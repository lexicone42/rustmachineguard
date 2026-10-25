//! Secret-shaped content in agent transcript stores, by NAME and LABEL only.
//!
//! The transcript stores ([`crate::scanners::transcripts`], and Vibe's in
//! [`crate::scanners::vibe`]) are the most sensitive files on a developer machine: every
//! secret ever pasted into a conversation, or printed by a tool the agent ran, is in them.
//! This module reads a bounded sample of their text for two things and keeps nothing else:
//!
//! - secret-named KEYS, by the `.env` scanner's classifier
//!   ([`is_secret_env_key_name`](crate::scanners::env_files::is_secret_env_key_name)), where
//!   they appear as `NAME=`, `NAME:`, `"NAME"`, `export NAME`, `-e NAME` or `--env NAME`;
//! - well-known token PREFIXES ([`TOKEN_SHAPES`]) followed by a plausible length and charset,
//!   recorded as the shape's closed LABEL and a count.
//!
//! Never a value, the matched text, the text around it, a line excerpt or a hash: the
//! result ([`TranscriptSecretShapes`]) holds names, labels, counts and booleans. Reads are
//! bounded ([`SAMPLE_FILES`] files, newest first by mtime with ties broken by path, the
//! first [`SAMPLE_BYTES`] of each), symlinks are never followed (the walk uses
//! `symlink_metadata` and the read opens with `O_NOFOLLOW`), and only regular files are
//! opened.

use crate::models::TranscriptSecretShapes;
use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};

/// Files sampled per store.
pub const SAMPLE_FILES: usize = 200;
/// Bytes read from the head of each sampled file.
pub const SAMPLE_BYTES: usize = 1024 * 1024;
/// Distinct secret-named keys kept per store.
pub const MAX_KEY_NAMES: usize = 50;

/// The transcript stores whose content is sampled: conversations, command histories,
/// sessions and session state, and Claude Code's shell snapshots and session environment.
/// Closed: `(framework, kind)` as the scanners record them.
pub fn in_scope(framework: &str, kind: &str) -> bool {
    use crate::scanners::transcripts::{SESSION_ENV, SHELL_SNAPSHOTS};
    match framework {
        "claude-code" => matches!(
            kind,
            "conversation transcripts" | "command history" | SHELL_SNAPSHOTS | SESSION_ENV
        ),
        "codex" | "mistral-vibe" => matches!(kind, "sessions" | "command history"),
        "gemini-cli" => kind == "session state",
        _ => false,
    }
}

/// Bytes a token body may contain.
#[derive(Clone, Copy)]
enum Charset {
    /// `[A-Za-z0-9]`
    Alnum,
    /// `[A-Za-z0-9_]`
    AlnumUnderscore,
    /// `[A-Za-z0-9_-]`
    Url,
    /// `[A-Za-z0-9-]`
    AlnumDash,
    /// `[A-Z0-9]`
    UpperDigit,
}

impl Charset {
    fn has(self, b: u8) -> bool {
        match self {
            Charset::Alnum => b.is_ascii_alphanumeric(),
            Charset::AlnumUnderscore => b.is_ascii_alphanumeric() || b == b'_',
            Charset::Url => b.is_ascii_alphanumeric() || b == b'_' || b == b'-',
            Charset::AlnumDash => b.is_ascii_alphanumeric() || b == b'-',
            Charset::UpperDigit => b.is_ascii_uppercase() || b.is_ascii_digit(),
        }
    }
}

/// What else a token body must show to be plausible rather than a placeholder
/// (`sk-xxxxxxxx...`) or an identifier that happens to share a prefix (`hf_hub_download`).
#[derive(Clone, Copy)]
enum Mix {
    /// At least one letter and one digit (random base62 of these lengths almost always has
    /// both).
    LetterAndDigit,
    /// Upper- and lower-case letters (Hugging Face tokens are letters only).
    MixedCase,
}

/// One token prefix: the literal, its closed label, and the body that must follow it to
/// the end of the word.
pub struct TokenShape {
    prefix: &'static [u8],
    pub label: &'static str,
    charset: Charset,
    min: usize,
    max: usize,
    mix: Mix,
}

const fn shape(
    prefix: &'static [u8],
    label: &'static str,
    charset: Charset,
    min: usize,
    max: usize,
    mix: Mix,
) -> TokenShape {
    TokenShape {
        prefix,
        label,
        charset,
        min,
        max,
        mix,
    }
}

/// The token prefixes, a closed table: the first entry whose prefix a word starts with
/// decides it (`sk-ant-` before `sk-`). Lengths are of the body after the prefix, which
/// must run to the end of the word. Sources, each page fetched 2026-10-25; where the
/// vendor documents a prefix but no length or charset, the length here is the issued
/// form and the index is GitHub's secret-scanning pattern list,
/// <https://docs.github.com/en/code-security/secret-scanning/introduction/supported-secret-scanning-patterns>:
///
/// - Anthropic `sk-ant-` (`sk-ant-api03-`, `sk-ant-admin01-`): the API-key object's
///   `partial_key_hint` example (`sk-ant-api03-...`),
///   <https://platform.claude.com/docs/en/api/beta/organization/api_keys/retrieve>, and
///   "Admin API key (starting with `sk-ant-admin...`)",
///   <https://platform.claude.com/docs/en/manage-claude/admin-api>. No length is
///   documented; the GitHub list has `anthropic_api_key` and `anthropic_admin_api_key`.
/// - OpenAI `sk-proj-`, `sk-svcacct-`, `sk-admin-` and legacy `sk-`: OpenAI's API
///   reference (<https://developers.openai.com/api/reference/overview>) documents bearer
///   authentication but no public key format, so the source is the GitHub list
///   (`openai_api_key`).
/// - GitHub `ghp_` `gho_` `ghu_` `ghs_` `ghr_` and `github_pat_`: the prefix list,
///   <https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/about-authentication-to-github>,
///   and the base62 body with a CRC32 checksum in its last six characters,
///   <https://github.blog/engineering/platform-security/behind-githubs-new-authentication-token-formats/>.
///   Neither page states a length: 36 is the issued body of the classic tokens (40 in
///   all). GitHub App installation tokens also come in a stateless `ghs_APPID_JWT` form:
///   "Starting April 27, 2026, GitHub began a staged rollout of a stateless format
///   (`ghs_APPID_JWT`) to all newly minted GitHub App installation tokens" (the first
///   page); "A stateless token is a `ghs_`-prefixed JWT. It is longer (~520 characters)
///   and contains two dots", while "a stateful token is a short opaque string with no
///   dots" (<https://github.blog/changelog/2026-05-15-github-app-installation-tokens-per-request-override-header/>);
///   the rollout completed per
///   <https://github.blog/changelog/2026-10-02-stateless-github-app-installation-tokens-rolled-out>
///   (pages fetched 2026-10-25). A JWT's dots end a word, so that form is matched by
///   [`stateless_ghs`] beside the 36-byte `ghs_` row, with the same label.
/// - AWS access key ids `AKIA` (access key) and `ASIA` (temporary STS key), 16 more
///   `[A-Z0-9]`: the prefixes,
///   <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html#identifiers-prefixes>.
///   AWS documents the id only as 16 to 128 `[\w]` characters
///   (<https://docs.aws.amazon.com/IAM/latest/APIReference/API_AccessKey.html>); 20 in all is
///   the issued form.
/// - Slack `xoxb-` (bot) and `xoxp-` (user): <https://docs.slack.dev/authentication/tokens>
///   (no length documented; the GitHub list has `slack_api_token`).
/// - GitLab `glpat-` (personal, impersonation, project and group access tokens):
///   <https://docs.gitlab.com/security/tokens/#token-prefixes> (no length documented; the
///   GitHub list has `gitlab_access_token`).
/// - Hugging Face `hf_`: shown only as `hf_...` in
///   <https://huggingface.co/docs/hub/security-tokens>, with no length or charset, so the
///   source for the shape is the GitHub list (`hf_user_access_token`).
/// - npm `npm_` (36 base62): the prefix and the base62 CRC32 checksum in the last six
///   characters, <https://github.blog/changelog/2021-09-23-npm-has-a-new-access-token-format/>.
///   The page gives no length for the new format (its "36 characters" is the old UUID
///   format); 36 is the issued body. The GitHub list has `npm_access_token`.
/// - Google API keys `AIza` (35 more `[A-Za-z0-9_-]`): the example key in
///   <https://docs.cloud.google.com/docs/authentication/api-keys> is `AIza` and 35 such
///   characters; no length is stated. The GitHub list has `google_api_key`.
/// - PEM private keys (`-----BEGIN ... PRIVATE KEY-----` followed by a base64 body): the
///   encapsulation boundaries and the `PRIVATE KEY` / `ENCRYPTED PRIVATE KEY` labels are
///   RFC 7468, <https://www.rfc-editor.org/rfc/rfc7468>; the `RSA`, `EC` and `OPENSSH`
///   labels this also matches are not in it (they are OpenSSL's and OpenSSH's own).
///   Matched by [`pem_private_key`].
pub const TOKEN_SHAPES: &[TokenShape] = &[
    shape(
        b"sk-ant-",
        "Anthropic API key",
        Charset::Url,
        32,
        256,
        Mix::LetterAndDigit,
    ),
    shape(
        b"sk-proj-",
        "OpenAI API key",
        Charset::Url,
        32,
        256,
        Mix::LetterAndDigit,
    ),
    shape(
        b"sk-svcacct-",
        "OpenAI API key",
        Charset::Url,
        32,
        256,
        Mix::LetterAndDigit,
    ),
    shape(
        b"sk-admin-",
        "OpenAI API key",
        Charset::Url,
        32,
        256,
        Mix::LetterAndDigit,
    ),
    shape(b"sk-", "OpenAI API key", Charset::Alnum, 32, 128, Mix::LetterAndDigit),
    shape(
        b"github_pat_",
        "GitHub token",
        Charset::AlnumUnderscore,
        50,
        255,
        Mix::LetterAndDigit,
    ),
    shape(b"ghp_", "GitHub token", Charset::Alnum, 36, 36, Mix::LetterAndDigit),
    shape(b"gho_", "GitHub token", Charset::Alnum, 36, 36, Mix::LetterAndDigit),
    shape(b"ghu_", "GitHub token", Charset::Alnum, 36, 36, Mix::LetterAndDigit),
    shape(b"ghs_", "GitHub token", Charset::Alnum, 36, 36, Mix::LetterAndDigit),
    shape(b"ghr_", "GitHub token", Charset::Alnum, 36, 36, Mix::LetterAndDigit),
    shape(
        b"AKIA",
        "AWS access key id",
        Charset::UpperDigit,
        16,
        16,
        Mix::LetterAndDigit,
    ),
    shape(
        b"ASIA",
        "AWS access key id",
        Charset::UpperDigit,
        16,
        16,
        Mix::LetterAndDigit,
    ),
    shape(
        b"xoxb-",
        "Slack token",
        Charset::AlnumDash,
        20,
        255,
        Mix::LetterAndDigit,
    ),
    shape(
        b"xoxp-",
        "Slack token",
        Charset::AlnumDash,
        20,
        255,
        Mix::LetterAndDigit,
    ),
    shape(b"glpat-", "GitLab token", Charset::Url, 20, 255, Mix::LetterAndDigit),
    shape(b"hf_", "Hugging Face token", Charset::Alnum, 30, 64, Mix::MixedCase),
    shape(b"npm_", "npm token", Charset::Alnum, 36, 36, Mix::LetterAndDigit),
    shape(b"AIza", "Google API key", Charset::Url, 35, 35, Mix::LetterAndDigit),
];

/// The label of a PEM private key ([`pem_private_key`]).
pub const PEM_LABEL: &str = "PEM private key";

/// Every label this module can emit, sorted and distinct: the closed value set of
/// `token_prefix_labels`.
pub const TOKEN_LABELS: &[&str] = &[
    "AWS access key id",
    "Anthropic API key",
    "GitHub token",
    "GitLab token",
    "Google API key",
    "Hugging Face token",
    "OpenAI API key",
    PEM_LABEL,
    "Slack token",
    "npm token",
];

/// What one file's sampled head shows: distinct secret-named keys, token labels, and the
/// number of token-shaped strings. Names and labels only.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct FileShapes {
    pub names: BTreeSet<String>,
    pub labels: BTreeSet<&'static str>,
    pub tokens: usize,
}

impl FileShapes {
    pub fn any(&self) -> bool {
        !self.names.is_empty() || !self.labels.is_empty()
    }
}

/// The bytes of a word, `[A-Za-z0-9_-]`, as a table (the scan's inner loop).
const WORD: [bool; 256] = {
    let mut t = [false; 256];
    let mut b = 0;
    while b < 256 {
        let c = b as u8;
        t[b] = c.is_ascii_alphanumeric() || c == b'_' || c == b'-';
        b += 1;
    }
    t
};

/// A byte of a word: `[A-Za-z0-9_-]`.
fn is_word(b: u8) -> bool {
    WORD[b as usize]
}

/// The label of the token shape the word `w` is, if any: the first [`TOKEN_SHAPES`] entry
/// whose prefix it starts with decides; the body must be entirely in the charset, of a
/// length in range, and mixed as the shape requires.
pub fn token_label(w: &[u8]) -> Option<&'static str> {
    // The shortest shape is 20 bytes (`AKIA` + 16) and every prefix starts with one of
    // these bytes: most words are rejected here, before the table.
    if w.len() < 20 || !matches!(w[0], b's' | b'g' | b'A' | b'x' | b'h' | b'n') {
        return None;
    }
    let s = TOKEN_SHAPES.iter().find(|s| w.starts_with(s.prefix))?;
    let body = &w[s.prefix.len()..];
    if body.len() < s.min || body.len() > s.max || !body.iter().all(|b| s.charset.has(*b)) {
        return None;
    }
    let mixed = match s.mix {
        Mix::LetterAndDigit => body.iter().any(u8::is_ascii_alphabetic) && body.iter().any(u8::is_ascii_digit),
        Mix::MixedCase => body.iter().any(u8::is_ascii_uppercase) && body.iter().any(u8::is_ascii_lowercase),
    };
    mixed.then_some(s.label)
}

/// The label of both GitHub installation-token forms.
const GITHUB_TOKEN: &str = "GitHub token";

/// A stateless GitHub App installation token at the word `buf[s..e]`: `ghs_`, the numeric
/// app id, `_`, then a JWT, three base64url segments joined by dots (sources at
/// [`TOKEN_SHAPES`]). The word (which ends at the first dot) must be `ghs_<digits>_eyJ...`
/// (a JWT header is base64url JSON, which starts `eyJ`), followed by `.` and a payload of
/// at least 16 bytes, `.` and a signature of at least 16 bytes, and nothing more of the
/// token after it (no further dot-joined segment).
fn stateless_ghs(buf: &[u8], s: usize, e: usize) -> bool {
    let w = &buf[s..e];
    let Some(rest) = w.strip_prefix(b"ghs_") else {
        return false;
    };
    let digits = rest.iter().take_while(|b| b.is_ascii_digit()).count();
    if !(1..=20).contains(&digits) || rest.get(digits) != Some(&b'_') {
        return false;
    }
    let header = &rest[digits + 1..];
    if header.len() < 16 || !header.starts_with(b"eyJ") {
        return false;
    }
    let mut p = e;
    for _ in 0..2 {
        if buf.get(p) != Some(&b'.') {
            return false;
        }
        let seg = buf[p + 1..].iter().take_while(|b| is_word(**b)).count();
        if seg < 16 {
            return false;
        }
        p += 1 + seg;
    }
    !(buf.get(p) == Some(&b'.') && buf.get(p + 1).is_some_and(|b| is_word(*b)))
}

/// A PEM private-key block starting at the word `-----BEGIN` that ends at `e`: within 48
/// bytes `PRIVATE KEY-----`, then a line break (raw, or the `\n` escape of a JSON string),
/// then at least 40 base64 bytes. A header alone (code that checks for one) is not a key.
fn pem_private_key(buf: &[u8], e: usize) -> bool {
    const TAIL: &[u8] = b"PRIVATE KEY-----";
    let window = &buf[e..buf.len().min(e + 48 + TAIL.len())];
    let Some(at) = window.windows(TAIL.len()).position(|w| w == TAIL) else {
        return false;
    };
    let mut p = e + at + TAIL.len();
    for brk in [&b"\r\n"[..], b"\n", b"\\r\\n", b"\\n"] {
        if buf[p..].starts_with(brk) {
            p += brk.len();
            break;
        }
    }
    buf[p..]
        .iter()
        .take(40)
        .filter(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
        .count()
        == 40
}

/// Shown in place of a NAME that could itself be a value ([`shown_as_name`]).
pub const KEY_SHAPED: &str = "<key-shaped name>";

/// Whether a secret-named NAME found in key position is shown as itself. Not when the
/// command redactor would hide it (it is shaped like a key), nor when it is one long word
/// with no `_`: tool output prints values in key position too (a script's
/// `GHCANARYTOKEN: 0` line), and an upper-case value that happens to hold a hint
/// (`MYSECRETPASSWORD`) has no `_` structure, while a real variable name of one word is
/// short (`APIKEY`, `PASSWORD`, `JWT`). Such a NAME still counts, as [`KEY_SHAPED`].
fn shown_as_name(name: &str) -> bool {
    crate::scanners::redact_command_text(name) == name && (name.contains('_') || name.len() <= 10)
}

/// The `.env` scanner's secret-NAME rule, the same three tests it applies to a key: a
/// secret-named key (`AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN`, `*_PASSWORD`), a
/// connection-string key (`DATABASE_URL`, `REDIS_URL`, `*_DSN`), or a webhook key
/// (`SLACK_WEBHOOK_URL`). `KEY` counts only as a word, as in the command redactor
/// ([`key_word_hint`](crate::scanners::env_files::key_word_hint)): `KEYBOARD_LAYOUT`,
/// `KEYWORD`, `HOTKEY` and `MONKEY` are not secret names here.
pub fn is_secret_name(name: &str) -> bool {
    use crate::scanners::env_files::{is_connection_string_key_name, is_secret_env_key_name, is_webhook_key_name};
    is_secret_env_key_name(name) || is_connection_string_key_name(name) || is_webhook_key_name(name)
}

/// An environment-variable-shaped NAME: `[A-Z_][A-Z0-9_]{2,63}` with at least one letter.
/// Upper case only: transcripts are JSON whose own field names (`input_tokens`,
/// `cache_read_input_tokens`, `accessToken`) are lower or camel case and would otherwise
/// all read as secret names.
fn env_shaped(w: &[u8]) -> bool {
    (3..=64).contains(&w.len())
        && (w[0].is_ascii_uppercase() || w[0] == b'_')
        && w.iter()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || *b == b'_')
        && w.iter().any(u8::is_ascii_uppercase)
}

/// Whether the word `buf[s..e]` sits where a KEY NAME does: followed by `=` (not `==`) or
/// `:` (not `::`), a quoted key (`"NAME":`, `\"NAME\":`, `["NAME"]`), or after `export `,
/// `-e `, `--env ` or `--env=`, and never right of an `=` or `:`. A quoted string elsewhere
/// is a value (`"token": "SOMETOKEN"`), and is never taken for a name; nor is a
/// `const NAME:` / `static NAME:` declaration in quoted source code.
fn key_context(buf: &[u8], s: usize, e: usize) -> bool {
    let at = |i: usize| buf.get(i).copied();
    let ends_with_word = |end: usize, words: &[&[u8]]| {
        words.iter().any(|f| {
            end >= f.len() && &buf[end - f.len()..end] == *f && (end == f.len() || !is_word(buf[end - f.len() - 1]))
        })
    };
    let mut j = s;
    while j > 0 && matches!(buf[j - 1], b' ' | b'\t') {
        j -= 1;
    }
    if j < s && ends_with_word(j, &[b"const", b"static"]) {
        return false;
    }
    let ends_with_flag = |end: usize| ends_with_word(end, &[b"export", b"-e", b"--env"]);
    // Right of an `=` or `:` is a value (`DB_PASSWORD=MYSECRETPASS:x`, `user:SECRETPASS`),
    // never a name, except `--env=NAME`.
    if j > 0 && matches!(buf[j - 1], b'=' | b':') {
        return j == s && buf[s - 1] == b'=' && ends_with_flag(s - 1);
    }
    if (at(e) == Some(b'=') && at(e + 1) != Some(b'=')) || (at(e) == Some(b':') && at(e + 1) != Some(b':')) {
        return true;
    }
    if s > 0 && buf[s - 1] == b'"' {
        // The closing quote, raw or escaped inside a JSON string.
        let close = match (at(e), at(e + 1)) {
            (Some(b'"'), _) => Some(e + 1),
            (Some(b'\\'), Some(b'"')) => Some(e + 2),
            _ => None,
        };
        let Some(mut c) = close else { return false };
        let open_bracket = s >= 2 && buf[s - 2] == b'[' || s >= 3 && buf[s - 3] == b'[' && buf[s - 2] == b'\\';
        if open_bracket && at(c) == Some(b']') {
            return true;
        }
        while matches!(at(c), Some(b' ' | b'\t')) {
            c += 1;
        }
        return at(c) == Some(b':');
    }
    j < s && ends_with_flag(j)
}

/// Whether a word starts at `p` although the byte before it is a word byte: after the
/// letter of a JSON escape (`\nGITHUB_TOKEN` in a JSONL line is a line break then the
/// name) or after an ANSI colour code (`\u001b[1mGITHUB_TOKEN`, `\u001b[1;32mX`).
fn escaped_start(buf: &[u8], p: usize) -> bool {
    if p >= 2 && buf[p - 2] == b'\\' && matches!(buf[p - 1], b'n' | b't' | b'r') {
        return true;
    }
    if p >= 2 && buf[p - 1] == b'm' && buf[p - 2].is_ascii_digit() {
        let digits = buf[..p - 1].iter().rev().take_while(|b| b.is_ascii_digit()).count();
        let before = p - 1 - digits;
        return before > 0 && matches!(buf[before - 1], b'[' | b';');
    }
    false
}

/// The secret-named keys and token shapes in `buf` (one sampled file head). A word is a
/// maximal run of `[A-Za-z0-9_-]`, or the rest of one after a JSON escape letter or an ANSI
/// colour code ([`escaped_start`]); a token must be a whole word ([`token_label`]) and a
/// key NAME a whole word in key position ([`key_context`]) that the `.env` classifier calls
/// secret. A NAME that could itself be a value ([`shown_as_name`]) is recorded as
/// [`KEY_SHAPED`]. Nothing else of `buf` is kept.
pub fn shapes_in(buf: &[u8]) -> FileShapes {
    let mut out = FileShapes::default();
    let mut memo: HashMap<&[u8], bool> = HashMap::new();
    for_each_candidate_word(buf, |s| {
        let mut i = s;
        while i < buf.len() && is_word(buf[i]) {
            i += 1;
        }
        let w = &buf[s..i];
        if w == b"-----BEGIN" {
            if pem_private_key(buf, i) {
                out.labels.insert(PEM_LABEL);
                out.tokens += 1;
            }
            return;
        }
        if let Some(label) = token_label(w).or_else(|| stateless_ghs(buf, s, i).then_some(GITHUB_TOKEN)) {
            out.labels.insert(label);
            out.tokens += 1;
            return;
        }
        if !env_shaped(w) || !key_context(buf, s, i) {
            return;
        }
        let secret = *memo
            .entry(w)
            .or_insert_with(|| is_secret_name(std::str::from_utf8(w).unwrap_or_default()));
        if secret {
            let name = String::from_utf8_lossy(w).into_owned();
            let shown = if shown_as_name(&name) {
                name
            } else {
                KEY_SHAPED.to_string()
            };
            out.names.insert(shown);
        }
    });
    out
}

/// The byte before a word start that is a word byte, by the byte before it: an escape
/// letter after `\\` ([`ESC1`] `n` `t` `r`, [`ESC2`] the backslash) or a colour code's
/// `m` after a digit (`ESC1` `m`, `ESC2` digits). A loose pre-filter: [`escaped_start`]
/// decides.
const ESC1: [bool; 256] = {
    let mut t = [false; 256];
    t[b'n' as usize] = true;
    t[b't' as usize] = true;
    t[b'r' as usize] = true;
    t[b'm' as usize] = true;
    t
};
const ESC2: [bool; 256] = {
    let mut t = [false; 256];
    t[b'\\' as usize] = true;
    let mut d = b'0';
    while d <= b'9' {
        t[d as usize] = true;
        d += 1;
    }
    t
};

/// Bytes a word that [`shapes_in`] may keep can start with: an upper-case letter or `_` (a
/// NAME, `AKIA`, `AIza`), `-` (`-----BEGIN`), and the first letters of the lower-case
/// prefixes.
const START: [bool; 256] = {
    let mut t = [false; 256];
    let mut b = 0;
    while b < 256 {
        let c = b as u8;
        t[b] = c.is_ascii_uppercase() || matches!(c, b'_' | b'-' | b's' | b'g' | b'x' | b'h' | b'n');
        b += 1;
    }
    t
};

/// Whether the word at `s` can be a token or a NAME, from its first two bytes: every word
/// [`shapes_in`] would keep passes, and most text is rejected here without finding the
/// word's end.
fn plausible_start(buf: &[u8], s: usize) -> bool {
    if s > 0 && is_word(buf[s - 1]) && !escaped_start(buf, s) {
        return false;
    }
    let b0 = buf[s];
    let b1 = buf.get(s + 1).copied().unwrap_or(0);
    match b0 {
        b'A'..=b'Z' | b'_' => b1.is_ascii_uppercase() || b1.is_ascii_digit() || b1 == b'_',
        b'-' => buf[s..].starts_with(b"-----BEGIN"),
        b's' => b1 == b'k',
        b'g' => matches!(b1, b'h' | b'l' | b'i'),
        b'x' => b1 == b'o',
        b'h' => b1 == b'f',
        b'n' => b1 == b'p',
        _ => false,
    }
}

/// Call `f` with the start of every word of `buf` that [`plausible_start`] accepts. Starts
/// are found 64 bytes at a time as a bit mask (a [`START`] byte after a non-word byte, or
/// after an escape letter or a colour code's `m`, which [`plausible_start`] then checks),
/// without data-dependent branches: walking every word one by one cost about 3 ns a byte
/// on transcript text.
fn for_each_candidate_word(buf: &[u8], mut f: impl FnMut(usize)) {
    let (mut prev2, mut prev) = (b' ', b' ');
    for (block, chunk) in buf.chunks(64).enumerate() {
        let mut mask = 0u64;
        for (k, &b) in chunk.iter().enumerate() {
            // `&` and `|`, not `&&`: no branch per byte.
            let boundary = !WORD[prev as usize] | (ESC2[prev2 as usize] & ESC1[prev as usize]);
            mask |= u64::from(START[b as usize] & boundary) << k;
            (prev2, prev) = (prev, b);
        }
        while mask != 0 {
            let s = block * 64 + mask.trailing_zeros() as usize;
            mask &= mask - 1;
            if plausible_start(buf, s) {
                f(s);
            }
        }
    }
}

/// One regular file of a store, as a walk found it (lstat only): sampled newest first by
/// `mtime`, ties by `path`.
pub struct SampleFile {
    pub mtime: std::time::SystemTime,
    pub path: PathBuf,
    pub len: u64,
    /// Other users can read it: o+r, with o+x on every directory from the store down.
    pub others: bool,
}

#[cfg(unix)]
fn other_bits(meta: &std::fs::Metadata) -> (bool, bool) {
    use std::os::unix::fs::PermissionsExt;
    let m = meta.permissions().mode();
    (m & 0o004 != 0, m & 0o001 != 0)
}
#[cfg(not(unix))]
fn other_bits(_meta: &std::fs::Metadata) -> (bool, bool) {
    (false, false)
}

/// The regular files under `dir` (symlinks are neither followed nor listed), at most
/// `cap`; true when the cap stopped the walk.
fn walk(dir: &Path, root_traversable: bool, cap: usize) -> (Vec<SampleFile>, bool) {
    let mut out = Vec::new();
    let mut stack = vec![(dir.to_path_buf(), root_traversable)];
    while let Some((d, reachable)) = stack.pop() {
        let Ok(entries) = crate::scanners::probe_read_dir(&d) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(meta) = std::fs::symlink_metadata(entry.path()) else {
                continue;
            };
            let (o_read, o_exec) = other_bits(&meta);
            if meta.file_type().is_dir() {
                stack.push((entry.path(), reachable && o_exec));
            } else if meta.file_type().is_file() {
                if out.len() >= cap {
                    return (out, true);
                }
                out.push(SampleFile {
                    mtime: meta.modified().unwrap_or(std::time::UNIX_EPOCH),
                    path: entry.path(),
                    len: meta.len(),
                    others: reachable && o_read,
                });
            }
        }
    }
    (out, false)
}

/// Sample one store (a directory or a single file such as `history.jsonl`) with the
/// default caps. `home` is the scan pass's home (it groups the hygiene advisory).
pub fn sample_store(store: &Path, home: &Path) -> TranscriptSecretShapes {
    let cap = crate::scanners::telemetry::walk_cap(
        crate::scanners::transcripts::BASE_WALK_FILES,
        crate::scanners::telemetry::walk_budget(),
    );
    sample_store_with(store, home, SAMPLE_FILES, SAMPLE_BYTES, cap)
}

/// [`sample_store`] with explicit caps: at most `files` files of the store (newest first
/// by mtime, ties by path), the first `bytes` of each, from a walk of at most `walk_cap`
/// files. The files are read on the scan's helper threads.
pub fn sample_store_with(
    store: &Path,
    home: &Path,
    files: usize,
    bytes: usize,
    walk_cap: usize,
) -> TranscriptSecretShapes {
    let shapes = TranscriptSecretShapes {
        scan_home: Some(home.display().to_string()),
        ..Default::default()
    };
    let Ok(meta) = std::fs::symlink_metadata(store) else {
        return shapes;
    };
    let (cands, truncated) = if meta.is_dir() {
        walk(store, other_bits(&meta).1, walk_cap)
    } else if meta.is_file() {
        let c = SampleFile {
            mtime: std::time::UNIX_EPOCH,
            path: store.to_path_buf(),
            len: meta.len(),
            others: other_bits(&meta).0,
        };
        (vec![c], false)
    } else {
        return shapes; // a symlinked store is not followed
    };
    sample_files(cands, truncated, home, files, bytes)
}

/// Sample `cands`, the regular files of one store (`walk_truncated`: the walk that listed
/// them stopped at its cap): at most `files` of them, newest first by mtime with ties by
/// path, the first `bytes` of each, read without following a symlink on the scan's helper
/// threads.
pub fn sample_files(
    mut cands: Vec<SampleFile>,
    walk_truncated: bool,
    home: &Path,
    files: usize,
    bytes: usize,
) -> TranscriptSecretShapes {
    let mut shapes = TranscriptSecretShapes {
        scan_home: Some(home.display().to_string()),
        ..Default::default()
    };
    let mut truncated = walk_truncated;
    cands.sort_by(|a, b| b.mtime.cmp(&a.mtime).then_with(|| a.path.cmp(&b.path)));
    if cands.len() > files {
        truncated = true;
        cands.truncate(files);
    }
    let jobs = crate::scanners::telemetry::helper_jobs();
    let results = crate::scanners::telemetry::par_map(cands, jobs, |c: SampleFile| {
        let head = crate::scanners::read_head_bytes_nofollow(&c.path, bytes)?;
        Some((shapes_in(&head), c.others, c.len > bytes as u64))
    });
    let mut names = BTreeSet::new();
    let mut labels = BTreeSet::new();
    for (found, others, cut) in results.into_iter().flatten() {
        shapes.files_sampled += 1;
        truncated |= cut;
        if found.any() {
            shapes.files_with_secret_shapes += 1;
            if others {
                shapes.other_readable_files_with_secret_shapes += 1;
            }
        }
        shapes.token_shaped_strings += found.tokens;
        names.extend(found.names);
        labels.extend(found.labels);
    }
    shapes.secret_key_names_truncated = names.len() > MAX_KEY_NAMES;
    shapes.secret_key_names = names.into_iter().take(MAX_KEY_NAMES).collect();
    shapes.token_prefix_labels = labels.into_iter().map(str::to_string).collect();
    shapes.sampling_truncated = truncated;
    shapes
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(text: &str) -> Vec<String> {
        shapes_in(text.as_bytes()).names.into_iter().collect()
    }
    fn labels(text: &str) -> Vec<&'static str> {
        shapes_in(text.as_bytes()).labels.into_iter().collect()
    }

    #[test]
    fn key_names_in_key_position_only() {
        assert_eq!(names("AWS_SECRET_ACCESS_KEY=x"), ["AWS_SECRET_ACCESS_KEY"]);
        assert_eq!(names("GITHUB_TOKEN: x"), ["GITHUB_TOKEN"]);
        assert_eq!(names(r#"{"OPENAI_API_KEY": 1}"#), ["OPENAI_API_KEY"]);
        assert_eq!(names(r#"\"DB_PASSWORD\": 1"#), ["DB_PASSWORD"]);
        assert_eq!(names(r#"os.environ["API_TOKEN"]"#), ["API_TOKEN"]);
        assert_eq!(names(r#"env[\"API_TOKEN\"]"#), ["API_TOKEN"]);
        // A quoted VALUE is never a name, whatever its shape.
        assert!(names(r#"{"token": "HUNTERSECRETTOKEN", "x": \"MYPASSWORD\"}"#).is_empty());
        assert!(names(r#"["AWSCANARYSECRET", "X"]"#).is_empty());
        assert!(names("const SECRET_KEY_HINTS: &[&str]").is_empty());
        // A value printed in key position by a tool is counted, never shown.
        assert_eq!(names("GHCANARYTOKEN: 0\nAWSCANARYSECRET: 0"), [KEY_SHAPED]);
        assert_eq!(names("PASSWORD: x APIKEY=y"), ["APIKEY", "PASSWORD"]);
        assert_eq!(names("DB_PASSWORD=MYSECRETPASS:x"), ["DB_PASSWORD"], "value position");
        assert_eq!(names("postgres://u:SECRETPASS@h PASSWORD=SECRETPASS="), ["PASSWORD"]);
        assert_eq!(names("PASSWORD: SECRETPASS: x"), ["PASSWORD"]);
        assert_eq!(names("export  STRIPE_SECRET"), ["STRIPE_SECRET"]);
        assert_eq!(names("docker run -e NPM_TOKEN img"), ["NPM_TOKEN"]);
        assert_eq!(names("x --env=SLACK_TOKEN y"), ["SLACK_TOKEN"]);
        assert_eq!(names("x --env SLACK_TOKEN y"), ["SLACK_TOKEN"]);
        assert_eq!(
            names("DATABASE_URL=x SLACK_WEBHOOK_URL=y"),
            ["DATABASE_URL", "SLACK_WEBHOOK_URL"]
        );
        assert_eq!(names(r"\nGITHUB_TOKEN=x"), ["GITHUB_TOKEN"], "after a JSON escape");
        assert_eq!(names("\x1b[1mGITHUB_TOKEN=x"), ["GITHUB_TOKEN"], "after an ANSI code");
        // Not in key position, not env-shaped, or not a secret name.
        assert!(names("set GITHUB_TOKEN in CI").is_empty());
        assert!(names("x --e GITHUB_TOKEN").is_empty());
        assert!(names(r#"{"input_tokens": 3, "accessToken": "x"}"#).is_empty());
        assert!(names("AWS_ACCESS_KEY_ID=x PATH=y A==b").is_empty());
        assert!(names("crate::SECRET_KEY::x").is_empty());
        assert!(names("GITHUB_TOKEN==x").is_empty());
    }

    #[test]
    fn token_prefixes_need_length_charset_and_mix() {
        let gh = format!("ghp_{}", "aB3".repeat(12));
        assert_eq!(labels(&format!("token {gh} end")), ["GitHub token"]);
        assert!(labels(&format!("{gh}x")).is_empty(), "37 chars is not a ghp_ token");
        assert!(labels(&format!("ghp_{}", "a".repeat(36))).is_empty(), "no digit");
        assert_eq!(labels("AKIA0123456789ABCDEF"), ["AWS access key id"]);
        assert!(labels("AKIA0123456789ABCDEFG").is_empty());
        assert!(labels("xAKIA0123456789ABCDEF").is_empty(), "inside a word");
        let ant = format!("sk-ant-api03-{}", "Zx9_".repeat(10));
        assert_eq!(labels(&format!("\"{ant}\"")), ["Anthropic API key"]);
        assert_eq!(labels(&format!("sk-{}", "Q7".repeat(24))), ["OpenAI API key"]);
        assert_eq!(labels(&format!("sk-proj-{}", "Q7-".repeat(12))), ["OpenAI API key"]);
        assert!(labels("sk-learn sk-CODEXAUTHCANARY").is_empty());
        assert_eq!(labels(&format!("hf_{}", "AbCd".repeat(9))), ["Hugging Face token"]);
        // Built from parts so the source never holds a literal that matches a vendor's
        // token pattern (GitHub push protection scans blobs for them).
        let hf_lower = format!("hf_hub_download hf_{}", "abcdefghijklmnopqrstuvwxyzabcdefgh");
        assert!(labels(&hf_lower).is_empty(), "no digit mix");
        assert_eq!(labels(&format!("npm_{}", "a1B".repeat(12))), ["npm token"]);
        assert_eq!(labels(&format!("AIza{}", "Sy0-_".repeat(7))), ["Google API key"]);
        assert_eq!(labels(&format!("xoxb-1234-{}", "aZ".repeat(10))), ["Slack token"]);
        assert_eq!(labels(&format!("glpat-{}", "x1".repeat(10))), ["GitLab token"]);
        assert_eq!(labels(&format!("github_pat_{}", "11AB_c".repeat(14))), ["GitHub token"]);
        let pem = format!("-----BEGIN OPENSSH PRIVATE KEY-----\\n{}", "b3Bl".repeat(12));
        assert_eq!(labels(&pem), [PEM_LABEL]);
        assert!(labels("starts_with(\"-----BEGIN OPENSSH PRIVATE KEY-----\")").is_empty());
        assert_eq!(shapes_in(format!("{gh} {gh}").as_bytes()).tokens, 2);
    }

    #[test]
    fn labels_are_the_closed_table() {
        let mut from_table: Vec<&str> = TOKEN_SHAPES.iter().map(|s| s.label).collect();
        from_table.push(PEM_LABEL);
        from_table.sort_unstable();
        from_table.dedup();
        assert_eq!(from_table, TOKEN_LABELS);
    }

    #[test]
    fn scope_is_closed() {
        assert!(in_scope("claude-code", "conversation transcripts"));
        assert!(in_scope("claude-code", "shell snapshots"));
        assert!(in_scope("mistral-vibe", "sessions"));
        assert!(in_scope("gemini-cli", "session state"));
        assert!(!in_scope("claude-code", "todo state"));
        assert!(!in_scope("claude-code", "account state file"));
        assert!(!in_scope("mistral-vibe", "plan files"));
    }
}
