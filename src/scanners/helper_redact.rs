//! Shape-only redaction for credential-helper commands (apiKeyHelper, awsAuthRefresh,
//! awsCredentialExport, gcpAuthRefresh, otelHeadersHelper).
//!
//! A helper's job is to PRINT a credential, so its most naive form carries the
//! credential as a literal, and the literal can sit anywhere: `echo KEY`,
//! `sh -c 'echo KEY'`, `(echo KEY)`, `sudo echo KEY`, `python3 -c 'print("KEY")'`,
//! `awk 'BEGIN{print "KEY"}'`. Matching secret shapes cannot be complete here (a short
//! password has no shape), so this records only the command's SHAPE and drops every
//! argument it cannot prove harmless.
//!
//! Kept: each simple command's program word (after `NAME=value` prefixes, `{`/`(`,
//! and wrappers such as exec, sudo, env, command, builtin, time, nohup, timeout), flags
//! (`--long`, short clusters of up to two letters; an attached value is redacted),
//! `$VAR`/`${VAR}` references, file paths (`/x`, `./x`, `~/x`, `$HOME/x`, `@file`),
//! a URL's scheme and host (userinfo, path and query dropped), shell operators and
//! redirections, `printenv NAME`, and a fixed vocabulary of subcommand words
//! (`aws sso login`, `op read`, `gcloud auth print-access-token`). The string given to
//! `sh|bash|zsh ... -c` and the arguments of `eval` are redacted as nested commands.
//! Everything else, including every argument of echo/printf/print, interpreter code
//! passed to `-c`/`-e`, heredoc bodies and here-strings, becomes `<redacted>`.

use super::{looks_high_entropy, split_url_authority};

/// Nested `sh -c` / `eval` levels expanded before the rest is redacted whole.
const MAX_DEPTH: usize = 4;

/// Subcommand and argument words of common secret-store and cloud CLIs. A credential is
/// never one of these words, so they are kept and the command stays reviewable.
const VOCAB: &[&str] = &[
    "access-token", "account", "api-key", "application-default", "assume-role", "auth",
    "configure", "credential", "credentials", "creds", "export-credentials", "fetch",
    "find-generic-password", "find-internet-password", "get", "get-caller-identity",
    "get-parameter", "get-secret-value", "get-session-token", "inject", "item", "key",
    "keys", "kv", "list", "login", "lookup", "print", "print-access-token",
    "print-identity-token", "read", "refresh", "run", "secret", "secrets", "secretsmanager",
    "show", "signin", "ssm", "sso", "sts", "token", "view", "whoami",
];

/// Words that start a simple command without being its program, with the flags of
/// theirs that take a value (that value is redacted and is not the program).
const WRAPPERS: &[(&str, &[&str])] = &[
    ("exec", &["-a"]),
    ("command", &[]),
    ("builtin", &[]),
    ("sudo", &["-u", "-g", "-p", "-C", "-D", "-h", "-r", "-t", "-U", "-T", "-R"]),
    ("doas", &["-u", "-C"]),
    ("env", &["-u", "-C", "-S", "--unset", "--chdir", "--split-string"]),
    ("nohup", &[]),
    ("nice", &["-n"]),
    ("ionice", &["-c", "-n", "-p"]),
    ("time", &["-f", "-o"]),
    ("timeout", &["-s", "-k"]),
    ("stdbuf", &["-i", "-o", "-e"]),
    ("setsid", &[]),
    ("xargs", &["-I", "-n", "-P", "-d", "-E", "-L", "-s", "-a"]),
    ("export", &[]),
    ("readonly", &[]),
    ("local", &[]),
    ("declare", &[]),
];

const RESERVED: &[&str] = &[
    "{", "}", "!", "if", "then", "else", "elif", "fi", "do", "done", "while", "until", "case",
    "esac", "in", "for", "function", "[[", "]]",
];

const SHELLS: &[&str] = &["sh", "bash", "zsh", "dash", "ksh", "mksh", "ash", "fish", "busybox"];
const ECHOES: &[&str] = &["echo", "printf", "print", "yes"];

/// Shell operators, longest first.
const OPERATORS: &[&str] = &[
    "<<<", "<<-", "&>>", "<<", "<>", "<&", ">>", ">&", ">|", "&>", "&&", "||", "|&", ";;", "<", ">",
    "&", "|", ";", "(", ")",
];

#[derive(Debug)]
enum Tok {
    Space,
    Newline,
    Op(String),
    Word(Word),
    /// A heredoc body (always redacted) and the delimiter line that closed it, if any.
    Heredoc(Option<String>),
    Comment,
}

#[derive(Debug, Default)]
struct Word {
    raw: String,
    /// The word with quoting removed (expansions left as text).
    value: String,
    /// The quote character, when the whole word is a single quoted string.
    whole_quote: Option<char>,
}

fn lex(cmd: &str) -> Vec<Tok> {
    let chars: Vec<char> = cmd.chars().collect();
    let n = chars.len();
    let mut out = Vec::new();
    let mut i = 0;
    let mut heredocs: Vec<String> = Vec::new();
    let mut want_delim = false;
    while i < n {
        let c = chars[i];
        if c == '\n' {
            out.push(Tok::Newline);
            i += 1;
            // Heredoc bodies start on the next line: skip to each delimiter line.
            for d in heredocs.drain(..) {
                let mut closed = None;
                while i < n {
                    let end = (i..n).find(|&j| chars[j] == '\n').unwrap_or(n);
                    let line: String = chars[i..end].iter().collect();
                    i = (end + 1).min(n);
                    if line.trim() == d {
                        closed = Some(line.trim().to_string());
                        break;
                    }
                }
                out.push(Tok::Heredoc(closed));
            }
            continue;
        }
        if c.is_whitespace() {
            while i < n && chars[i].is_whitespace() && chars[i] != '\n' {
                i += 1;
            }
            out.push(Tok::Space);
            continue;
        }
        if c == '#' {
            while i < n && chars[i] != '\n' {
                i += 1;
            }
            out.push(Tok::Comment);
            continue;
        }
        // `2>`, `2>&1`: an fd number glued to a redirection belongs to the operator.
        let digits = chars[i..].iter().take_while(|d| d.is_ascii_digit()).count();
        let op_at = |k: usize| OPERATORS.iter().find(|op| starts_with(&chars[k..], op));
        if let Some(op) = op_at(i + digits).filter(|op| digits == 0 || op.starts_with(['<', '>'])) {
            let text: String = chars[i..i + digits].iter().collect::<String>() + op;
            i += digits + op.chars().count();
            want_delim = matches!(*op, "<<" | "<<-");
            out.push(Tok::Op(text));
            continue;
        }
        let (w, next) = lex_word(&chars, i);
        i = next;
        if want_delim {
            heredocs.push(w.value.clone());
            want_delim = false;
        }
        out.push(Tok::Word(w));
    }
    if !heredocs.is_empty() {
        // A heredoc opened on the last line has no body in this string.
        out.push(Tok::Heredoc(None));
    }
    out
}

fn starts_with(chars: &[char], s: &str) -> bool {
    s.chars().enumerate().all(|(k, c)| chars.get(k) == Some(&c))
}

/// One shell word starting at `i`: quotes, escapes, `$(...)` and backticks included.
fn lex_word(chars: &[char], mut i: usize) -> (Word, usize) {
    let n = chars.len();
    let start = i;
    let mut w = Word::default();
    let first_quote = chars.get(i).copied().filter(|c| *c == '\'' || *c == '"');
    let mut first_quote_end = None;
    while i < n {
        let c = chars[i];
        if c.is_whitespace() || OPERATORS.iter().any(|op| starts_with(&chars[i..], op)) {
            break;
        }
        match c {
            '\\' => {
                if let Some(&nx) = chars.get(i + 1) {
                    w.value.push(nx);
                }
                i += 2;
            }
            '\'' => {
                let end = (i + 1..n).find(|&j| chars[j] == '\'').unwrap_or(n);
                w.value.extend(&chars[i + 1..end]);
                if i == start {
                    first_quote_end = Some(end + 1);
                }
                i = end + 1;
            }
            '"' => {
                let mut j = i + 1;
                while j < n && chars[j] != '"' {
                    if chars[j] == '\\' && j + 1 < n {
                        w.value.push(chars[j + 1]);
                        j += 2;
                        continue;
                    }
                    w.value.push(chars[j]);
                    j += 1;
                }
                if i == start {
                    first_quote_end = Some(j + 1);
                }
                i = j + 1;
            }
            '$' if chars.get(i + 1) == Some(&'(') => {
                let mut depth = 0;
                let mut j = i + 1;
                while j < n {
                    match chars[j] {
                        '(' => depth += 1,
                        ')' => {
                            depth -= 1;
                            if depth == 0 {
                                break;
                            }
                        }
                        _ => {}
                    }
                    j += 1;
                }
                let end = (j + 1).min(n);
                w.value.extend(&chars[i..end]);
                i = end;
            }
            '`' => {
                let end = (i + 1..n).find(|&j| chars[j] == '`').map_or(n, |j| j + 1);
                w.value.extend(&chars[i..end]);
                i = end;
            }
            _ => {
                w.value.push(c);
                i += 1;
            }
        }
    }
    let i = i.min(n);
    w.raw = chars[start..i].iter().collect();
    if first_quote.is_some() && first_quote_end.is_some_and(|e| e >= i) {
        w.whole_quote = first_quote;
    }
    (w, i.max(start + 1))
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Kind {
    Shell,
    Eval,
    Echo,
    Printenv,
    Other,
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum State {
    Start,
    /// After a wrapper: its flags, then the program. `true` = the next word is a flag value.
    Wrapper(&'static [&'static str], bool),
    Args(Kind),
    /// The next word is a nested command (`sh -c STRING`).
    Nested(Kind),
    /// The next word is a value (redacted), then back to Args.
    Value(Kind),
    /// The next word is a redirection target; then back to the saved state.
    Redir,
    /// The next word is a heredoc delimiter.
    Delim,
}

pub fn redact_helper_command(cmd: &str) -> String {
    super::redact_secrets_in_text(&shape(cmd, 0))
}

/// A conventional heredoc delimiter (`EOF`, `END_KEY`): shown; anything else is not.
fn delimiter_ok(v: &str) -> bool {
    !v.is_empty() && v.len() <= 16 && v.chars().all(|c| c.is_ascii_uppercase() || c == '_')
}

fn basename(v: &str) -> &str {
    v.rsplit('/').next().unwrap_or(v)
}

fn is_var_ref(v: &str) -> bool {
    let name = v.strip_prefix("${").and_then(|r| r.strip_suffix('}')).or_else(|| v.strip_prefix('$'));
    name.is_some_and(|n| {
        !n.is_empty()
            && (n.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') || matches!(n, "@" | "*" | "#" | "?"))
    })
}

fn is_assignment(raw: &str) -> Option<(&str, &str)> {
    let (k, v) = raw.split_once('=')?;
    (k.chars().next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'))
    .then_some((k, v))
}

/// A path argument, shown with any key-shaped component redacted.
fn path_shape(v: &str) -> Option<String> {
    let body = v.strip_prefix('@').unwrap_or(v);
    if body == "-" && v.starts_with('@') {
        return Some(v.to_string());
    }
    let pathy = body.starts_with('/')
        || body.starts_with("./")
        || body.starts_with("../")
        || body.starts_with("~/")
        || body == "~"
        || body.starts_with("$HOME/")
        || body.starts_with("${HOME}/")
        || relative_path(body);
    if !pathy || body.contains("$(") || body.contains('`') || body.contains("//") {
        return None;
    }
    let comps: Vec<String> = v
        .split('/')
        .map(|c| if looks_high_entropy(c) { "<redacted>".to_string() } else { c.to_string() })
        .collect();
    Some(comps.join("/"))
}

/// A relative path written without `./`: `.vscode/key.mjs`, `scripts/get-key.sh`, or a
/// bare script name (`key.mjs`). Path characters only, and no key-shaped component.
fn relative_path(v: &str) -> bool {
    const SCRIPT_EXTS: &[&str] = &["sh", "bash", "zsh", "py", "js", "mjs", "cjs", "ts", "rb", "pl", "ps1", "php"];
    let comps: Vec<&str> = v.split('/').collect();
    let chars_ok = !v.starts_with('-')
        && comps.iter().all(|c| !c.is_empty() && c.chars().all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-' | '@')))
        && !comps.iter().any(|c| looks_high_entropy(c));
    let script = v.rsplit_once('.').is_some_and(|(stem, ext)| !stem.is_empty() && SCRIPT_EXTS.contains(&ext));
    chars_ok && (comps.len() > 1 || script)
}

/// `scheme://host` for a URL argument (userinfo, path, query and fragment dropped).
fn url_shape(v: &str) -> Option<String> {
    let (scheme, rest) = v.split_once("://")?;
    if scheme.is_empty() || !scheme.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.')) {
        return None;
    }
    let (_, host) = split_url_authority(v);
    let host_ok = host.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':' | '[' | ']'));
    let host = if host_ok && !looks_high_entropy(host) { host } else { "<redacted>" };
    let tail = rest.find(['/', '?', '#']).map(|i| &rest[i..]).unwrap_or("");
    let tail = if tail.is_empty() || tail == "/" { tail } else { "/<redacted>" };
    Some(format!("{scheme}://{host}{tail}"))
}

fn flag_shape(raw: &str, v: &str) -> String {
    if let Some(long) = v.strip_prefix("--") {
        if let Some((name, val)) = long.split_once('=') {
            let name_ok = name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-');
            let shown = if is_var_ref(val) || path_shape(val).is_some() { val.to_string() } else { "<redacted>".into() };
            return if name_ok { format!("--{name}={shown}") } else { "<redacted>".into() };
        }
        return if long.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') && long.len() <= 40 {
            raw.to_string()
        } else {
            "<redacted>".into()
        };
    }
    let short = &v[1..];
    if short.chars().all(|c| c.is_ascii_alphabetic()) && short.len() <= 2 {
        return raw.to_string();
    }
    if short.chars().all(|c| c.is_ascii_digit()) && short.len() <= 3 {
        return raw.to_string();
    }
    match short.chars().next() {
        Some(c) if c.is_ascii_alphabetic() => format!("-{c}<redacted>"),
        _ => "<redacted>".into(),
    }
}

/// A shell flag cluster that ends in `c` (`-c`, `-lc`, `-ec`, `-euxc`): the next word
/// is the command string.
fn is_shell_c(v: &str) -> bool {
    v.len() >= 2 && v.len() <= 6 && v.starts_with('-') && !v.starts_with("--")
        && v[1..].chars().all(|c| c.is_ascii_alphabetic()) && v.ends_with('c')
}

fn nested(w: &Word, depth: usize) -> String {
    let inner = shape(&w.value, depth + 1);
    match w.whole_quote {
        Some(q) => format!("{q}{inner}{q}"),
        None if inner.contains(char::is_whitespace) => format!("'{inner}'"),
        None => inner,
    }
}

fn program(w: &Word, st: &mut State) -> String {
    let v = w.value.as_str();
    if let Some((_, flags)) = WRAPPERS.iter().find(|(name, _)| *name == basename(v)) {
        *st = State::Wrapper(flags, false);
        return w.raw.clone();
    }
    let base = basename(v);
    let kind = if SHELLS.contains(&base) {
        Kind::Shell
    } else if base == "eval" {
        Kind::Eval
    } else if ECHOES.contains(&base) {
        Kind::Echo
    } else if base == "printenv" {
        Kind::Printenv
    } else {
        Kind::Other
    };
    *st = State::Args(kind);
    let program_like = !v.is_empty()
        && v.len() <= 200
        && !v.contains(char::is_whitespace)
        && !looks_high_entropy(v)
        && v.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '.' | '_' | '-' | '+' | '~' | '$' | '{' | '}' | '@' | ':'));
    if program_like { w.raw.clone() } else { "<redacted>".into() }
}

fn argument(w: &Word, kind: Kind, st: &mut State, depth: usize) -> String {
    let v = w.value.as_str();
    if v == "--" {
        return w.raw.clone();
    }
    if kind == Kind::Eval {
        return nested(w, depth);
    }
    if is_var_ref(v) {
        return w.raw.clone();
    }
    if v.starts_with('-') && v.len() > 1 {
        if kind == Kind::Shell && is_shell_c(v) {
            *st = State::Nested(kind);
            return w.raw.clone();
        }
        return flag_shape(&w.raw, v);
    }
    if kind == Kind::Echo {
        return "<redacted>".into();
    }
    if kind == Kind::Printenv && v.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') && !v.is_empty() {
        return w.raw.clone();
    }
    if let Some(p) = path_shape(v) {
        return p;
    }
    if let Some(u) = url_shape(v) {
        return u;
    }
    if VOCAB.contains(&v) {
        return w.raw.clone();
    }
    "<redacted>".into()
}

fn shape(cmd: &str, depth: usize) -> String {
    if depth > MAX_DEPTH {
        return "<redacted>".into();
    }
    let mut out = String::with_capacity(cmd.len());
    let mut st = State::Start;
    let mut saved = State::Start;
    for t in lex(cmd) {
        match t {
            Tok::Space => {
                if !out.is_empty() && !out.ends_with(char::is_whitespace) {
                    out.push(' ');
                }
            }
            Tok::Newline => {
                out.push('\n');
                st = State::Start;
            }
            Tok::Heredoc(closed) => {
                out.push_str("<redacted>");
                if let Some(d) = closed.filter(|d| delimiter_ok(d)) {
                    out.push('\n');
                    out.push_str(&d);
                }
            }
            Tok::Comment => out.push_str("# <redacted>"),
            Tok::Op(op) => {
                out.push_str(&op);
                let bare = op.trim_start_matches(|c: char| c.is_ascii_digit());
                if matches!(bare, "<<<") {
                    if st != State::Redir {
                        saved = st;
                    }
                    // The here-string word is always redacted, then the command resumes.
                    st = State::Value(Kind::Other);
                } else if matches!(bare, "<<" | "<<-") {
                    if st != State::Redir {
                        saved = st;
                    }
                    st = State::Delim;
                } else if bare.starts_with(['<', '>']) || matches!(bare, "&>" | "&>>") {
                    if st != State::Redir {
                        saved = st;
                    }
                    st = State::Redir;
                } else {
                    st = State::Start;
                }
            }
            Tok::Word(w) => {
                let rendered = match st {
                    State::Delim => {
                        st = saved;
                        let v = w.value.as_str();
                        if delimiter_ok(v) { w.raw.clone() } else { "<redacted>".into() }
                    }
                    State::Redir => {
                        st = saved;
                        let v = w.value.as_str();
                        if v == "-" || v.chars().all(|c| c.is_ascii_digit()) || is_var_ref(v) {
                            w.raw.clone()
                        } else {
                            path_shape(v).unwrap_or_else(|| "<redacted>".into())
                        }
                    }
                    State::Start => {
                        if RESERVED.contains(&w.value.as_str()) {
                            w.raw.clone()
                        } else if let Some((k, v)) = is_assignment(&w.raw) {
                            if v.is_empty() || is_var_ref(v.trim_matches(['"', '\''])) {
                                w.raw.clone()
                            } else {
                                format!("{k}=<redacted>")
                            }
                        } else {
                            program(&w, &mut st)
                        }
                    }
                    State::Wrapper(flags, expect_value) => {
                        let v = w.value.as_str();
                        let duration = !v.is_empty()
                            && v.trim_end_matches(['s', 'm', 'h', 'd']).chars().all(|c| c.is_ascii_digit() || c == '.');
                        if expect_value {
                            st = State::Wrapper(flags, false);
                            "<redacted>".into()
                        } else if v.starts_with('-') && v.len() > 1 {
                            if flags.contains(&v) {
                                st = State::Wrapper(flags, true);
                            }
                            flag_shape(&w.raw, v)
                        } else if let Some((k, val)) = is_assignment(&w.raw) {
                            if val.is_empty() || is_var_ref(val.trim_matches(['"', '\''])) {
                                w.raw.clone()
                            } else {
                                format!("{k}=<redacted>")
                            }
                        } else if duration {
                            w.raw.clone()
                        } else {
                            program(&w, &mut st)
                        }
                    }
                    State::Args(kind) => argument(&w, kind, &mut st, depth),
                    State::Nested(_) => {
                        // Words after the -c string are $0, $1, ...: redacted like echo's.
                        st = State::Args(Kind::Echo);
                        nested(&w, depth)
                    }
                    State::Value(_) => {
                        st = saved;
                        "<redacted>".into()
                    }
                };
                out.push_str(&rendered);
            }
        }
    }
    out.trim_end_matches(' ').to_string()
}
