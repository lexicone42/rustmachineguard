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
//! Kept: each simple command's program word when it is a path (key- and
//! password-shaped components redacted), a `$VAR`, or a known tool or interpreter name
//! (any other program word is `<program>`); wrapper words (exec, sudo, env, command,
//! builtin, time, nohup, timeout, ...); flag NAMES (`--long` in lower case, short
//! clusters of up to two letters, `-name=`), with any attached value `<redacted>`; a
//! word whose RAW text is exactly `$NAME`, `${NAME}`, `"$NAME"` or `"${NAME}"`;
//! `NAME=` assignment names; shell operators, reserved words, fd numbers and
//! `/dev/null`-style redirection targets. The string given to `sh|bash|zsh ... -c` is
//! shaped as a nested command, and so are the arguments of `eval`, joined into one
//! command the way the shell joins them. Every other word, in every position (paths,
//! URLs, subcommands, here-strings, heredoc bodies, quote-concatenations, ANSI-C and
//! locale strings), is `<redacted>`. The display is for a human to recognise the
//! helper, not to reproduce it.

use super::looks_high_entropy;

/// Nested `sh -c` / `eval` levels expanded before the rest is redacted whole.
const MAX_DEPTH: usize = 4;

/// Words that start a simple command without being its program, with the flags of
/// theirs that take a value (that value is redacted and is not the program).
const WRAPPERS: &[(&str, &[&str])] = &[
    ("exec", &["-a"]),
    ("command", &[]),
    ("builtin", &[]),
    (
        "sudo",
        &["-u", "-g", "-p", "-C", "-D", "-h", "-r", "-t", "-U", "-T", "-R"],
    ),
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
    "{", "}", "!", "if", "then", "else", "elif", "fi", "do", "done", "while", "until", "case", "esac", "in", "for",
    "function", "[[", "]]",
];

const SHELLS: &[&str] = &["sh", "bash", "zsh", "dash", "ksh", "mksh", "ash", "fish", "busybox"];

/// Shell operators, longest first.
const OPERATORS: &[&str] = &[
    "<<<", "<<-", "&>>", "<<", "<>", "<&", ">>", ">&", ">|", "&>", "&&", "||", "|&", ";;", "<", ">", "&", "|", ";",
    "(", ")",
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
            // ANSI-C quoting, `$'...'`: a literal string (backslash escapes, `\'`
            // included, are part of it), never a variable reference. Its body is pushed
            // without the `$`, so `$'Hunter2pass'` is the literal `Hunter2pass`.
            '$' if chars.get(i + 1) == Some(&'\'') => {
                let mut j = i + 2;
                while j < n && chars[j] != '\'' {
                    j += if chars[j] == '\\' { 2 } else { 1 };
                }
                let end = j.min(n);
                w.value.extend(&chars[i + 2..end]);
                i = end + 1;
            }
            // Locale quoting, `$"..."`: a double-quoted string; the `$` is not part of it.
            '$' if chars.get(i + 1) == Some(&'"') => {
                i += 1;
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
    Other,
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum State {
    Start,
    /// After a wrapper: its flags, then the program. `true` = the next word is a flag value.
    Wrapper(&'static [&'static str], bool),
    Args(Kind),
    /// The next word is a nested command (`sh -c STRING`).
    Nested,
    /// The next word is a value (redacted), then back to the saved state.
    Value,
    /// The next word is a redirection target; then back to the saved state.
    Redir,
    /// The next word is a heredoc delimiter.
    Delim,
}

pub fn redact_helper_command(cmd: &str) -> String {
    super::redact_secrets_in_text(&shape(cmd, 0, false))
}

/// The shape with path ARGUMENTS kept (key- and password-shaped components still
/// redacted), for the risk classifier only: it looks for agent-config directories in
/// the paths a helper names (`node .vscode/key.mjs`). Never displayed; the classifier's
/// risk text names the directory, not the path.
pub fn helper_classification_shape(cmd: &str) -> String {
    super::redact_secrets_in_text(&shape(cmd, 0, true))
}

/// Heredoc delimiters shown as written; any other delimiter word is `<redacted>`.
const DELIMITERS: &[&str] = &["EOF", "END", "EOT", "EOM", "EOS", "HEREDOC", "SCRIPT", "DATA", "JSON"];

/// Redirection targets shown as written (fixed device paths).
const DEVICES: &[&str] = &["/dev/null", "/dev/stdout", "/dev/stderr", "/dev/tty", "/dev/stdin"];

fn basename(v: &str) -> &str {
    v.rsplit('/').next().unwrap_or(v)
}

/// `$NAME` / `${NAME}` (or `$@`, `$*`, `$#`, `$?`, `$1`) and nothing else.
fn is_var_ref(v: &str) -> bool {
    let name = v
        .strip_prefix("${")
        .and_then(|r| r.strip_suffix('}'))
        .or_else(|| v.strip_prefix('$'));
    name.is_some_and(|n| {
        !n.is_empty()
            && (n.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') || matches!(n, "@" | "*" | "#" | "?"))
    })
}

/// The RAW word is exactly one variable reference: `$NAME`, `${NAME}`, `"$NAME"` or
/// `"${NAME}"`. Decided on the raw text, so `$x"LITERAL"`, `"$x"LITERAL` and
/// `'$LITERAL'` (quote-concatenation, single-quoted text) are never references.
fn raw_var_ref(raw: &str) -> bool {
    let inner = raw.strip_prefix('"').and_then(|r| r.strip_suffix('"')).unwrap_or(raw);
    is_var_ref(inner)
}

fn is_assignment(raw: &str) -> Option<(&str, &str)> {
    let (k, v) = raw.split_once('=')?;
    (k.chars().next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'))
    .then_some((k, v))
}

fn assignment(raw: &str) -> Option<String> {
    let (k, v) = is_assignment(raw)?;
    Some(if v.is_empty() || raw_var_ref(v) {
        raw.to_string()
    } else {
        format!("{k}=<redacted>")
    })
}

/// A run of 10+ letters and digits with upper case, lower case and a digit
/// (`Zq9Hunter2Pw`): a password shape, never a real path component or tool name.
fn mixed_case_run(s: &str) -> bool {
    s.split(|c: char| !c.is_ascii_alphanumeric()).any(|r| {
        r.len() >= 10
            && r.bytes().any(|b| b.is_ascii_uppercase())
            && r.bytes().any(|b| b.is_ascii_lowercase())
            && r.bytes().any(|b| b.is_ascii_digit())
    })
}

/// Tools and interpreters whose name is shown as the program word. Any other plain
/// word in program position is `<program>`: a literal written where the program goes
/// (`Hunter2pass --flag`, `(cd /tmp && Hunter2pass)`) never reaches the report.
const KNOWN_PROGRAMS: &[&str] = &[
    // shells, builtins and coreutils
    "sh",
    "bash",
    "zsh",
    "dash",
    "ksh",
    "mksh",
    "ash",
    "fish",
    "busybox",
    "eval",
    "echo",
    "printf",
    "print",
    "printenv",
    "cat",
    "head",
    "tail",
    "tr",
    "cut",
    "sed",
    "awk",
    "gawk",
    "grep",
    "jq",
    "yq",
    "base64",
    "xxd",
    "cd",
    "test",
    "[",
    "true",
    "false",
    "read",
    "set",
    "unset",
    "source",
    ".",
    "trap",
    "exit",
    "return",
    "yes",
    "tee",
    "sort",
    "uniq",
    "wc",
    "date",
    "sleep",
    "mktemp",
    "rm",
    "ls",
    "mkdir",
    "chmod",
    "id",
    "whoami",
    "hostname",
    "uname",
    "which",
    "type",
    "dirname",
    "basename",
    "realpath",
    "readlink",
    "stat",
    "touch",
    // interpreters and runtimes
    "node",
    "nodejs",
    "deno",
    "bun",
    "npx",
    "npm",
    "pnpm",
    "yarn",
    "ruby",
    "perl",
    "php",
    "pwsh",
    "powershell",
    "osascript",
    "uv",
    "uvx",
    "pipx",
    "pip",
    "go",
    "java",
    "dotnet",
    "lua",
    // network and crypto
    "curl",
    "wget",
    "http",
    "https",
    "xh",
    "openssl",
    "gpg",
    "gpg2",
    "age",
    "sops",
    "ssh",
    "nc",
    "socat",
    // secret stores and cloud CLIs
    "aws",
    "aws-vault",
    "gcloud",
    "az",
    "gh",
    "glab",
    "vault",
    "op",
    "pass",
    "gopass",
    "security",
    "secret-tool",
    "keyring",
    "bw",
    "lpass",
    "doppler",
    "infisical",
    "chamber",
    "akeyless",
    "kubectl",
    "terraform",
    "saml2aws",
    "granted",
    "assume",
    "gimme-aws-creds",
    "keepassxc-cli",
    "ykman",
    "conjur",
    "claude",
];

fn known_program(v: &str) -> bool {
    KNOWN_PROGRAMS.contains(&v)
        || v.strip_prefix("python")
            .is_some_and(|r| r.chars().all(|c| c.is_ascii_digit() || c == '.'))
        || WRAPPERS.iter().any(|(name, _)| *name == v)
}

/// A program path (`/usr/local/bin/key-helper`, `./k.sh`, `~/bin/x`, `$HOME/bin/x`,
/// `scripts/get-key.sh`), with any key- or password-shaped component redacted. `None`
/// when `v` is not a plain path.
fn path_display(v: &str) -> Option<String> {
    let pathy = v.starts_with('/')
        || v.starts_with("./")
        || v.starts_with("../")
        || v.starts_with("~/")
        || v.starts_with("$HOME/")
        || v.starts_with("${HOME}/")
        || (v.contains('/') && !v.starts_with('-'));
    let chars_ok = v
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '.' | '_' | '-' | '+' | '~' | '@' | '$' | '{' | '}'));
    if !pathy || !chars_ok || v.contains("//") || v.len() > 300 {
        return None;
    }
    let comps: Vec<&str> = v
        .split('/')
        .map(|c| {
            if looks_high_entropy(c) || mixed_case_run(c) {
                "<redacted>"
            } else {
                c
            }
        })
        .collect();
    Some(comps.join("/"))
}

/// A flag keeps its NAME only; any value attached to it is `<redacted>` (a `$NAME`
/// reference excepted, decided on the raw text).
fn flag_shape(raw: &str, v: &str) -> String {
    let raw_val = raw.split_once('=').map(|(_, r)| r).unwrap_or("");
    let shown = if raw_var_ref(raw_val) {
        raw_val.to_string()
    } else {
        "<redacted>".to_string()
    };
    if let Some(long) = v.strip_prefix("--") {
        let lower_name = |n: &str| {
            !n.is_empty()
                && n.len() <= 40
                && n.chars().next().is_some_and(|c| c.is_ascii_lowercase())
                && n.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        };
        return match long.split_once('=') {
            Some((name, _)) if lower_name(name) => format!("--{name}={shown}"),
            Some(_) => "<redacted>".into(),
            None if lower_name(long) => format!("--{long}"),
            None => "<redacted>".into(),
        };
    }
    let short = &v[1..];
    // Single-dash long options with an attached value (`vault kv get -field=api_key`,
    // Go's flag package): the name is kept like a `--name=value`, the value redacted.
    if let Some((name, _)) = short.split_once('=') {
        let name_ok = name.len() >= 2
            && name.len() <= 40
            && name.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
            && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            && !looks_high_entropy(name)
            && !mixed_case_run(name);
        return if name_ok {
            format!("-{name}={shown}")
        } else {
            "<redacted>".into()
        };
    }
    if (short.chars().all(|c| c.is_ascii_alphabetic()) || short.chars().all(|c| c.is_ascii_digit())) && short.len() <= 2
    {
        return format!("-{short}");
    }
    // `-pHunter2pass`: the flag letter, then its value as a separate redacted word.
    match short.chars().next() {
        Some(c) if c.is_ascii_alphabetic() => format!("-{c} <redacted>"),
        _ => "<redacted>".into(),
    }
}

/// A shell flag cluster that ends in `c` (`-c`, `-lc`, `-ec`, `-euxc`): the next word
/// is the command string.
fn is_shell_c(v: &str) -> bool {
    v.len() >= 2
        && v.len() <= 6
        && v.starts_with('-')
        && !v.starts_with("--")
        && v[1..].chars().all(|c| c.is_ascii_alphabetic())
        && v.ends_with('c')
}

/// A command string the shell parses again (`sh -c STRING`, `eval WORDS`), shaped as a
/// nested command; `quote` re-wraps it the way it was written.
fn nested(text: &str, quote: Option<char>, depth: usize, keep_paths: bool) -> String {
    let inner = shape(text, depth + 1, keep_paths);
    match quote {
        Some(q) => format!("{q}{inner}{q}"),
        None if inner.contains(char::is_whitespace) => format!("'{inner}'"),
        None => inner,
    }
}

fn program(w: &Word, st: &mut State) -> String {
    let v = w.value.as_str();
    let base = basename(v);
    if let Some((_, flags)) = WRAPPERS.iter().find(|(name, _)| *name == base) {
        *st = State::Wrapper(flags, false);
    } else {
        let kind = if SHELLS.contains(&base) {
            Kind::Shell
        } else if base == "eval" {
            Kind::Eval
        } else {
            Kind::Other
        };
        *st = State::Args(kind);
    }
    if raw_var_ref(&w.raw) {
        return w.raw.clone();
    }
    if let Some(p) = path_display(v) {
        return p;
    }
    if known_program(v) {
        v.to_string()
    } else {
        "<program>".into()
    }
}

fn argument(w: &Word, kind: Kind, st: &mut State, keep_paths: bool) -> String {
    let v = w.value.as_str();
    if w.raw == "--" {
        return "--".into();
    }
    if raw_var_ref(&w.raw) {
        return w.raw.clone();
    }
    if v.starts_with('-') && v.len() > 1 {
        if kind == Kind::Shell && is_shell_c(v) {
            *st = State::Nested;
            return v.to_string();
        }
        return flag_shape(&w.raw, v);
    }
    if keep_paths && let Some(p) = path_display(v) {
        return p;
    }
    "<redacted>".into()
}

fn shape(cmd: &str, depth: usize, keep_paths: bool) -> String {
    if depth > MAX_DEPTH {
        return "<redacted>".into();
    }
    let toks = lex(cmd);
    let mut out = String::with_capacity(cmd.len());
    let mut st = State::Start;
    let mut saved = State::Start;
    let mut i = 0;
    while i < toks.len() {
        let t = &toks[i];
        i += 1;
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
                if let Some(d) = closed.as_deref().filter(|d| DELIMITERS.contains(d)) {
                    out.push('\n');
                    out.push_str(d);
                }
            }
            Tok::Comment => out.push_str("# <redacted>"),
            Tok::Op(op) => {
                out.push_str(op);
                let bare = op.trim_start_matches(|c: char| c.is_ascii_digit());
                if matches!(bare, "<<<") {
                    if st != State::Redir {
                        saved = st;
                    }
                    // The here-string word is always redacted, then the command resumes.
                    st = State::Value;
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
                        if DELIMITERS.contains(&w.value.as_str()) {
                            w.value.clone()
                        } else {
                            "<redacted>".into()
                        }
                    }
                    State::Redir => {
                        st = saved;
                        let v = w.value.as_str();
                        let fd = !v.is_empty() && v.len() <= 2 && v.chars().all(|c| c.is_ascii_digit());
                        if v == "-" || fd || DEVICES.contains(&v) || raw_var_ref(&w.raw) {
                            w.raw.clone()
                        } else {
                            "<redacted>".into()
                        }
                    }
                    State::Start => {
                        if RESERVED.contains(&w.value.as_str()) && w.raw == w.value {
                            w.raw.clone()
                        } else if let Some(a) = assignment(&w.raw) {
                            a
                        } else {
                            program(w, &mut st)
                        }
                    }
                    State::Wrapper(flags, expect_value) => {
                        let v = w.value.as_str();
                        let duration = !v.is_empty()
                            && v.trim_end_matches(['s', 'm', 'h', 'd'])
                                .chars()
                                .all(|c| c.is_ascii_digit() || c == '.');
                        if expect_value {
                            st = State::Wrapper(flags, false);
                            "<redacted>".into()
                        } else if v.starts_with('-') && v.len() > 1 {
                            if flags.contains(&v) {
                                st = State::Wrapper(flags, true);
                            }
                            flag_shape(&w.raw, v)
                        } else if let Some(a) = assignment(&w.raw) {
                            a
                        } else if duration {
                            "<redacted>".into()
                        } else {
                            program(w, &mut st)
                        }
                    }
                    State::Args(Kind::Eval) => {
                        // `eval` joins its arguments with spaces and parses the result as
                        // ONE command, so the words are shaped together: the first is the
                        // program, the rest its arguments (`eval echo LITERAL`).
                        let mut words: Vec<&Word> = vec![w];
                        let mut trailing_space = false;
                        while let Some(next) = toks.get(i) {
                            match next {
                                Tok::Space => {
                                    trailing_space = true;
                                    i += 1;
                                }
                                Tok::Word(nw) => {
                                    trailing_space = false;
                                    words.push(nw);
                                    i += 1;
                                }
                                _ => break,
                            }
                        }
                        let mut prefix = String::new();
                        if words.first().is_some_and(|w| w.raw == "--") {
                            words.remove(0);
                            prefix.push_str("--");
                        }
                        st = State::Args(Kind::Other);
                        let body = if words.is_empty() {
                            String::new()
                        } else {
                            let joined = words.iter().map(|w| w.value.as_str()).collect::<Vec<_>>().join(" ");
                            let quote = if words.len() == 1 { words[0].whole_quote } else { None };
                            nested(&joined, quote, depth, keep_paths)
                        };
                        let sep = if !prefix.is_empty() && !body.is_empty() {
                            " "
                        } else {
                            ""
                        };
                        let tail = if trailing_space { " " } else { "" };
                        format!("{prefix}{sep}{body}{tail}")
                    }
                    State::Args(kind) => argument(w, kind, &mut st, keep_paths),
                    State::Nested => {
                        // Words after the -c string are $0, $1, ...: redacted like any argument.
                        st = State::Args(Kind::Other);
                        nested(&w.value, w.whole_quote, depth, keep_paths)
                    }
                    State::Value => {
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

#[cfg(test)]
mod tests {
    use super::redact_helper_command as r;

    #[test]
    fn quoted_literals_are_redacted() {
        // ANSI-C and locale quoting are literal strings, not `$VAR` references.
        assert_eq!(r("printf %s $'Hunter2pass'"), "printf <redacted> <redacted>");
        assert_eq!(r("echo $\"Tr0ub4dor3\""), "echo <redacted>");
        assert_eq!(r("mytool $'Hunter2pass'"), "<program> <redacted>");
        assert_eq!(r("mytool $\"Hunter2pass\""), "<program> <redacted>");
        // Single-quoted `$` text is literal too; a double-quoted reference is not.
        assert_eq!(r("mytool '$Hunter2pass'"), "<program> <redacted>");
        assert_eq!(r("mytool --flag='$Hunter2pass'"), "<program> --flag=<redacted>");
        assert_eq!(r("K='$Hunter2pass' mytool"), "K=<redacted> <program>");
        assert_eq!(r("mytool \"$ANTHROPIC_API_KEY\""), "<program> \"$ANTHROPIC_API_KEY\"");
        assert_eq!(r("mytool $ANTHROPIC_API_KEY"), "<program> $ANTHROPIC_API_KEY");
        // Nested: inside `sh -c '...'` the inner shell expands `$X`.
        assert_eq!(r("sh -c 'echo $X'"), "sh -c 'echo $X'");
        assert!(!r("bash -c $'echo Hunter2pass'").contains("Hunter2pass"));
    }

    #[test]
    fn single_dash_name_value_flags_keep_their_name() {
        assert_eq!(
            r("vault kv get -field=api_key secret/anthropic"),
            "vault <redacted> <redacted> -field=<redacted> <redacted>"
        );
        assert_eq!(
            r("vault kv get -field=$FIELD secret/x"),
            "vault <redacted> <redacted> -field=$FIELD <redacted>"
        );
        assert_eq!(r("tool -token=Hunter2pass"), "<program> -token=<redacted>");
        // A short flag with an attached value keeps only its letter.
        assert_eq!(r("mysqlx -pHunter2pass"), "<program> -p <redacted>");
    }

    /// Review round 6: each `eval` argument used to be shaped as its own command, so the
    /// literal became a kept program word.
    #[test]
    fn eval_arguments_are_one_nested_command() {
        const C: &str = "Zq9Hunter2Pw";
        for (cmd, want) in [
            ("eval echo Zq9Hunter2Pw", "eval 'echo <redacted>'"),
            ("command eval echo Zq9Hunter2Pw", "command eval 'echo <redacted>'"),
            ("sh -c 'eval echo Zq9Hunter2Pw'", "sh -c 'eval 'echo <redacted>''"),
            ("eval mytool Zq9Hunter2Pw", "eval '<program> <redacted>'"),
            ("true && eval echo Zq9Hunter2Pw", "true && eval 'echo <redacted>'"),
            ("eval -- echo Zq9Hunter2Pw", "eval -- 'echo <redacted>'"),
            ("builtin eval echo Zq9Hunter2Pw", "builtin eval 'echo <redacted>'"),
            ("eval \"echo Zq9Hunter2Pw\"", "eval \"echo <redacted>\""),
            ("eval echo Zq9Hunter2Pw; date", "eval 'echo <redacted>'; date"),
            ("eval $CMD", "eval $CMD"),
        ] {
            let out = r(cmd);
            assert!(!out.contains(C), "{cmd} -> {out}");
            assert_eq!(out, want, "{cmd}");
        }
    }

    /// Review round 6: a quote-concatenated word is a literal next to an expansion, not a
    /// variable reference.
    #[test]
    fn quote_concatenation_is_not_a_reference() {
        for cmd in [
            "echo $x\"Zq9Hunter2Pw\"",
            "echo \"$x\"Zq9Hunter2Pw",
            "echo ${x}Zq9Hunter2Pw",
            "echo $x'Zq9Hunter2Pw'",
            "mytool --t=$x\"Zq9Hunter2Pw\"",
            "K=$x\"Zq9Hunter2Pw\" mytool",
            "cat > $x\"Zq9Hunter2Pw\"",
            "cat <<< \"$x\"Zq9Hunter2Pw",
        ] {
            let out = r(cmd);
            assert!(!out.contains("Zq9Hunter2Pw"), "{cmd} -> {out}");
        }
        assert_eq!(
            r("echo \"${KEY}\" $KEY ${KEY} \"$KEY\""),
            "echo \"${KEY}\" $KEY ${KEY} \"$KEY\""
        );
    }

    /// Review round 6: long flags, URL hosts, program words and path arguments no longer
    /// carry a literal through.
    #[test]
    fn every_other_position_is_shape_only() {
        for cmd in [
            "mytool --Zq9Hunter2Pw",
            "mytool https://Zq9Hunter2Pw.example.com/",
            "Zq9Hunter2Pw --flag",
            "(cd /tmp && Zq9Hunter2Pw)",
            "cat /tmp/Zq9Hunter2Pw",
            "mytool ./Zq9Hunter2Pw",
            "mytool ~/Zq9Hunter2Pw",
            "/opt/Zq9Hunter2Pw/get-key",
            "printenv Zq9Hunter2Pw",
            "cat <<Zq9Hunter2Pw\nx\nZq9Hunter2Pw",
            "timeout Zq9Hunter2Pw mytool",
            "mytool 2>Zq9Hunter2Pw",
            "aws Zq9Hunter2Pw",
        ] {
            let out = r(cmd);
            assert!(!out.contains("Zq9Hunter2Pw"), "{cmd} -> {out}");
        }
        assert_eq!(r("Zq9Hunter2Pw --flag"), "<program> --flag");
        assert_eq!(r("mytool --Zq9Hunter2Pw"), "<program> <redacted>");
        assert_eq!(
            r("/usr/bin/op read op://v/i/f 2>/dev/null"),
            "/usr/bin/op <redacted> <redacted> 2>/dev/null"
        );
        assert_eq!(r("python3.12 -c x"), "python3.12 -c <redacted>");
    }
}
