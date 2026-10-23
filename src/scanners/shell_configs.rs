use crate::models::{OllamaHostSetting, ShellConfig};
use std::path::{Path, PathBuf};
use crate::platform::PlatformInfo;
use crate::scanners::Scanner;

pub struct ShellConfigsScanner;

/// Patterns that indicate AI-related configuration in shell files.
/// These are matched as whole-word prefixes to avoid false positives
/// (e.g., MAIL_DELIVERY matching "AI_").
const AI_KEY_PATTERNS: &[&str] = &[
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "CLAUDE_API_KEY",
    "CLAUDE_CODE",
    "COPILOT_TOKEN",
    "GEMINI_API_KEY",
    "GOOGLE_AI_STUDIO",
    "HF_TOKEN",
    "HUGGING_FACE_HUB_TOKEN",
    "REPLICATE_API_TOKEN",
    "TOGETHER_API_KEY",
    "GROQ_API_KEY",
    "MISTRAL_API_KEY",
    "COHERE_API_KEY",
    "OLLAMA_HOST",
    "OLLAMA_MODELS",
];

/// Alias patterns (these don't contain secrets, safe to report as-is).
const ALIAS_PATTERNS: &[&str] = &[
    "alias claude",
    "alias copilot",
    "alias aider",
    "alias ollama",
];

impl Scanner for ShellConfigsScanner {
    type Output = Vec<ShellConfig>;

    fn scan(&self, platform: &dyn PlatformInfo) -> Vec<ShellConfig> {
        let mut results = Vec::new();

        for (shell, path) in platform.shell_config_paths() {
            if !crate::scanners::probe_file(&path) {
                continue;
            }

            // Size guard: skip files over 1MB
            let meta = match std::fs::metadata(&path) {
                Ok(m) => m,
                Err(_) => continue,
            };
            if meta.len() > 1_048_576 {
                continue;
            }

            let Some(content) = crate::scanners::read_bounded(&path) else {
                continue;
            };

            let mut ai_entries = Vec::new();
            let mut ollama_value = None;
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with('#') || trimmed.is_empty() {
                    continue;
                }
                if let Some(v) = ollama_host_assignment(trimmed) {
                    ollama_value = Some(v);
                }

                // Check for key patterns — report only the variable name, never the value
                for pattern in AI_KEY_PATTERNS {
                    if trimmed.contains(pattern) {
                        ai_entries.push(format!("{pattern}=<redacted>"));
                        break;
                    }
                }

                // Check alias patterns (safe to report)
                for pattern in ALIAS_PATTERNS {
                    if trimmed.starts_with(pattern) {
                        ai_entries.push(format!("{pattern} (alias defined)"));
                        break;
                    }
                }
            }

            if !ai_entries.is_empty() {
                results.push(ShellConfig {
                    shell,
                    config_path: path.display().to_string(),
                    ai_related_entries: ai_entries,
                    ollama_host: ollama_value.map(|v| {
                        let (value, bind) = classify_ollama_host(&v);
                        OllamaHostSetting { value, bind: bind.into(), service: false }
                    }),
                });
            }
        }

        // Service definitions that start the Ollama server with OLLAMA_HOST: systemd
        // user units (any unit), the official installer's system unit and its
        // `systemctl edit` drop-ins, and launchd jobs.
        let home = platform.home_dir();
        results.extend(scan_systemd_units(&[
            (home.join(".config/systemd/user"), "systemd-user", true),
            (crate::scanners::system_path("/etc/systemd/system"), "systemd-system", false),
        ]));
        results.extend(scan_launchd(&[
            (home.join("Library/LaunchAgents"), true),
            (crate::scanners::system_path("/Library/LaunchAgents"), false),
            (crate::scanners::system_path("/Library/LaunchDaemons"), false),
        ]));

        results
    }
}

/// Classify an OLLAMA_HOST value the way the Ollama server parses it, returning a
/// sanitized display form and where the server would listen: "wildcard" (every
/// interface), "non-loopback-ip", "hostname", "loopback" or "unresolved" (a shell
/// expansion we cannot evaluate).
///
/// Mirrors `envconfig.Host()` in ollama/ollama (envconfig/config.go): quotes and spaces
/// trimmed, scheme cut at `://`, path cut at the first `/`, then Go's SplitHostPort; on
/// a split error the whole string (brackets trimmed) is the host. An empty value means
/// the default 127.0.0.1:11434 (docs.ollama.com/faq), and an empty host (`:11434`)
/// makes net.Listen bind every interface. Userinfo is stripped at the last `@` before
/// classifying, so it never reaches the display.
pub fn classify_ollama_host(v: &str) -> (String, &'static str) {
    let s = v.trim().trim_matches(|c| c == '"' || c == '\'').trim();
    // A shell expansion is not evaluated, and its text (`\`echo KEY\``, `$(cmd)`) is not
    // shown: only that there is one.
    if s.contains('$') || s.contains('`') {
        return ("<shell expansion>".to_string(), "unresolved");
    }
    let hostport = s.split_once("://").map_or(s, |(_, rest)| rest);
    let hostport = hostport.split('/').next().unwrap_or(hostport);
    let hostport = hostport.rsplit_once('@').map_or(hostport, |(_, h)| h);
    if s.is_empty() {
        return (String::new(), "loopback");
    }
    let (host, port): (String, Option<&str>) = match go_split_host_port(hostport) {
        Some((h, p)) => (h.to_string(), Some(p)),
        None => {
            let trimmed = hostport.trim_matches(|c| c == '[' || c == ']');
            // Go keeps the 127.0.0.1 default when nothing is left (`http://`).
            (if trimmed.is_empty() { "127.0.0.1".to_string() } else { trimmed.to_string() }, None)
        }
    };
    let bind = if host.is_empty() {
        "wildcard"
    } else if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        let ip = ip.to_canonical();
        if ip.is_unspecified() {
            "wildcard"
        } else if ip.is_loopback() {
            "loopback"
        } else {
            "non-loopback-ip"
        }
    } else if host.eq_ignore_ascii_case("localhost") {
        "loopback"
    } else {
        "hostname"
    };
    let shown = match port {
        Some(p) if host.contains(':') => format!("[{host}]:{p}"),
        Some(p) => format!("{host}:{p}"),
        None => host,
    };
    (crate::scanners::sanitize_display(&crate::scanners::redact_secrets_in_text(&shown), 128), bind)
}

/// Go's net.SplitHostPort: `[h]:p`, or exactly one `:`; anything else is an error.
fn go_split_host_port(hp: &str) -> Option<(&str, &str)> {
    if let Some(rest) = hp.strip_prefix('[') {
        let end = rest.find(']')?;
        let port = rest[end + 1..].strip_prefix(':')?;
        return Some((&rest[..end], port));
    }
    if hp.matches(':').count() != 1 {
        return None;
    }
    hp.split_once(':')
}

/// Strip one pair of surrounding quotes, or cut an unquoted value at whitespace, `;`
/// or a `#` comment.
fn shell_value(raw: &str) -> String {
    let raw = raw.trim_start();
    for q in ['"', '\''] {
        if let Some(rest) = raw.strip_prefix(q) {
            return rest.split(q).next().unwrap_or("").to_string();
        }
    }
    raw.split(|c: char| c.is_whitespace() || c == ';' || c == '#')
        .next()
        .unwrap_or("")
        .to_string()
}

/// The OLLAMA_HOST value assigned on one shell-profile line, if any: `OLLAMA_HOST=v`,
/// `export OLLAMA_HOST=v`, fish `set -x|-gx|-Ux OLLAMA_HOST v`, and the macOS
/// `launchctl setenv OLLAMA_HOST v` form from Ollama's FAQ.
pub fn ollama_host_assignment(line: &str) -> Option<String> {
    let t = line.trim();
    if t.starts_with('#') {
        return None;
    }
    let after_export = t.strip_prefix("export ").map(str::trim_start).unwrap_or(t);
    if let Some(rest) = after_export.strip_prefix("OLLAMA_HOST=") {
        return Some(shell_value(rest));
    }
    let words: Vec<&str> = t.split_whitespace().collect();
    match words.as_slice() {
        ["set", flag, "OLLAMA_HOST", ..] if flag.starts_with('-') && flag.contains('x') => {
            let rest = t.splitn(4, char::is_whitespace).nth(3).unwrap_or("");
            Some(shell_value(rest.trim_start()))
        }
        ["launchctl", "setenv", "OLLAMA_HOST", ..] => {
            let idx = t.find("OLLAMA_HOST")? + "OLLAMA_HOST".len();
            Some(shell_value(&t[idx..]))
        }
        _ => None,
    }
}

/// Split a systemd `Environment=` value into assignments (whitespace-separated,
/// double or single quotes group).
fn systemd_words(v: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    let mut any = false;
    for c in v.chars() {
        match quote {
            Some(q) if c == q => quote = None,
            Some(_) => cur.push(c),
            None if c == '"' || c == '\'' => {
                quote = Some(c);
                any = true;
            }
            None if c.is_whitespace() => {
                if !cur.is_empty() || any {
                    out.push(std::mem::take(&mut cur));
                }
                any = false;
            }
            None => cur.push(c),
        }
    }
    if !cur.is_empty() || any {
        out.push(cur);
    }
    out
}

/// True when a command line starts the Ollama server: the program's basename is `ollama`
/// and its first argument is `serve`. systemd's ExecStart prefixes (`-`, `@`, `:`, `+`,
/// `!`) and an `env [NAME=value ...]` wrapper are skipped. A client unit that merely
/// mentions ollama (an Open WebUI image tagged `:ollama`) is not the server.
pub fn runs_ollama_serve(cmdline: &str) -> bool {
    let words: Vec<&str> = cmdline.split_whitespace().collect();
    let mut i = 0;
    let base = |w: &str| w.trim_matches(['"', '\'']).rsplit('/').next().unwrap_or("").to_string();
    while i < words.len() {
        let w = words[i].trim_start_matches(['-', '@', ':', '+', '!']);
        if base(w) == "env" || (i > 0 && w.contains('=') && !w.starts_with('-')) {
            i += 1;
            continue;
        }
        return base(w) == "ollama" && words.get(i + 1).is_some_and(|a| a.trim_matches(['"', '\'']) == "serve");
    }
    false
}

/// The last OLLAMA_HOST in a systemd unit or drop-in, and whether the unit starts the
/// Ollama server (see [`runs_ollama_serve`]). `EnvironmentFile=` is not followed
/// (documented floor).
pub fn systemd_ollama_host(text: &str) -> (Option<String>, bool) {
    let mut value = None;
    let mut runs_ollama = false;
    for line in systemd_logical_lines(text) {
        // systemd.syntax(7): the key ends at the first `=`, and whitespace around it is
        // ignored (`Environment = "OLLAMA_HOST=0.0.0.0"` is valid).
        let Some((key, rest)) = line.split_once('=') else { continue };
        match key.trim() {
            "Environment" => {
                for w in systemd_words(rest.trim()) {
                    if let Some(v) = w.strip_prefix("OLLAMA_HOST=") {
                        value = Some(v.to_string());
                    }
                }
            }
            "ExecStart" if runs_ollama_serve(rest.trim()) => runs_ollama = true,
            _ => {}
        }
    }
    (value, runs_ollama)
}

/// A unit file's logical lines, as systemd reads them: a line ending in a backslash is
/// joined with the next (the backslash becomes a space), comment lines (`#`, `;`) are
/// dropped, including those inside a continuation, and section headers are skipped.
fn systemd_logical_lines(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur: Option<String> = None;
    for raw in text.lines() {
        let t = raw.trim();
        if t.starts_with('#') || t.starts_with(';') {
            continue;
        }
        let (body, cont) = match t.strip_suffix('\\') {
            Some(b) => (b, true),
            None => (t, false),
        };
        let joined = match cur.take() {
            Some(mut c) => {
                c.push(' ');
                c.push_str(body);
                c
            }
            None => body.to_string(),
        };
        if cont {
            cur = Some(joined);
        } else if !joined.trim().is_empty() && !joined.trim_start().starts_with('[') {
            out.push(joined);
        }
    }
    if let Some(c) = cur.filter(|c| !c.trim().is_empty()) {
        out.push(c);
    }
    out
}

const MAX_SERVICE_ENTRIES: usize = 500;

fn regular_file(p: &Path) -> bool {
    std::fs::symlink_metadata(p).is_ok_and(|m| m.is_file())
}

fn ollama_entry(shell: &str, path: &Path, value: &str, service: bool) -> ShellConfig {
    let (value, bind) = classify_ollama_host(value);
    ShellConfig {
        shell: shell.to_string(),
        config_path: crate::scanners::sanitize_display(&path.display().to_string(), 512),
        ai_related_entries: vec!["OLLAMA_HOST=<redacted>".into()],
        ollama_host: Some(OllamaHostSetting { value, bind: bind.into(), service }),
    }
}

/// systemd units that set OLLAMA_HOST. Each `(dir, label, all_units)`: with
/// `all_units`, every `*.service` and `*.service.d/*.conf` is read (a user's own units);
/// otherwise only `ollama.service` and `ollama.service.d/*.conf` (the official installer's
/// unit and the `systemctl edit ollama.service` override path from the Ollama FAQ).
/// Regular files only; symlinked units are not followed.
pub fn scan_systemd_units(dirs: &[(PathBuf, &'static str, bool)]) -> Vec<ShellConfig> {
    let mut out = Vec::new();
    for (dir, label, all) in dirs {
        if !dir.is_dir() {
            crate::scanners::telemetry::note_probe(dir, false);
            continue;
        }
        // The system directory is probed for the two names it can hold, not listed: a
        // large /etc/systemd/system cut to a listing cap in read_dir order could drop
        // ollama.service nondeterministically. Elsewhere the cap applies after the suffix
        // filter, and the kept names are sorted.
        let mut names: Vec<String> = if *all {
            let Ok(entries) = crate::scanners::probe_read_dir(dir) else { continue };
            entries
                .flatten()
                .filter_map(|e| e.file_name().to_str().map(String::from))
                .filter(|n| n.ends_with(".service") || n.ends_with(".service.d"))
                .collect()
        } else {
            ["ollama.service", "ollama.service.d"]
                .iter()
                .filter(|n| std::fs::symlink_metadata(dir.join(n)).is_ok())
                .map(|n| n.to_string())
                .collect()
        };
        // Sort, then cap: which names survive the cap must not depend on read_dir order.
        names.sort();
        names.truncate(MAX_SERVICE_ENTRIES);
        let wanted = |unit: &str| *all || unit == "ollama.service";
        let mut files: Vec<(PathBuf, String)> = Vec::new();
        for n in &names {
            let p = dir.join(n);
            if n.ends_with(".service") && wanted(n) && regular_file(&p) {
                files.push((p, n.clone()));
            } else if let Some(unit) = n.strip_suffix(".d")
                && unit.ends_with(".service")
                && wanted(unit)
                && std::fs::symlink_metadata(&p).is_ok_and(|m| m.is_dir())
                && let Ok(confs) = std::fs::read_dir(&p)
            {
                let mut cs: Vec<String> = confs
                    .flatten()
                    .filter_map(|e| e.file_name().to_str().map(String::from))
                    .filter(|c| c.ends_with(".conf"))
                    .collect();
                cs.sort();
                cs.truncate(MAX_SERVICE_ENTRIES);
                for c in cs {
                    let cp = p.join(&c);
                    if regular_file(&cp) {
                        files.push((cp, unit.to_string()));
                    }
                }
            }
        }
        for (path, unit) in files {
            // O_NOFOLLOW|O_NONBLOCK + fstat: a unit swapped for a link or FIFO after the
            // regular-file check is refused, not followed or blocked on.
            let Some(text) = crate::scanners::read_bounded_nofollow(&path, None) else { continue };
            let (value, runs) = systemd_ollama_host(&text);
            if let Some(v) = value {
                // The server: a unit whose ExecStart is `ollama serve`, or the official
                // installer's ollama.service (and its drop-ins), whatever it execs.
                let service = runs || unit == "ollama.service";
                out.push(ollama_entry(label, &path, &v, service));
            }
        }
    }
    out
}

fn xml_unescape(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

/// Every `<key>` and `<string>` element of an XML plist, in document order.
fn plist_tokens(text: &str) -> Vec<(&'static str, String)> {
    let mut out = Vec::new();
    let mut rest = text;
    loop {
        let k = rest.find("<key>");
        let s = rest.find("<string>");
        let (tag, open, close, at) = match (k, s) {
            (Some(k), Some(s)) if k < s => ("key", "<key>", "</key>", k),
            (Some(k), None) => ("key", "<key>", "</key>", k),
            (_, Some(s)) => ("string", "<string>", "</string>", s),
            (None, None) => break,
        };
        let body = &rest[at + open.len()..];
        let Some(end) = body.find(close) else { break };
        out.push((tag, xml_unescape(body[..end].trim())));
        rest = &body[end + close.len()..];
        if out.len() > 10_000 {
            break;
        }
    }
    out
}

/// OLLAMA_HOST in an XML launchd plist, and whether the job is Ollama's: an
/// `EnvironmentVariables` `<key>OLLAMA_HOST</key><string>v</string>`, or a
/// ProgramArguments `launchctl setenv OLLAMA_HOST v` (the common agent that exports it
/// for the app; that form counts as the server's own setting).
pub fn launchd_ollama_host(text: &str) -> (Option<String>, bool) {
    if text.starts_with("bplist00") {
        return (None, false);
    }
    let toks = plist_tokens(text);
    let mut value = None;
    let mut service = false;
    for (i, (tag, v)) in toks.iter().enumerate() {
        if *tag == "key" && v == "OLLAMA_HOST"
            && let Some(("string", val)) = toks.get(i + 1).map(|(t, v)| (*t, v))
        {
            value = Some(val.clone());
        }
        if *tag == "string" && v == "setenv"
            && let (Some(("string", k)), Some(("string", val))) =
                (toks.get(i + 1).map(|(t, v)| (*t, v.as_str())), toks.get(i + 2).map(|(t, v)| (*t, v)))
            && k == "OLLAMA_HOST"
        {
            value = Some(val.clone());
            service = true;
        }
        // ProgramArguments of the server: `.../ollama` followed by `serve`, or the
        // macOS app bundle. A job that merely mentions ollama is a client.
        if *tag == "string"
            && (v.contains("Ollama.app/")
                || (v.rsplit('/').next() == Some("ollama")
                    && toks.get(i + 1).is_some_and(|(t, a)| *t == "string" && a == "serve")))
        {
            service = true;
        }
    }
    (value, service)
}

/// launchd jobs that set OLLAMA_HOST. Each `(dir, all_plists)`: the user's own
/// LaunchAgents are all read; the system directories only for files whose name
/// contains "ollama". XML plists only (binary plists are skipped).
pub fn scan_launchd(dirs: &[(PathBuf, bool)]) -> Vec<ShellConfig> {
    let mut out = Vec::new();
    for (dir, all) in dirs {
        if !dir.is_dir() {
            crate::scanners::telemetry::note_probe(dir, false);
            continue;
        }
        let Ok(entries) = crate::scanners::probe_read_dir(dir) else { continue };
        let mut names: Vec<String> = entries
            .flatten()
            .filter_map(|e| e.file_name().to_str().map(String::from))
            .filter(|n| n.ends_with(".plist"))
            .filter(|n| *all || n.to_ascii_lowercase().contains("ollama"))
            .collect();
        names.sort();
        names.truncate(MAX_SERVICE_ENTRIES);
        for n in names {
            let p = dir.join(&n);
            if !regular_file(&p) {
                continue;
            }
            let Some(text) = crate::scanners::read_bounded_nofollow(&p, None) else { continue };
            let (value, svc) = launchd_ollama_host(&text);
            if let Some(v) = value {
                // In the system directories only ollama-named jobs are read at all, and
                // one there that sets OLLAMA_HOST is the server's. In the user's own
                // LaunchAgents the job has to show it runs the server.
                let service = svc || (!*all && n.to_ascii_lowercase().contains("ollama"));
                out.push(ollama_entry("launchd", &p, &v, service));
            }
        }
    }
    out
}
