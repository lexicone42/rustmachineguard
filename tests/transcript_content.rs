//! End-to-end tests for secret-shaped content in agent transcript stores: the stores are
//! sampled for secret-named KEY NAMES and token-prefix LABELS, never a value
//! (`scanners::transcript_content`). Each test builds a temp HOME, runs the real binary
//! with only the transcript scanners, and reads the JSON report as plain JSON (and
//! through `collect_findings` on a report deserialized from it), so the file compiles
//! against b7747e9 and each test fails there on its assertions: that version reads no
//! transcript content, emits none of the fields, and grades nothing by content.
#![cfg(unix)]

use rustmachineguard::analysis::{Finding, Severity, collect_findings};
use rustmachineguard::models::ScanReport;
use serde_json::Value;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime};

/// Every scanner but the transcript ones (`transcripts`, `vibe`).
const SKIP: &str = "ai,frameworks,ide,extensions,mcp,node,shell,ssh,cloud,containers,notebooks,browser,packages,rules,skills,settings,aicreds,envfiles,marketplaces,vscodetasks,gitconfig,pypkgs,npmpkgs,jbplugins,persistence,liveness,playwright,statusline,listeners";

/// Values planted next to the secret-named keys. None may reach any output.
const KV: &[&str] = &[
    "TsKv1Hunter9Value",
    "TsKv2Hunter8Value",
    "TsKv3Hunter7Value",
    "TsKv4Hunter6Value",
    "TsKv5Hunter5Value",
];
/// Token-shaped values: a GitHub classic PAT (`ghp_` + 36), an AWS access key id
/// (`AKIA` + 16), an Anthropic key, and a PEM private key body.
const GH: &str = "ghp_TsGhCanary0123456789abcdefghijKLMNOP";
const AKIA: &str = "AKIATSCANARY01234567";
const ANT: &str = "sk-ant-api03-TsAntCanary0123456789abcdefghijklmn";
const PEM_BODY: &str = "TsPemCanaryb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ";

/// Every planted value and the parts of the tokens that identify them.
fn canaries() -> Vec<&'static str> {
    let mut c = KV.to_vec();
    c.extend([
        GH,
        "TsGhCanary",
        AKIA,
        "TSCANARY",
        ANT,
        "TsAntCanary",
        PEM_BODY,
        "TsPemCanary",
    ]);
    c
}

/// A fresh temp directory (mode 0755), canonicalized (macOS temp_dir() is under /var).
fn temp_home(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("rmg-tsc-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    chmod(&d, 0o755);
    fs::canonicalize(&d).unwrap()
}

fn write(path: &Path, text: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, text).unwrap();
}

fn chmod(path: &Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

/// `dir_mode` / `file_mode` on everything under `path` and on the directories between it
/// and `home`.
fn chmod_tree(home: &Path, path: &Path, dir_mode: u32, file_mode: u32) {
    for e in walk(path) {
        chmod(&e, if e.is_dir() { dir_mode } else { file_mode });
    }
    let mut a = path.parent();
    while let Some(d) = a {
        if d == home || !d.starts_with(home) {
            break;
        }
        chmod(d, dir_mode);
        a = d.parent();
    }
}

fn walk(p: &Path) -> Vec<PathBuf> {
    let mut out = vec![p.to_path_buf()];
    if fs::symlink_metadata(p).map(|m| m.is_dir()).unwrap_or(false) {
        for e in fs::read_dir(p).unwrap().flatten() {
            out.extend(walk(&e.path()));
        }
    }
    out
}

/// True when a directory above `p` is not traversable by other users (macOS `$TMPDIR`,
/// or CI's re-run under a 0700 parent): reachability-graded findings honestly drop there.
fn blocked_above(p: &Path) -> bool {
    p.ancestors().skip(1).any(|a| {
        fs::metadata(a)
            .map(|m| m.permissions().mode() & 0o001 == 0)
            .unwrap_or(false)
    })
}

/// Run rmguard against `home` with only the transcript scanners: (stdout, stderr).
fn run(home: &Path, args: &[&str]) -> (String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_rmguard"))
        .args(["--skip", SKIP])
        .args(args)
        .env("HOME", home)
        .env("PATH", "/usr/bin:/bin")
        .env("RMGUARD_TEST_SYSTEM_ROOT", home.join("sysroot"))
        .env("NO_COLOR", "1")
        .env_remove("CLAUDE_CONFIG_DIR")
        .env_remove("CODEX_HOME")
        .env_remove("GEMINI_CLI_HOME")
        .env_remove("VIBE_HOME")
        .env_remove("RMGUARD_TRACE")
        .current_dir(home)
        .output()
        .expect("run rmguard");
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// The JSON report as text and as a Value.
fn scan(home: &Path) -> (String, Value) {
    let (text, _) = run(home, &["--format", "json"]);
    let v = serde_json::from_str(&text).expect("report json");
    (text, v)
}

/// Findings of a JSON report, after `edit` (graded as rmguard grades it).
fn findings_of(v: &Value, edit: impl Fn(&mut Value)) -> Vec<Finding> {
    let mut v = v.clone();
    edit(&mut v);
    let report: ScanReport = serde_json::from_value(v).expect("report");
    collect_findings(&report)
}

/// Every store reachable by other users, as if no ancestor above the fixture blocked
/// them (the grading under test, independent of where the temp directory lives).
fn reachable(v: &mut Value) {
    for t in v["transcripts"].as_array_mut().unwrap() {
        t.as_object_mut().unwrap().remove("unreachable_via");
    }
}

/// The report with every transcript-content field removed: what b7747e9 reported.
fn without_shapes(v: &mut Value) {
    for t in v["transcripts"].as_array_mut().unwrap() {
        let o = t.as_object_mut().unwrap();
        for k in [
            "secret_key_names",
            "secret_key_names_truncated",
            "token_prefix_labels",
            "token_shaped_strings",
            "files_with_secret_shapes",
            "other_readable_files_with_secret_shapes",
            "files_sampled",
            "sampling_truncated",
            "scan_home",
        ] {
            o.remove(k);
        }
    }
}

fn dump(findings: &[Finding]) -> String {
    findings
        .iter()
        .map(|f| {
            format!(
                "[{}] {} | {} | {} | {}\n",
                f.severity.label(),
                f.category,
                f.title,
                f.location,
                f.evidence.as_deref().unwrap_or("")
            )
        })
        .collect()
}

/// The store row of `framework` and `kind`.
fn store<'a>(v: &'a Value, framework: &str, kind: &str) -> &'a Value {
    v["transcripts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["framework"] == framework && s["kind"] == kind)
        .unwrap_or_else(|| panic!("no {framework} {kind} store in {}", v["transcripts"]))
}

fn strings(v: &Value) -> Vec<String> {
    v.as_array()
        .map(|a| a.iter().map(|s| s.as_str().unwrap().to_string()).collect())
        .unwrap_or_default()
}

/// A home with a Claude Code conversation store (two files with shapes, one without), a
/// command history with one secret-named key, and a Codex session with a GitHub token.
fn shapes_home(tag: &str) -> PathBuf {
    let home = temp_home(tag);
    let proj = home.join(".claude/projects/-work-app");
    // JSONL as Claude Code writes it: tool output inside JSON strings, `\n` escaped.
    write(
        &proj.join("a1.jsonl"),
        &format!(
            concat!(
                r#"{{"type":"user","message":{{"content":"my .env is\nAWS_SECRET_ACCESS_KEY={k1}\nPORT=3000"}}}}"#,
                "\n",
                r#"{{"type":"tool_result","content":"{{\"GITHUB_TOKEN\": \"{k2}\", \"input_tokens\": 3}}"}}"#,
                "\n",
                r#"{{"type":"assistant","message":{{"content":"run: export OPENAI_API_KEY={k3} && docker run -e DATABASE_URL=postgres://u:{k4}@db/x img"}}}}"#,
                "\n"
            ),
            k1 = KV[0],
            k2 = KV[1],
            k3 = KV[2],
            k4 = KV[3]
        ),
    );
    write(
        &proj.join("a2.jsonl"),
        &format!(
            concat!(
                r#"{{"type":"tool_result","content":"token {gh} key {akia}"}}"#,
                "\n",
                r#"{{"type":"user","message":{{"content":"use \"{ant}\" and\n-----BEGIN OPENSSH PRIVATE KEY-----\n{pem}\n-----END OPENSSH PRIVATE KEY-----"}}}}"#,
                "\n"
            ),
            gh = GH,
            akia = AKIA,
            ant = ANT,
            pem = PEM_BODY
        ),
    );
    write(
        &proj.join("a3.jsonl"),
        r#"{"type":"user","message":{"content":"set the TOKEN in CI; the input_tokens field counts"}}"#,
    );
    write(
        &home.join(".claude/history.jsonl"),
        &format!(
            r#"{{"display":"export STRIPE_SECRET_KEY={}","project":"/work/app"}}"#,
            KV[4]
        ),
    );
    write(
        &home.join(".codex/sessions/2026/10/24/rollout-1.jsonl"),
        &format!(r#"{{"type":"function_call_output","output":"GH {GH}"}}"#),
    );
    home
}

/// Names and labels appear, counts are right, and no planted value appears in the JSON.
/// Fails on b7747e9: no `secret_key_names` / `token_prefix_labels` / counts are emitted.
#[test]
fn key_names_and_token_labels_are_reported_by_name_only() {
    let home = shapes_home("names");
    let (text, v) = scan(&home);
    let conv = store(&v, "claude-code", "conversation transcripts");
    assert_eq!(
        strings(&conv["secret_key_names"]),
        [
            "AWS_SECRET_ACCESS_KEY",
            "DATABASE_URL",
            "GITHUB_TOKEN",
            "OPENAI_API_KEY"
        ],
        "{conv}"
    );
    assert_eq!(
        strings(&conv["token_prefix_labels"]),
        [
            "AWS access key id",
            "Anthropic API key",
            "GitHub token",
            "PEM private key"
        ],
        "{conv}"
    );
    assert_eq!(conv["token_shaped_strings"], 4, "{conv}");
    assert_eq!(conv["files_sampled"], 3, "{conv}");
    assert_eq!(conv["files_with_secret_shapes"], 2, "a3.jsonl has none: {conv}");
    assert!(conv.get("sampling_truncated").is_none(), "{conv}");
    let hist = store(&v, "claude-code", "command history");
    assert_eq!(strings(&hist["secret_key_names"]), ["STRIPE_SECRET_KEY"], "{hist}");
    assert_eq!(hist["files_sampled"], 1);
    let codex = store(&v, "codex", "sessions");
    assert_eq!(strings(&codex["token_prefix_labels"]), ["GitHub token"], "{codex}");
    assert!(codex.get("secret_key_names").is_none(), "{codex}");
    for c in canaries() {
        assert!(!text.contains(c), "a planted value reached the JSON report: {c}");
    }
    let _ = fs::remove_dir_all(&home);
}

/// The user's own stores (0700 directories, 0600 files) with shapes are ONE Low "Secret
/// hygiene" advisory per home naming the stores; nothing is escalated. Fails on b7747e9:
/// no such finding.
#[test]
fn user_only_stores_with_shapes_are_one_low_hygiene_advisory() {
    let home = shapes_home("advisory");
    chmod_tree(&home, &home.join(".claude"), 0o700, 0o600);
    chmod_tree(&home, &home.join(".codex"), 0o700, 0o600);
    let (_, v) = scan(&home);
    let findings = findings_of(&v, reachable);
    let d = dump(&findings);
    let hygiene: Vec<&Finding> = findings.iter().filter(|f| f.category == "Secret hygiene").collect();
    assert_eq!(hygiene.len(), 1, "{d}");
    let f = hygiene[0];
    assert_eq!(f.severity, Severity::Low, "{d}");
    assert_eq!(
        f.title,
        "agent transcripts mention 5 secret-named keys / 5 token-shaped strings; consider rotating anything pasted into a conversation",
        "{d}"
    );
    assert_eq!(f.location, home.display().to_string(), "{d}");
    let ev = f.evidence.as_deref().unwrap();
    assert!(
        ev.contains("/.claude/projects (claude-code conversation transcripts): 2 of 3 sampled files"),
        "{ev}"
    );
    assert!(
        ev.contains("/.codex/sessions (codex sessions): 1 of 1 sampled files"),
        "{ev}"
    );
    assert!(ev.contains("token labels: GitHub token (1 strings)"), "{ev}");
    assert!(ev.contains("key names: STRIPE_SECRET_KEY"), "{ev}");
    assert!(
        !findings.iter().any(|f| f.category == "Transcript exposure"),
        "a user-only store is not exposed: {d}"
    );
    for c in canaries() {
        assert!(!d.contains(c), "a planted value reached a finding: {c}");
    }
    let _ = fs::remove_dir_all(&home);
}

/// A store other users can read AND whose readable files show shapes raises its
/// "Transcript exposure" finding one step and says so: the Claude Code state finding High
/// -> Critical, the Codex session store High -> Critical. The same report without the
/// content fields grades High (the step is the content's). Fails on b7747e9: High, and no
/// "secret-shaped content" in the title.
#[test]
fn world_readable_store_with_shapes_escalates_one_step() {
    let home = shapes_home("escalate");
    chmod_tree(&home, &home.join(".claude"), 0o755, 0o644);
    chmod_tree(&home, &home.join(".codex"), 0o755, 0o644);
    let (_, v) = scan(&home);
    let conv = store(&v, "claude-code", "conversation transcripts");
    assert_eq!(conv["other_readable_files_with_secret_shapes"], 2, "{conv}");

    let before = findings_of(&v, |v| {
        reachable(v);
        without_shapes(v);
    });
    let after = findings_of(&v, reachable);
    let (b, a) = (dump(&before), dump(&after));
    let pick = |fs: &[Finding], prefix: &str| -> Finding {
        fs.iter()
            .find(|f| f.category == "Transcript exposure" && f.title.starts_with(prefix))
            .cloned()
            .unwrap_or_else(|| panic!("no {prefix} finding:\n{}", dump(fs)))
    };
    assert_eq!(pick(&before, "Claude Code state under").severity, Severity::High, "{b}");
    assert_eq!(pick(&before, "codex sessions").severity, Severity::High, "{b}");
    let c = pick(&after, "Claude Code state under");
    assert_eq!(c.severity, Severity::Critical, "{a}");
    assert!(
        c.title.ends_with(
            "and contains secret-shaped content (labels: AWS access key id, Anthropic API key, GitHub token, PEM private key, AWS_SECRET_ACCESS_KEY, DATABASE_URL, GITHUB_TOKEN, OPENAI_API_KEY +1 more)"
        ),
        "{a}"
    );
    let x = pick(&after, "codex sessions");
    assert_eq!(x.severity, Severity::Critical, "{a}");
    assert!(
        x.title
            .ends_with("and contains secret-shaped content (labels: GitHub token)"),
        "{a}"
    );
    assert!(
        !after.iter().any(|f| f.category == "Secret hygiene"),
        "an escalated store is not also an advisory: {a}"
    );
    // Live, where the fixture is reachable: the binary's own report says the same.
    if !blocked_above(&home) {
        let live = findings_of(&v, |_| {});
        let l = pick(&live, "Claude Code state under");
        assert_eq!(l.severity, Severity::Critical, "{}", dump(&live));
    }
    for c in canaries() {
        assert!(!a.contains(c), "a planted value reached a finding: {c}");
    }
    let _ = fs::remove_dir_all(&home);
}

/// A store whose files show no secret-shaped content yields nothing: no advisory, no
/// escalation, no names or labels; `files_sampled` shows it looked. Fails on b7747e9:
/// `files_sampled` is absent (nothing was sampled).
#[test]
fn a_store_with_no_shapes_yields_nothing() {
    let home = temp_home("none");
    let proj = home.join(".claude/projects/-work-app");
    write(
        &proj.join("s.jsonl"),
        r#"{"type":"user","message":{"content":"the TOKEN limit; input_tokens: 3; PORT=3000; PATH=/usr/bin; set GITHUB_TOKEN in CI; sk-learn; hf_hub_download; AKIA_PREFIX"}}"#,
    );
    chmod_tree(&home, &home.join(".claude"), 0o755, 0o644);
    let (_, v) = scan(&home);
    let conv = store(&v, "claude-code", "conversation transcripts");
    assert_eq!(conv["files_sampled"], 1, "{conv}");
    for k in ["secret_key_names", "token_prefix_labels", "files_with_secret_shapes"] {
        assert!(conv.get(k).is_none(), "{k}: {conv}");
    }
    let findings = findings_of(&v, reachable);
    let d = dump(&findings);
    assert!(!findings.iter().any(|f| f.category == "Secret hygiene"), "{d}");
    let f = findings
        .iter()
        .find(|f| f.category == "Transcript exposure")
        .unwrap_or_else(|| panic!("{d}"));
    assert_eq!(f.severity, Severity::High, "{d}");
    assert!(!f.title.contains("secret-shaped"), "{d}");
    let _ = fs::remove_dir_all(&home);
}

/// Bounded reads: at most 200 files, newest first by mtime with ties broken by name, and
/// the first 1 MiB of each; either cap marks `sampling_truncated`. Fails on b7747e9: no
/// `files_sampled`, names or truncation flag.
#[test]
fn sampling_caps_order_and_truncation() {
    let home = temp_home("caps");
    let proj = home.join(".claude/projects/-p");
    let base = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let set_mtime = |p: &Path, t: SystemTime| {
        fs::File::options()
            .write(true)
            .open(p)
            .unwrap()
            .set_modified(t)
            .unwrap();
    };
    // f000..f009 share the oldest mtime; f010..f204 are each a second newer.
    for i in 0..205 {
        let p = proj.join(format!("f{i:03}.jsonl"));
        let text = match i {
            0 => "KEPT_PASSWORD=1\n",
            9 => "DROPPED_PASSWORD=1\n",
            204 => "NEWEST_TOKEN=1\n",
            _ => "{}\n",
        };
        write(&p, text);
        let t = if i < 10 { base } else { base + Duration::from_secs(i) };
        set_mtime(&p, t);
    }
    // One sampled file is longer than the 1 MiB read: a name past it is not seen.
    let big = proj.join("f100.jsonl");
    let mut text = "EARLY_TOKEN=1\n".to_string();
    text.push_str(&"x".repeat(1024 * 1024));
    text.push_str("\nLATE_TOKEN=1\n");
    write(&big, &text);
    set_mtime(&big, base + Duration::from_secs(100));
    let (_, v) = scan(&home);
    let conv = store(&v, "claude-code", "conversation transcripts");
    assert_eq!(conv["file_count"], 205);
    assert_eq!(conv["files_sampled"], 200, "{conv}");
    assert_eq!(conv["sampling_truncated"], true, "{conv}");
    assert_eq!(
        strings(&conv["secret_key_names"]),
        ["EARLY_TOKEN", "KEPT_PASSWORD", "NEWEST_TOKEN"],
        "newest first, ties by name, 1 MiB per file: {conv}"
    );

    // A single-file store cut at 1 MiB is truncated though one file is all of it.
    write(&home.join(".claude/history.jsonl"), &text);
    let (_, v) = scan(&home);
    let h = store(&v, "claude-code", "command history");
    assert_eq!(h["files_sampled"], 1, "{h}");
    assert_eq!(h["sampling_truncated"], true, "{h}");
    assert_eq!(strings(&h["secret_key_names"]), ["EARLY_TOKEN"], "{h}");
    let _ = fs::remove_dir_all(&home);
}

/// Symlinked transcript files and directories are neither followed nor read: the shapes
/// behind them are not reported, and `--trace` shows no read of their targets. Fails on
/// b7747e9: the positive control (the real file's name) is not reported there.
#[test]
fn symlinked_transcripts_are_not_followed() {
    let home = temp_home("links");
    let outside = home.join("outside");
    write(
        &outside.join("secret.jsonl"),
        &format!("LINKED_PASSWORD={}\ntoken {GH}\n", KV[0]),
    );
    write(&outside.join("dir/d.jsonl"), "DIRLINK_PASSWORD=1\n");
    let proj = home.join(".claude/projects/-p");
    write(&proj.join("real.jsonl"), "REAL_TOKEN=1\n");
    std::os::unix::fs::symlink(outside.join("secret.jsonl"), proj.join("link.jsonl")).unwrap();
    std::os::unix::fs::symlink(outside.join("dir"), home.join(".claude/projects/-q")).unwrap();
    let (text, v) = scan(&home);
    let conv = store(&v, "claude-code", "conversation transcripts");
    assert_eq!(strings(&conv["secret_key_names"]), ["REAL_TOKEN"], "{conv}");
    assert!(conv.get("token_prefix_labels").is_none(), "{conv}");
    assert_eq!(conv["files_sampled"], 1, "{conv}");
    assert!(!text.contains(KV[0]) && !text.contains(GH));
    let (_, trace) = run(&home, &["--format", "json", "--trace"]);
    assert!(trace.contains("real.jsonl -> ok"), "positive control: {trace}");
    for target in [
        "outside/secret.jsonl",
        "outside/dir/d.jsonl",
        "link.jsonl -> ok",
        "-q/d.jsonl",
    ] {
        assert!(!trace.contains(target), "{target} was read: {trace}");
    }
    let _ = fs::remove_dir_all(&home);
}

/// `--diff` ignores the content fields: they churn with every session. Two reports that
/// differ only in them diff empty. (Passes on b7747e9 by construction; it guards the
/// choice.)
#[test]
fn diff_ignores_the_content_fields() {
    let home = shapes_home("diff");
    let (_, v) = scan(&home);
    let mut quiet = v.clone();
    without_shapes(&mut quiet);
    let d = rustmachineguard::diff::diff_reports(&quiet, &v);
    assert!(d.is_empty(), "{}", rustmachineguard::diff::render_diff(&d));
    let _ = fs::remove_dir_all(&home);
}

/// session-env readable by others is already High for exporting a secret-named variable
/// (graded by its exported NAMES); its content sample reports the same name but does not
/// raise the finding a second time. Fails on b7747e9: no `secret_key_names` on the row.
#[test]
fn session_env_names_are_not_counted_twice() {
    let home = temp_home("sessenv");
    write(
        &home.join(".claude/session-env/s1/sessionstart-hook-0.sh"),
        &format!("export GITHUB_TOKEN={}\n", KV[0]),
    );
    chmod_tree(&home, &home.join(".claude"), 0o755, 0o644);
    let (text, v) = scan(&home);
    let row = store(&v, "claude-code", "session environment");
    assert_eq!(strings(&row["secret_key_names"]), ["GITHUB_TOKEN"], "{row}");
    let findings = findings_of(&v, reachable);
    let d = dump(&findings);
    let f = findings
        .iter()
        .find(|f| f.category == "Transcript exposure")
        .unwrap_or_else(|| panic!("{d}"));
    assert_eq!(f.severity, Severity::High, "{d}");
    assert!(!f.title.contains("secret-shaped"), "{d}");
    assert!(!findings.iter().any(|f| f.category == "Secret hygiene"), "{d}");
    assert!(!text.contains(KV[0]));
    let _ = fs::remove_dir_all(&home);
}
