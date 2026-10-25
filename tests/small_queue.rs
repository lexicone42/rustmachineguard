//! Small queue: generic secret-hygiene guidance, whole-word `KEY` in the `.env` (and
//! transcript) secret-name classifier, the advisory-severity backfill, and the posture
//! fields `--diff` compares.
//!
//! The file compiles against 248452b and fails there on its assertions: the guidance
//! names only `.env` files, `KEYBOARD`/`KEYWORD`/`HOTKEY`/`MONKEY`/`TURKEY` are secret
//! names, the backfilled rows have no `advisory_severity`, and a baseline differing only
//! in an MCP server's `awaits_approval` diffs as "no changes".

use rustmachineguard::analysis::guidance;
use rustmachineguard::catalogs::BUILTIN_CATALOG;
use rustmachineguard::diff::diff_reports;
use rustmachineguard::scanners::env_files::is_secret_env_key_name;
use rustmachineguard::scanners::transcript_content::is_secret_name;
use serde_json::{Value, json};

// ── Q1: the "Secret hygiene" guidance covers every source it is shown for ──────────────

#[test]
fn q1_secret_hygiene_guidance_names_env_files_and_transcripts() {
    let g = guidance("Secret hygiene");
    let all = format!("{} {} {}", g.what, g.why, g.fix);
    assert!(
        g.what.contains("env files") && g.what.contains("agent transcripts"),
        "{}",
        g.what
    );
    // One sentence per source in what was found, and the fix for each.
    assert!(
        g.what.contains("A .env that is git-tracked or world-readable"),
        "{}",
        g.what
    );
    assert!(
        g.what.contains("Agent transcripts that mention secret-named keys"),
        "{}",
        g.what
    );
    assert!(g.fix.contains("chmod 600"), "{}", g.fix);
    assert!(
        g.fix
            .contains("rotate any credential that was pasted into or printed in a conversation"),
        "{}",
        g.fix
    );
    assert!(g.fix.contains("secret manager"), "{}", g.fix);
    assert!(all.contains("never values"), "{all}");
}

// ── Q2: KEY as a word in the .env and transcript secret-name rule ─────────────────────

#[test]
fn q2_env_secret_names_match_key_as_a_word() {
    for no in [
        "KEYBOARD",
        "KEYWORD",
        "KEYWORDS",
        "HOTKEY",
        "MONKEY",
        "TURKEY",
        "KEYBOARD_LAYOUT",
        "keyboardLayout",
        "KEY_ID",
        "API_KEY_ID",
        "AWS_ACCESS_KEY_ID",
        "PRIVATE_KEY_PATH",
    ] {
        assert!(!is_secret_env_key_name(no), "{no} should not be a secret name");
        assert!(!is_secret_name(no), "{no} should not be a transcript secret name");
    }
    for yes in [
        "API_KEY",
        "apiKey",
        "SECRET_KEY",
        "sshkey",
        "PRIVKEY",
        "keyPem",
        "APIKEY",
        "KEY",
        "API_KEY2",
        "OPENAI_API_KEY",
        "AWS_SECRET_ACCESS_KEY",
        "SECRET_KEY_BASE",
        "API_KEY_ROTATED",
        "TLS_PRIVATE_KEY_PEM",
        "KEYTEXT",
        "KEYPHRASE",
        // A long hint other than KEY still matches as a substring.
        "GITHUBTOKEN",
        "KEYBOARD_PASSWORD",
    ] {
        assert!(is_secret_env_key_name(yes), "{yes} should be a secret name");
    }
}

// ── Q4: advisory_severity on the older vulnerable-range rows ─────────────────────────

#[test]
fn q4_backfilled_rows_carry_their_advisory_severity() {
    let rows: Vec<Value> = serde_json::from_str(BUILTIN_CATALOG).unwrap();
    let sev = |name: &str, range: &str| -> Option<String> {
        let row = rows
            .iter()
            .find(|r| r["name"] == name && r["version_range"] == range)
            .unwrap_or_else(|| panic!("no row {name} {range}"));
        row.get("advisory_severity").and_then(|v| v.as_str()).map(String::from)
    };
    for (name, range, want) in [
        ("mcp", "<1.30.0", "high"),
        ("mcp", ">=2.0.0, <2.2.0", "high"),
        ("mistral-vibe", ">=1.3.4, <2.25.4", "critical"),
        ("@modelcontextprotocol/server", ">=2.0.0, <2.3.0", "high"),
        ("@modelcontextprotocol/node", ">=2.0.0, <2.1.0", "high"),
        ("@modelcontextprotocol/sdk", "<1.32.0", "high"),
        ("fastmcp", ">=2.10.0, <3.4.10", "critical"),
        ("fastmcp", ">=4.0.0, <4.1.2", "critical"),
        ("hermes-agent", ">=0.18.2, <0.21.1", "high"),
        ("@modelcontextprotocol/inspector", "<1.0.3", "critical"),
        ("@modelcontextprotocol/inspector", ">=2.0.0, <2.12.0", "high"),
        ("@mcpjam/inspector", "<1.4.3", "critical"),
    ] {
        assert_eq!(sev(name, range).as_deref(), Some(want), "{name} {range}");
    }
    // The hermes-agent row cites GitHub's record for CVE-2026-71963.
    let hermes = rows.iter().find(|r| r["name"] == "hermes-agent").unwrap();
    assert!(hermes["advisory"].as_str().unwrap().contains("GHSA-cc88-9pxf-j2wv"));
}

// ── Q5: --diff compares posture fields, not counters ──────────────────────────────────

fn report_with_server(extra: Value) -> Value {
    let mut server = json!({"name": "proj-server", "transport": "stdio"});
    for (k, v) in extra.as_object().unwrap() {
        server[k] = v.clone();
    }
    json!({
        "mcp_configs": [{"config_source": "project", "config_path": "/p/.mcp.json", "servers": [server]}],
        "transcripts": [{"framework": "claude-code", "path": "/h/.claude/projects", "kind": "conversation transcripts",
                         "files_sampled": 200, "token_shaped_strings": 3}],
    })
}

#[test]
fn q5_awaits_approval_is_a_change() {
    let base = report_with_server(json!({"awaits_approval": true}));
    let cur = report_with_server(json!({"approved": true}));
    let d = diff_reports(&base, &cur);
    let mcp = d.sections.iter().find(|s| s.name == "MCP Servers").unwrap();
    let changes: Vec<&String> = mcp.changed.iter().flat_map(|c| &c.changes).collect();
    assert!(
        changes.iter().any(|c| c.starts_with("awaits_approval: true -> ")),
        "{changes:?}"
    );
    assert!(changes.iter().any(|c| c.starts_with("approved: ")), "{changes:?}");
    // Only the flip of awaits_approval, nothing else differing.
    let base = report_with_server(json!({"awaits_approval": true}));
    let cur = report_with_server(json!({}));
    assert!(!diff_reports(&base, &cur).is_empty());
}

#[test]
fn q5_counters_and_samples_are_not_changes() {
    let base = report_with_server(json!({}));
    let mut cur = report_with_server(json!({}));
    cur["transcripts"][0]["files_sampled"] = json!(17);
    cur["transcripts"][0]["token_shaped_strings"] = json!(40);
    assert!(diff_reports(&base, &cur).is_empty());

    // A listener's pid and age, an .env's key count, an output directory's file count:
    // churn. Its shell bridging, world-readability and git state: posture.
    let listener = |pid: u32, shell: &str| {
        json!({"bind": "all-interfaces", "address": "0.0.0.0", "port": 7681, "pid": pid, "age_days": pid,
               "program": "ttyd", "serves_shell": shell})
    };
    let env =
        |keys: u32, wr: bool| json!({"path": "/p/.env", "git_tracked": false, "world_readable": wr, "key_count": keys});
    let out = |files: u32, tracked: u32| {
        json!({"framework": "playwright-mcp", "path": "/p/.playwright-mcp", "file_count": files,
               "tracked_files": tracked, "in_repo": true, "ignored": false})
    };
    let rep =
        |l: Value, e: Value, o: Value| json!({"network_listeners": [l], "env_files": [e], "agent_output_dirs": [o]});
    let base = rep(listener(100, "none"), env(3, false), out(5, 0));
    let churn = rep(listener(200, "none"), env(9, false), out(50, 0));
    assert!(
        diff_reports(&base, &churn).is_empty(),
        "{:?}",
        diff_reports(&base, &churn).sections
    );
    let posture = rep(listener(200, "tmux-child"), env(9, true), out(50, 2));
    let d = diff_reports(&base, &posture);
    let changed = |name: &str| -> Vec<String> {
        d.sections
            .iter()
            .find(|s| s.name == name)
            .map(|s| s.changed.iter().flat_map(|c| c.changes.clone()).collect())
            .unwrap_or_default()
    };
    assert_eq!(changed("Network Listeners"), ["serves_shell: none -> tmux-child"]);
    assert_eq!(changed(".env Files"), ["world_readable: false -> true"]);
    assert_eq!(changed("Agent Output Dirs"), ["git_state: not ignored -> tracked"]);
}

#[test]
fn q5_settings_compare_graded_rules_and_mode_guards() {
    let settings = |rules: Value, bypass: bool| {
        json!({"agent_settings": [{"path": "/h/.claude/settings.json", "source": "user-global", "framework": "claude-code",
            "git_tracked": false, "allow_rules": 2, "deny_rules": 0, "auto_approve_mcp": false,
            "permission_rules": rules, "disable_bypass_mode": bypass}]})
    };
    let graded = json!({"list": "allow", "rule": "Bash", "class": "code-execution"});
    let plain = |r: &str| json!({"list": "allow", "rule": r});
    // Unclassified rules and their order are inventory.
    let a = settings(json!([plain("Read(./src/**)"), graded.clone()]), true);
    let b = settings(json!([graded.clone(), plain("Edit(./docs/**)")]), true);
    assert!(diff_reports(&a, &b).is_empty());
    // A graded rule appearing, or the bypass guard lifted, is drift.
    let c = settings(json!([plain("Read(./src/**)")]), false);
    let d = diff_reports(&a, &c);
    let changes: Vec<String> = d
        .sections
        .iter()
        .find(|s| s.name == "Agent Settings")
        .unwrap()
        .changed
        .iter()
        .flat_map(|c| c.changes.clone())
        .collect();
    assert!(
        changes.iter().any(|c| c == "disable_bypass_mode: true -> false"),
        "{changes:?}"
    );
    assert!(
        changes
            .iter()
            .any(|c| c.starts_with("permission_rules: [\"allow Bash (code-execution)\"] -> null")),
        "{changes:?}"
    );
}
