use proptest::prelude::*;
use rustmachineguard::output::html::html_escape;
use rustmachineguard::scanners::ai_tools::version_gte;
use rustmachineguard::scanners::cloud_credentials::parse_ini_sections;
use rustmachineguard::scanners::extensions::parse_extension_dir_name;
use rustmachineguard::scanners::extract_version;
use rustmachineguard::scanners::mcp::{
    extract_mcp_servers, extract_mcp_servers_toml, extract_mcp_servers_yaml,
};

// ─── extract_version ───────────────────────────────────────

proptest! {
    /// extract_version never panics on arbitrary input.
    #[test]
    fn extract_version_never_panics(s in "\\PC*") {
        let _ = extract_version(&s);
    }

    /// If extract_version returns Some, the result starts with an ASCII digit,
    /// contains a '.', and ends with an alphanumeric char or '.' or '-'.
    #[test]
    fn extract_version_output_well_formed(s in "[a-z ]* v?[0-9]+\\.[0-9]+(\\.[0-9]+)?(-[a-z0-9]+)? [a-z]*") {
        if let Some(v) = extract_version(&s) {
            prop_assert!(v.chars().next().unwrap().is_ascii_digit(),
                "version must start with digit, got: {v}");
            prop_assert!(v.contains('.'),
                "version must contain '.', got: {v}");
            let last = v.chars().last().unwrap();
            prop_assert!(last.is_ascii_alphanumeric() || last == '.' || last == '-',
                "version must end with alnum/dot/dash, got: {v}");
        }
    }

    /// Leading 'v' is always stripped.
    #[test]
    fn extract_version_strips_v_prefix(
        major in 0u32..100,
        minor in 0u32..100,
        patch in 0u32..100,
    ) {
        let input = format!("tool v{major}.{minor}.{patch} built");
        let v = extract_version(&input).unwrap();
        prop_assert!(!v.starts_with('v'), "v prefix not stripped: {v}");
        prop_assert_eq!(v, format!("{major}.{minor}.{patch}"));
    }

    /// Idempotence: extracting from an already-extracted version yields the same result.
    #[test]
    fn extract_version_idempotent(
        major in 0u32..999,
        minor in 0u32..999,
        patch in 0u32..999,
    ) {
        let version = format!("{major}.{minor}.{patch}");
        let first = extract_version(&version);
        if let Some(ref v) = first {
            let second = extract_version(v);
            prop_assert_eq!(&first, &second, "not idempotent");
        }
    }
}

// ─── parse_extension_dir_name ──────────────────────────────

proptest! {
    /// parse_extension_dir_name never panics on arbitrary UTF-8 input.
    #[test]
    fn parse_ext_dir_never_panics(s in "\\PC*") {
        let _ = parse_extension_dir_name(&s);
    }

    /// If input has no '-' followed by a digit, the result is None.
    #[test]
    fn parse_ext_dir_no_hyphen_digit_is_none(s in "[a-zA-Z.]+") {
        prop_assert!(parse_extension_dir_name(&s).is_none());
    }

    /// Roundtrip: id + "-" + version reconstructs the original input.
    #[test]
    fn parse_ext_dir_roundtrip(
        publisher in "[a-z]{2,10}",
        name in "[a-z]{2,10}",
        major in 0u32..100,
        minor in 0u32..100,
        patch in 0u32..100,
    ) {
        let input = format!("{publisher}.{name}-{major}.{minor}.{patch}");
        let (id, version) = parse_extension_dir_name(&input).unwrap();
        prop_assert_eq!(format!("{id}-{version}"), input);
    }
}

// ─── extract_mcp_servers ───────────────────────────────────

proptest! {
    /// Output is always sorted and deduplicated.
    #[test]
    fn mcp_servers_sorted_deduped(
        keys1 in prop::collection::vec("[a-z]{1,8}", 0..10),
        keys2 in prop::collection::vec("[a-z]{1,8}", 0..10),
    ) {
        let mut map1 = serde_json::Map::new();
        for k in &keys1 {
            map1.insert(k.clone(), serde_json::Value::Object(Default::default()));
        }
        let mut map2 = serde_json::Map::new();
        for k in &keys2 {
            map2.insert(k.clone(), serde_json::Value::Object(Default::default()));
        }

        let json = serde_json::json!({
            "mcpServers": serde_json::Value::Object(map1),
            "context_servers": serde_json::Value::Object(map2),
        });

        let result = extract_mcp_servers(&json);

        // Must be sorted
        for window in result.windows(2) {
            prop_assert!(window[0] <= window[1], "not sorted: {:?}", result);
        }

        // Must be deduplicated
        let mut deduped = result.clone();
        deduped.dedup();
        prop_assert_eq!(&result, &deduped, "has duplicates");

        // Must contain all keys from both maps
        let mut expected: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        expected.extend(keys1);
        expected.extend(keys2);
        let result_set: std::collections::BTreeSet<String> = result.into_iter().collect();
        prop_assert_eq!(result_set, expected);
    }

    /// Non-object values for mcpServers produce no names.
    #[test]
    fn mcp_servers_non_object_ignored(val in prop_oneof![
        Just(serde_json::Value::Null),
        Just(serde_json::Value::Bool(true)),
        Just(serde_json::Value::Number(42.into())),
        Just(serde_json::Value::String("foo".into())),
        Just(serde_json::Value::Array(vec![])),
    ]) {
        let json = serde_json::json!({"mcpServers": val});
        let result = extract_mcp_servers(&json);
        prop_assert!(result.is_empty(), "non-object should produce empty: {:?}", result);
    }
}

// ─── parse_ini_sections ────────────────────────────────────

proptest! {
    /// Every returned section name was enclosed in brackets in the input.
    #[test]
    fn ini_sections_match_brackets(
        sections in prop::collection::vec("[a-zA-Z0-9_ ]{1,20}", 1..10),
    ) {
        let content: String = sections
            .iter()
            .map(|s| format!("[{s}]\nkey=value\n"))
            .collect();
        let result = parse_ini_sections(&content);
        prop_assert_eq!(result.len(), sections.len());
        for (got, expected) in result.iter().zip(sections.iter()) {
            prop_assert_eq!(got, expected);
        }
    }

    /// Empty brackets [] produce no entry (we require len > 2).
    #[test]
    fn ini_empty_brackets_ignored(
        prefix in "[a-z ]{0,20}",
        suffix in "[a-z ]{0,20}",
    ) {
        let content = format!("{prefix}\n[]\n{suffix}");
        let result = parse_ini_sections(&content);
        prop_assert!(
            result.is_empty(),
            "empty brackets should produce nothing: {:?}", result
        );
    }

    /// Lines without matching brackets produce nothing.
    #[test]
    fn ini_mismatched_brackets_ignored(s in "[a-zA-Z0-9=_ ]{1,40}") {
        // No brackets at all
        let result = parse_ini_sections(&s);
        prop_assert!(result.is_empty());

        // Only opening bracket
        let result = parse_ini_sections(&format!("[{s}"));
        prop_assert!(result.is_empty());

        // Only closing bracket
        let result = parse_ini_sections(&format!("{s}]"));
        prop_assert!(result.is_empty());
    }
}

// ─── html_escape ───────────────────────────────────────────

proptest! {
    /// html_escape output never contains raw <, >, or unescaped & or quotes.
    #[test]
    fn html_escape_no_raw_dangerous_chars(s in "\\PC*") {
        let escaped = html_escape(&s);
        for c in escaped.chars() {
            prop_assert!(c != '<', "raw < in output");
            prop_assert!(c != '>', "raw > in output");
        }
        // Every '&' must be part of a known entity
        let without_entities = escaped
            .replace("&amp;", "")
            .replace("&lt;", "")
            .replace("&gt;", "")
            .replace("&quot;", "")
            .replace("&#x27;", "");
        prop_assert!(
            !without_entities.contains('&'),
            "unescaped & in output: {escaped}"
        );
    }

    /// html_escape is safe for attribute contexts (no unescaped quotes).
    #[test]
    fn html_escape_safe_for_attributes(s in "\\PC*") {
        let escaped = html_escape(&s);
        let without_entities = escaped
            .replace("&quot;", "")
            .replace("&#x27;", "");
        prop_assert!(!without_entities.contains('"'), "raw \" in output");
        prop_assert!(!without_entities.contains('\''), "raw ' in output");
    }
}

// ─── classify_key ──────────────────────────────────────────

#[test]
fn classify_key_no_private_key_header_means_not_a_key() {
    use rustmachineguard::scanners::ssh_keys::classify_key;
    let inputs = [
        "some random text",
        "-----BEGIN CERTIFICATE-----",
        "-----BEGIN PUBLIC KEY-----",
        "ssh-rsa AAAAB3NzaC1yc2...",
        "",
    ];
    for input in inputs {
        let (is_key, _, _) = classify_key(input, input, std::path::Path::new("/dev/null"));
        assert!(!is_key, "should not be a key: {input}");
    }
}

#[test]
fn classify_key_known_headers_produce_correct_types() {
    use rustmachineguard::scanners::ssh_keys::classify_key;
    let cases = [
        ("-----BEGIN RSA PRIVATE KEY-----", "rsa"),
        ("-----BEGIN EC PRIVATE KEY-----", "ecdsa"),
        ("-----BEGIN DSA PRIVATE KEY-----", "dsa"),
        ("-----BEGIN OPENSSH PRIVATE KEY-----", "openssh"),
        ("-----BEGIN PRIVATE KEY-----", "unknown"),
    ];
    for (header, expected_type) in cases {
        let (is_key, key_type, _) = classify_key(header, header, std::path::Path::new("/dev/null"));
        assert!(is_key, "should be a key: {header}");
        assert_eq!(key_type, expected_type, "wrong type for {header}");
    }
}

#[test]
fn classify_key_pem_encrypted_marker_detected() {
    use rustmachineguard::scanners::ssh_keys::classify_key;
    let header = "-----BEGIN RSA PRIVATE KEY-----";
    let content_encrypted =
        "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC\nbase64";
    let content_plain = "-----BEGIN RSA PRIVATE KEY-----\nbase64data";

    let (_, _, has_pp) = classify_key(header, content_encrypted, std::path::Path::new("/dev/null"));
    assert!(has_pp, "should detect ENCRYPTED");

    let (_, _, has_pp) = classify_key(header, content_plain, std::path::Path::new("/dev/null"));
    assert!(!has_pp, "should not detect ENCRYPTED");
}

// ─── compute_summary ───────────────────────────────────────

#[test]
fn summary_counts_match_vector_lengths() {
    use rustmachineguard::models::*;

    let mut report = ScanReport {
        agent_version: "test".to_string(),
        scan_timestamp: 0,
        scan_timestamp_iso: "test".to_string(),
        device: DeviceInfo {
            hostname: "t".into(), os_name: "t".into(), os_version: "t".into(),
            platform: "t".into(), kernel_version: "t".into(),
            user_identity: "t".into(), home_dir: "t".into(),
        },
        ai_agents_and_tools: vec![AiTool {
            name: "x".into(), vendor: "x".into(), tool_type: AiToolType::CliTool,
            version: None, binary_path: None, config_dir: None, install_path: None, is_running: false,
        }],
        ai_frameworks: vec![],
        ide_installations: vec![],
        ide_extensions: vec![
            IdeExtension { id: "a".into(), name: "a".into(), version: "1".into(), publisher: "p".into(), ide_type: "vs".into() },
            IdeExtension { id: "b".into(), name: "b".into(), version: "2".into(), publisher: "p".into(), ide_type: "vs".into() },
        ],
        mcp_configs: vec![],
        node_package_managers: vec![],
        shell_configs: vec![],
        ssh_keys: vec![SshKey { path: "/a".into(), key_type: "rsa".into(), has_passphrase: false, comment: None }],
        cloud_credentials: vec![],
        container_tools: vec![],
        notebook_servers: vec![],
        warnings: vec![],
        summary: Summary {
            ai_agents_and_tools_count: 0, ai_frameworks_count: 0,
            ide_installations_count: 0, ide_extensions_count: 0,
            mcp_configs_count: 0, node_package_managers_count: 0,
            shell_configs_count: 0, ssh_keys_count: 0,
            cloud_credentials_count: 0, container_tools_count: 0,
            notebook_servers_count: 0,
        },
    };

    report.compute_summary();

    assert_eq!(report.summary.ai_agents_and_tools_count, 1);
    assert_eq!(report.summary.ai_frameworks_count, 0);
    assert_eq!(report.summary.ide_extensions_count, 2);
    assert_eq!(report.summary.ssh_keys_count, 1);
}

// ─── JSON roundtrip ────────────────────────────────────────

#[test]
fn json_output_is_valid_json() {
    use rustmachineguard::models::*;

    let mut report = ScanReport {
        agent_version: "0.1.0".to_string(),
        scan_timestamp: 12345,
        scan_timestamp_iso: "2026-01-01T00:00:00Z".to_string(),
        device: DeviceInfo {
            hostname: "test</script><script>alert(1)</script>".into(),
            os_name: "test".into(), os_version: "1.0".into(),
            platform: "test".into(), kernel_version: "5.0".into(),
            user_identity: "user\"with'quotes".into(), home_dir: "/home/test".into(),
        },
        ai_agents_and_tools: vec![],
        ai_frameworks: vec![],
        ide_installations: vec![],
        ide_extensions: vec![],
        mcp_configs: vec![],
        node_package_managers: vec![],
        shell_configs: vec![],
        ssh_keys: vec![],
        cloud_credentials: vec![],
        container_tools: vec![],
        notebook_servers: vec![],
        warnings: vec![ScanWarning { scanner: "test".into(), message: "a warning".into() }],
        summary: Summary {
            ai_agents_and_tools_count: 0, ai_frameworks_count: 0,
            ide_installations_count: 0, ide_extensions_count: 0,
            mcp_configs_count: 0, node_package_managers_count: 0,
            shell_configs_count: 0, ssh_keys_count: 0,
            cloud_credentials_count: 0, container_tools_count: 0,
            notebook_servers_count: 0,
        },
    };
    report.compute_summary();

    let json_str = rustmachineguard::output::json::render(&report);
    let parsed: Result<serde_json::Value, _> = serde_json::from_str(&json_str);
    assert!(parsed.is_ok(), "JSON is not valid: {}", parsed.unwrap_err());
}

/// HTML output with XSS payload in hostname must not contain raw </script>.
#[test]
fn html_output_no_script_injection() {
    use rustmachineguard::models::*;

    let mut report = ScanReport {
        agent_version: "0.1.0".to_string(),
        scan_timestamp: 12345,
        scan_timestamp_iso: "2026-01-01T00:00:00Z".to_string(),
        device: DeviceInfo {
            hostname: "</script><script>alert('xss')</script>".into(),
            os_name: "test".into(), os_version: "1.0".into(),
            platform: "test".into(), kernel_version: "5.0".into(),
            user_identity: "test".into(), home_dir: "/home/test".into(),
        },
        ai_agents_and_tools: vec![],
        ai_frameworks: vec![],
        ide_installations: vec![],
        ide_extensions: vec![],
        mcp_configs: vec![],
        node_package_managers: vec![],
        shell_configs: vec![],
        ssh_keys: vec![],
        cloud_credentials: vec![],
        container_tools: vec![],
        notebook_servers: vec![],
        warnings: vec![],
        summary: Summary {
            ai_agents_and_tools_count: 0, ai_frameworks_count: 0,
            ide_installations_count: 0, ide_extensions_count: 0,
            mcp_configs_count: 0, node_package_managers_count: 0,
            shell_configs_count: 0, ssh_keys_count: 0,
            cloud_credentials_count: 0, container_tools_count: 0,
            notebook_servers_count: 0,
        },
    };
    report.compute_summary();

    let html = rustmachineguard::output::html::render(&report);

    // The only </script> should be the legitimate closing tag
    let script_close_count = html.matches("</script>").count();
    assert_eq!(script_close_count, 1, "XSS: found extra </script> tags in HTML output");

    // No raw <script> injection (the legitimate one is the only one)
    let script_open_count = html.matches("<script>").count();
    assert_eq!(script_open_count, 1, "XSS: found extra <script> tags in HTML output");

    // The XSS payload should be HTML-escaped in the visible text
    assert!(html.contains("&lt;script&gt;"), "XSS payload should be escaped");
    assert!(!html.contains("<script>alert"), "raw script+alert found");
}

// ─── YAML MCP parsing (Open Interpreter) ────────────────────

#[test]
fn yaml_mcp_parses_mcpservers_key() {
    let content = r#"
mcpServers:
  filesystem:
    command: mcp-server-filesystem
  github:
    command: mcp-server-github
"#;
    let servers = extract_mcp_servers_yaml(content);
    assert_eq!(servers, vec!["filesystem", "github"]);
}

#[test]
fn yaml_mcp_parses_nested_mcp_servers() {
    let content = r#"
mcp:
  servers:
    alpha:
      command: a
    beta:
      command: b
"#;
    let servers = extract_mcp_servers_yaml(content);
    assert_eq!(servers, vec!["alpha", "beta"]);
}

#[test]
fn yaml_mcp_invalid_returns_empty() {
    let servers = extract_mcp_servers_yaml("not: valid: yaml: [[[");
    assert!(servers.is_empty());
}

#[test]
fn yaml_mcp_empty_returns_empty() {
    assert!(extract_mcp_servers_yaml("").is_empty());
    assert!(extract_mcp_servers_yaml("other_key: value").is_empty());
}

// ─── TOML MCP parsing (Codex) ───────────────────────────────

#[test]
fn toml_mcp_parses_snake_case_table() {
    let content = r#"
[mcp_servers.filesystem]
command = "mcp-server-filesystem"

[mcp_servers.github]
command = "mcp-server-github"
"#;
    let servers = extract_mcp_servers_toml(content);
    assert_eq!(servers, vec!["filesystem", "github"]);
}

#[test]
fn toml_mcp_parses_camel_case_table() {
    let content = r#"
[mcpServers.alpha]
command = "a"

[mcpServers.beta]
command = "b"
"#;
    let servers = extract_mcp_servers_toml(content);
    assert_eq!(servers, vec!["alpha", "beta"]);
}

#[test]
fn toml_mcp_invalid_returns_empty() {
    let servers = extract_mcp_servers_toml("not valid = = = toml");
    assert!(servers.is_empty());
}

#[test]
fn toml_mcp_no_mcp_keys_returns_empty() {
    assert!(extract_mcp_servers_toml("[other]\nkey = \"value\"").is_empty());
}

// ─── Project-scoped Claude Code .claude.json ────────────────

#[test]
fn json_mcp_extracts_projects_scoped_servers() {
    let json: serde_json::Value = serde_json::from_str(
        r#"
{
  "projects": {
    "/home/user/proj1": {
      "mcpServers": {
        "tool_a": {}, "tool_b": {}
      }
    },
    "/home/user/proj2": {
      "mcpServers": {
        "tool_c": {}
      }
    }
  }
}
"#,
    )
    .unwrap();
    let servers = extract_mcp_servers(&json);
    assert_eq!(servers, vec!["tool_a", "tool_b", "tool_c"]);
}

// ─── version_gte ────────────────────────────────────────────

#[test]
fn version_gte_basic() {
    assert!(version_gte("0.7", (0, 7)));
    assert!(version_gte("0.7.1", (0, 7)));
    assert!(version_gte("1.0.0", (0, 7)));
    assert!(!version_gte("0.6.99", (0, 7)));
    assert!(!version_gte("0.6", (0, 7)));
}

#[test]
fn version_gte_handles_v_prefix() {
    assert!(version_gte("v0.7.0", (0, 7)));
    assert!(version_gte("v1.2", (0, 7)));
}

#[test]
fn version_gte_handles_suffixes() {
    assert!(version_gte("0.7.1-beta", (0, 7)));
    assert!(version_gte("1.0.0+build5", (0, 7)));
}

#[test]
fn version_gte_empty_or_invalid_returns_false() {
    assert!(!version_gte("", (0, 1)));
    assert!(!version_gte("abc", (0, 1)));
}

proptest! {
    /// Version comparison is monotonic: if v1 >= v2 then version_gte(v1, v2) is true.
    #[test]
    fn version_gte_monotonic(
        major_v in 0u32..100,
        minor_v in 0u32..100,
        major_t in 0u32..100,
        minor_t in 0u32..100,
    ) {
        let v = format!("{major_v}.{minor_v}.0");
        let actual = version_gte(&v, (major_t, minor_t));
        let expected = (major_v, minor_v) >= (major_t, minor_t);
        prop_assert_eq!(actual, expected);
    }
}
