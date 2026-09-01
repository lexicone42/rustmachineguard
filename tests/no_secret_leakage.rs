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

    // A secret shape that cannot occur inside the [a-z./-] filler tokens, so a
    // `contains` check can never be fooled by coincidence.
    const SECRET: &str = "[0-9]{4}[A-Z]{4}[a-z0-9]{4,20}";
    const FILLER: &str = "[a-z./-]{0,12}";

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
