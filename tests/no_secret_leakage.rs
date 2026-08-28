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
