//! SSH key passphrase state is read from the key file's header alone (the first line and
//! at most 32 characters after it), with no program run. Checked here against keys the
//! system `ssh-keygen` writes, in every format it offers; the byte-exact read bound is
//! `key_head_reader_never_reads_past_the_header` in tests/property_tests.rs.
//!
//! The test generates throwaway keys in a temporary home; it is skipped when the machine
//! has no `ssh-keygen`.
#![cfg(unix)]

use std::path::Path;
use std::process::Command;

fn keygen() -> Option<&'static str> {
    ["/usr/bin/ssh-keygen", "/bin/ssh-keygen", "/usr/local/bin/ssh-keygen"]
        .into_iter()
        .find(|p| Path::new(p).is_file())
}

#[test]
fn passphrase_state_matches_what_ssh_keygen_wrote_and_ssh_keygen_is_never_run() {
    let Some(keygen) = keygen() else {
        eprintln!("skipped: no ssh-keygen on this machine");
        return;
    };
    let home = std::env::temp_dir().join(format!("rmg-sshhead-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    let ssh = home.join(".ssh");
    std::fs::create_dir_all(&ssh).unwrap();
    let home = std::fs::canonicalize(&home).unwrap();
    let ssh = home.join(".ssh");
    // (file, type args, format args, passphrase, expected key_type, expected state)
    let pass = format!("throwaway-{}", std::process::id());
    let cases: Vec<(&str, Vec<&str>, &str, &str, &str)> = vec![
        ("ed_plain", vec!["-t", "ed25519"], "", "openssh", "no_passphrase"),
        ("ed_locked", vec!["-t", "ed25519"], &pass, "openssh", "encrypted"),
        (
            "rsa_new_plain",
            vec!["-t", "rsa", "-b", "2048"],
            "",
            "openssh",
            "no_passphrase",
        ),
        (
            "rsa_pem_plain",
            vec!["-t", "rsa", "-b", "2048", "-m", "PEM"],
            "",
            "rsa",
            "no_passphrase",
        ),
        (
            "rsa_pem_locked",
            vec!["-t", "rsa", "-b", "2048", "-m", "PEM"],
            &pass,
            "rsa",
            "encrypted",
        ),
        (
            "ec_pem_plain",
            vec!["-t", "ecdsa", "-m", "PEM"],
            "",
            "ecdsa",
            "no_passphrase",
        ),
        (
            "ec_pem_locked",
            vec!["-t", "ecdsa", "-m", "PEM"],
            &pass,
            "ecdsa",
            "encrypted",
        ),
        (
            "rsa_p8_plain",
            vec!["-t", "rsa", "-b", "2048", "-m", "PKCS8"],
            "",
            "unknown",
            "no_passphrase",
        ),
        (
            "rsa_p8_locked",
            vec!["-t", "rsa", "-b", "2048", "-m", "PKCS8"],
            &pass,
            "unknown",
            "encrypted",
        ),
    ];
    let mut made = Vec::new();
    for (name, args, passphrase, key_type, state) in &cases {
        let ok = Command::new(keygen)
            .args(args)
            .args(["-q", "-N", passphrase, "-C", "test", "-f"])
            .arg(ssh.join(name))
            .status()
            .is_ok_and(|s| s.success());
        // An OpenSSH build may refuse a format (PKCS8 private keys need a recent one).
        if ok {
            made.push((*name, *key_type, *state));
        }
    }
    assert!(made.len() >= 5, "ssh-keygen wrote only {made:?}");

    // A fake ssh-keygen first on PATH that leaves a marker if anything runs it.
    let fake = home.join("fakebin");
    std::fs::create_dir_all(&fake).unwrap();
    let marker = home.join("ran");
    std::fs::write(
        fake.join("ssh-keygen"),
        format!("#!/bin/sh\necho ran > '{}'\n", marker.display()),
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(fake.join("ssh-keygen"), std::fs::Permissions::from_mode(0o755)).unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_rmguard"))
        .args(["--format", "json", "--skip", "ai,frameworks,ide,extensions,mcp,node,shell,authkeys,cloud,containers,notebooks,browser,packages,rules,skills,settings,aicreds,envfiles,transcripts,marketplaces,vscodetasks,gitconfig,pypkgs,npmpkgs,jbplugins,persistence,lsp,liveness,playwright,vibe,statusline,listeners,agents"])
        .env("HOME", &home)
        .env("PATH", format!("{}:/usr/bin:/bin", fake.display()))
        .env("NO_COLOR", "1")
        .current_dir(&home)
        .output()
        .expect("run rmguard");
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json");
    let keys = v["ssh_keys"].as_array().expect("ssh_keys");
    for (name, key_type, state) in &made {
        let row = keys
            .iter()
            .find(|k| {
                k["path"]
                    .as_str()
                    .is_some_and(|p| p.ends_with(&format!("/.ssh/{name}")))
            })
            .unwrap_or_else(|| panic!("{name} not inventoried: {keys:?}"));
        assert_eq!(row["key_type"], *key_type, "{name}");
        assert_eq!(row["has_passphrase"], *state, "{name}");
        assert_eq!(row["comment"], "test", "{name}: comment from the .pub file");
    }
    // The .pub files are not private keys.
    assert_eq!(keys.len(), made.len(), "{keys:?}");
    assert!(!marker.exists(), "ssh-keygen was run");
    // The ssh scanner spawned nothing at all: its diagnostics row read only files.
    let _ = std::fs::remove_dir_all(&home);
}
