//! Machine-wide and tool-global package-manager configs: npm's `$PREFIX/etc/npmrc`, pnpm's
//! global `rc`, pip's global and macOS files, and uv's user and system `uv.toml`. Before
//! this file only `/etc/npmrc` and `/etc/pip.conf` were read (and from the host's real
//! `/etc`, even in tests), uv's user file not at all, and a pip index was called public
//! when its URL merely contained `pypi.org`.
#![cfg(unix)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn write(path: &Path, text: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, text).unwrap();
}

fn scan(home: &Path) -> (String, Vec<(String, String, String)>) {
    let out = Command::new(env!("CARGO_BIN_EXE_rmguard"))
        .args(["--format", "json"])
        .env("HOME", home)
        .env("PATH", "/usr/bin:/bin")
        .env("RMGUARD_TEST_SYSTEM_ROOT", home.join("sysroot"))
        .env("NO_COLOR", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env_remove("CLAUDE_CONFIG_DIR")
        .current_dir(home)
        .output()
        .expect("rmguard runs");
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    let v: serde_json::Value = serde_json::from_str(&text).expect("report json");
    let mut rows = Vec::new();
    for a in v["package_config_audits"].as_array().into_iter().flatten() {
        for f in a["findings"].as_array().into_iter().flatten() {
            rows.push((
                a["manager"].as_str().unwrap().to_string(),
                a["config_path"].as_str().unwrap().to_string(),
                f["description"].as_str().unwrap().to_string(),
            ));
        }
    }
    (text, rows)
}

fn home(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("rmg-pkg-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    fs::canonicalize(&d).unwrap()
}

#[test]
fn global_and_system_configs_of_npm_pnpm_pip_and_uv_are_read() {
    let h = home("global");
    let sys = h.join("sysroot");
    let secret = format!("pw{}", "canary-9f3k");
    write(&sys.join("usr/local/etc/npmrc"), "registry=https://npm.corp.example/\n");
    write(&sys.join("etc/npmrc"), "registry=https://registry.npmjs.org/\n");
    write(
        &h.join(".config/pnpm/rc"),
        "@acme:registry=https://pnpm.corp.example/\n",
    );
    write(
        &sys.join("etc/xdg/pip/pip.conf"),
        &format!("[global]\nindex-url = https://u:{secret}@pip.corp.example/simple\n"),
    );
    write(
        &h.join("Library/Application Support/pip/pip.conf"),
        "[global]\nextra-index-url = https://pypi.org/simple https://second.example/simple\n",
    );
    write(
        &h.join(".config/uv/uv.toml"),
        "allow-insecure-host = [\"insecure.example\"]\n[[index]]\nurl = \"https://uv.corp.example/simple\"\n",
    );
    write(&sys.join("etc/uv/uv.toml"), "index-url = \"https://pypi.org/simple\"\n");
    let (text, rows) = scan(&h);
    let _ = fs::remove_dir_all(&h);
    let has = |manager: &str, file: &str, needle: &str| {
        rows.iter()
            .any(|(m, p, d)| m == manager && p.ends_with(file) && d.contains(needle))
    };
    assert!(has("npm", "usr/local/etc/npmrc", "npm.corp.example"), "{rows:?}");
    assert!(has("npm", ".config/pnpm/rc", "pnpm.corp.example"), "{rows:?}");
    assert!(has("pip", "etc/xdg/pip/pip.conf", "pip.corp.example"), "{rows:?}");
    assert!(
        has("pip", "Application Support/pip/pip.conf", "second.example"),
        "{rows:?}"
    );
    assert!(has("uv", ".config/uv/uv.toml", "uv.corp.example"), "{rows:?}");
    assert!(has("uv", ".config/uv/uv.toml", "insecure.example"), "{rows:?}");
    // The public registry in a system file is not a finding.
    assert!(
        !rows
            .iter()
            .any(|(_, p, _)| p.ends_with("etc/npmrc") && !p.contains("local")),
        "{rows:?}"
    );
    assert!(!rows.iter().any(|(_, p, _)| p.ends_with("etc/uv/uv.toml")), "{rows:?}");
    assert!(!text.contains(&secret), "an index URL's password reached the report");
}

#[test]
fn pip_index_is_public_only_by_its_parsed_host() {
    use rustmachineguard::scanners::package_configs::audit_pip_config;
    let custom = |line: &str| {
        audit_pip_config(line)
            .iter()
            .any(|f| f.description.starts_with("Custom PyPI index"))
    };
    for line in [
        "index-url = https://pypi.org.evil.example/simple",
        "index-url = https://evil.example/pypi.org/simple",
        "index-url = https://pypi.org:x@evil.example/simple",
        "extra-index-url = https://pypi.org/simple https://evil.example/simple",
    ] {
        assert!(custom(line), "{line}");
    }
    for line in [
        "index-url = https://pypi.org/simple",
        "extra-index-url = https://pypi.org/simple/ https://test.pypi.org/simple",
        "timeout = 60",
    ] {
        assert!(!custom(line), "{line}");
    }
}
