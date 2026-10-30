//! Credentials files read by head only (K1) and project package-manager configs (K2).
//!
//! K1: a gcloud service-account key is classified from its first 4 KiB; a key whose
//! `"type"` lies past that head is reported as an unclassified JSON file, not read on.
//! On the base, every `~/.config/gcloud/*.json` was read whole, so the late-type file
//! was counted as a service-account key.
//!
//! K2: a project's `.npmrc`, `.yarnrc`, `.yarnrc.yml`, `bunfig.toml`, `uv.toml`,
//! `[tool.uv]`, a venv's `pip.conf` and `.cargo/config.toml` are inventoried (hosts and
//! setting NAMES only) and graded. On the base no project package-manager config was read,
//! so every risky fixture here produced no row and no finding.
#![cfg(unix)]

use rustmachineguard::analysis::{Finding, Severity, collect_findings};
use rustmachineguard::models::ScanReport;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const ALL_LABELS: &[&str] = &[
    "ai",
    "frameworks",
    "ide",
    "extensions",
    "mcp",
    "node",
    "shell",
    "ssh",
    "authkeys",
    "cloud",
    "containers",
    "notebooks",
    "browser",
    "packages",
    "rules",
    "skills",
    "settings",
    "aicreds",
    "envfiles",
    "transcripts",
    "marketplaces",
    "vscodetasks",
    "gitconfig",
    "pypkgs",
    "npmpkgs",
    "jbplugins",
    "persistence",
    "lsp",
    "liveness",
    "playwright",
    "vibe",
    "statusline",
    "listeners",
    "agents",
];

fn temp_home(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("rmg-pk-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    fs::canonicalize(&d).unwrap()
}

fn write(path: &Path, text: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, text).unwrap();
}

fn scan(home: &Path, keep: &[&str]) -> (String, ScanReport) {
    let skip: Vec<&str> = ALL_LABELS.iter().copied().filter(|l| !keep.contains(l)).collect();
    let out = Command::new(env!("CARGO_BIN_EXE_rmguard"))
        .args(["--format", "json", "--skip", &skip.join(",")])
        .env("HOME", home)
        .env("PATH", "/usr/bin:/bin")
        .env("RMGUARD_TEST_SYSTEM_ROOT", home.join("sysroot"))
        .env("NO_COLOR", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env_remove("CLAUDE_CONFIG_DIR")
        .env_remove("RMGUARD_TRACE")
        .current_dir(home)
        .output()
        .expect("run rmguard");
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    let report: ScanReport = serde_json::from_str(&text).expect("report json");
    (text, report)
}

fn git(dir: &Path, home: &Path, args: &[&str]) -> bool {
    Command::new("git")
        .args(args)
        .current_dir(dir)
        .env("PATH", "/usr/bin:/bin")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("HOME", home)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// A git repository at `dir`; false when git is unavailable.
fn git_repo(dir: &Path, home: &Path) -> bool {
    fs::create_dir_all(dir).unwrap();
    git(dir, home, &["init", "-q"])
        && git(dir, home, &["config", "user.email", "t@example.com"])
        && git(dir, home, &["config", "user.name", "t"])
}

fn commit_all(dir: &Path, home: &Path) {
    assert!(git(dir, home, &["add", "-A"]));
    assert!(git(dir, home, &["commit", "-q", "-m", "x"]));
}

fn register(home: &Path, projects: &[&Path]) {
    let keys: Vec<String> = projects.iter().map(|p| format!("\"{}\":{{}}", p.display())).collect();
    write(
        &home.join(".claude.json"),
        &format!("{{\"projects\":{{{}}}}}", keys.join(",")),
    );
}

/// Findings located at `path`.
fn at<'a>(fs: &'a [Finding], path: &Path) -> Vec<&'a Finding> {
    let p = path.display().to_string();
    fs.iter().filter(|f| f.location == p).collect()
}

fn has(fs: &[&Finding], sev: Severity, cat: &str) -> bool {
    fs.iter().any(|f| f.severity == sev && f.category == cat)
}

// ── K1 ────────────────────────────────────────────────────────────────────────────

#[test]
fn gcloud_key_with_type_past_the_head_is_unclassified_not_read_on() {
    let home = temp_home("gcloud");
    let gc = home.join(".config/gcloud");
    let canary = format!("{}{}", "PKCANARY", "PRIVATEKEYBODY");
    // Google's layout: type first, private_key later; padded past 4 KiB.
    write(
        &gc.join("first.json"),
        &format!(
            "{{\"type\": \"service_account\", \"private_key_id\": \"k\", \"pad\": \"{}\", \"private_key\": \"{canary}\"}}",
            "a".repeat(5000)
        ),
    );
    // A key whose type is only past the head: not classified, and not read further.
    write(
        &gc.join("late.json"),
        &format!(
            "{{\"pad\": \"{}\", \"type\": \"service_account\", \"private_key\": \"{canary}\"}}",
            "b".repeat(5000)
        ),
    );
    let (text, report) = scan(&home, &["cloud"]);
    let _ = fs::remove_dir_all(&home);
    assert!(!text.contains(&canary));
    let gcp = report
        .cloud_credentials
        .iter()
        .find(|c| c.provider == "GCP")
        .expect("GCP row");
    assert!(
        gcp.credential_type.contains("1 service account key(s)"),
        "{}",
        gcp.credential_type
    );
    assert!(
        gcp.credential_type.contains("1 unclassified JSON file(s)"),
        "{}",
        gcp.credential_type
    );
}

// ── K2 ────────────────────────────────────────────────────────────────────────────

/// npm: a committed literal `_authToken` is Critical (name only, never the value); a
/// committed `${NPM_TOKEN}` reference to the default registry is nothing; an override
/// host and `strict-ssl=false` are Medium each.
#[test]
fn project_npmrc_graded_by_name_and_tracking() {
    let home = temp_home("npmrc");
    let (risky, benign, mirror) = (home.join("risky"), home.join("benign"), home.join("mirror"));
    for p in [&risky, &benign, &mirror] {
        if !git_repo(p, &home) {
            eprintln!("git unavailable; skipping");
            return;
        }
    }
    let token = format!("{}{}", "npm_", "CANARYTOKENVALUEabcdefghijklmnopqrstuv");
    write(
        &risky.join(".npmrc"),
        &format!("@acme:registry=https://npm.pkg.github.com/\n//npm.pkg.github.com/:_authToken={token}\n"),
    );
    write(
        &benign.join(".npmrc"),
        "registry=https://registry.npmjs.org/\n//registry.npmjs.org/:_authToken=${NPM_TOKEN}\nignore-scripts=true\n",
    );
    write(
        &mirror.join(".npmrc"),
        "registry=https://npm.mirror.example/\nstrict-ssl=false\n",
    );
    for p in [&risky, &benign, &mirror] {
        commit_all(p, &home);
    }
    register(&home, &[&risky, &benign, &mirror]);
    let (text, report) = scan(&home, &["packages"]);
    let _ = fs::remove_dir_all(&home);
    assert!(!text.contains(&token), "token value leaked");
    let f = collect_findings(&report);
    let r = at(&f, &risky.join(".npmrc"));
    assert!(has(&r, Severity::Critical, "Secret leak"), "{r:?}");
    assert!(
        r.iter().any(|x| x.title.contains("_authToken for npm.pkg.github.com")),
        "{r:?}"
    );
    // The scoped registry is a non-default host as well.
    assert!(has(&r, Severity::Medium, "Package registry"), "{r:?}");
    assert!(at(&f, &benign.join(".npmrc")).is_empty(), "benign .npmrc graded");
    let m = at(&f, &mirror.join(".npmrc"));
    assert_eq!(m.len(), 2, "{m:?}");
    assert!(m.iter().any(|x| x.title.contains("npm.mirror.example")));
    assert!(m.iter().any(|x| x.title.contains("strict-ssl=false")));
    let row = report
        .package_config_audits
        .iter()
        .find(|a| a.config_path == risky.join(".npmrc").display().to_string())
        .expect("project row");
    assert_eq!(row.scope.as_deref(), Some("project"));
    assert_eq!(row.git_tracked, Some(true));
}

/// Yarn berry: an untracked `.yarnrc.yml` with a literal `npmAuthToken` is High; Yarn
/// classic `.yarnrc` with a mirror registry is Medium; a `${NPM_AUTH}` reference is not
/// a credential.
#[test]
fn project_yarn_configs() {
    let home = temp_home("yarn");
    let (berry, classic, refd) = (home.join("berry"), home.join("classic"), home.join("refd"));
    if !git_repo(&berry, &home) {
        return;
    }
    let token = format!("{}{}", "YARNCANARY", "TOKENVALUE0123");
    write(&berry.join("README"), "x");
    commit_all(&berry, &home);
    write(
        &berry.join(".yarnrc.yml"),
        &format!(
            "npmScopes:\n  acme:\n    npmRegistryServer: \"https://yarn.corp.example\"\n    npmAuthToken: {token}\nenableStrictSsl: false\nunsafeHttpWhitelist:\n  - \"*.corp.example\"\n"
        ),
    );
    write(
        &classic.join(".yarnrc"),
        "registry \"https://mirror.example/npm/\"\nstrict-ssl false\n",
    );
    write(
        &refd.join(".yarnrc.yml"),
        "npmRegistryServer: \"https://registry.yarnpkg.com\"\nnpmAuthToken: \"${NPM_AUTH}\"\n",
    );
    register(&home, &[&berry, &classic, &refd]);
    let (text, report) = scan(&home, &["packages"]);
    let _ = fs::remove_dir_all(&home);
    assert!(!text.contains(&token));
    let f = collect_findings(&report);
    let b = at(&f, &berry.join(".yarnrc.yml"));
    assert!(has(&b, Severity::High, "Package registry"), "{b:?}");
    assert!(b.iter().any(|x| x.title.contains("npmAuthToken")));
    assert!(b.iter().any(|x| x.title.contains("yarn.corp.example")));
    assert!(
        b.iter()
            .any(|x| x.title.contains("enableStrictSsl: false") && x.title.contains("*.corp.example"))
    );
    assert!(
        !has(&b, Severity::Critical, "Secret leak"),
        "untracked is not committed"
    );
    let c = at(&f, &classic.join(".yarnrc"));
    assert!(c.iter().any(|x| x.title.contains("mirror.example")), "{c:?}");
    assert!(c.iter().any(|x| x.title.contains("strict-ssl false")), "{c:?}");
    assert!(at(&f, &refd.join(".yarnrc.yml")).is_empty(), "reference graded");
}

/// Bun: `[install] registry` table with a literal token, and a scope whose token is an
/// env reference. uv: an index URL with userinfo (credential, host only), a benign
/// `[[tool.uv.index]]` to pypi.org, `allow-insecure-host`. A venv's `pip.conf`
/// `trusted-host`.
#[test]
fn project_bun_uv_pip_configs() {
    let home = temp_home("bunuv");
    let p = home.join("proj");
    let (benign, venvp) = (home.join("benign"), home.join("venvp"));
    let token = format!("{}{}", "BUNCANARY", "TOKEN42");
    let pw = format!("{}{}", "UVCANARY", "PASSWORD7");
    write(
        &p.join("bunfig.toml"),
        &format!(
            "[install]\nregistry = {{ url = \"https://bun.corp.example/\", token = \"{token}\" }}\n[install.scopes]\nacme = {{ token = \"$npm_token\", url = \"https://registry.npmjs.org/\" }}\n"
        ),
    );
    write(
        &p.join("uv.toml"),
        &format!(
            "index-url = \"https://ci:{pw}@pypi.corp.example/simple\"\nallow-insecure-host = [\"pypi.corp.example\"]\n"
        ),
    );
    write(
        &benign.join("pyproject.toml"),
        "[project]\nname = \"x\"\n[[tool.uv.index]]\nname = \"pypi\"\nurl = \"https://pypi.org/simple\"\n",
    );
    write(
        &benign.join("bunfig.toml"),
        "[install]\nregistry = \"https://registry.npmjs.org\"\n",
    );
    write(&venvp.join(".venv/pyvenv.cfg"), "home = /usr/bin\n");
    write(
        &venvp.join(".venv/pip.conf"),
        "[global]\nindex-url = https://pypi.org/simple\nextra-index-url =\n    https://dl.example/simple\ntrusted-host = dl.example\n",
    );
    write(
        &venvp.join("pyproject.toml"),
        "[tool.uv]\nextra-index-url = [\"https://wheels.example/simple\"]\n",
    );
    register(&home, &[&p, &benign, &venvp]);
    let (text, report) = scan(&home, &["packages"]);
    let _ = fs::remove_dir_all(&home);
    assert!(!text.contains(&token) && !text.contains(&pw), "value leaked");
    let f = collect_findings(&report);
    let b = at(&f, &p.join("bunfig.toml"));
    assert!(has(&b, Severity::High, "Package registry"), "{b:?}");
    assert!(b.iter().any(|x| x.title.contains("install.registry.token")), "{b:?}");
    assert!(
        !b.iter().any(|x| x.title.contains("acme")),
        "env-referenced scope token: {b:?}"
    );
    let u = at(&f, &p.join("uv.toml"));
    assert!(u.iter().any(|x| x.title.contains("index-url URL userinfo")), "{u:?}");
    assert!(
        u.iter()
            .any(|x| x.title.contains("pypi.corp.example") && x.severity == Severity::Medium)
    );
    assert!(u.iter().any(|x| x.title.contains("allow-insecure-host")), "{u:?}");
    assert!(at(&f, &benign.join("pyproject.toml")).is_empty());
    assert!(at(&f, &benign.join("bunfig.toml")).is_empty());
    let v = at(&f, &venvp.join(".venv/pip.conf"));
    assert!(
        v.iter()
            .any(|x| x.title.contains("dl.example") && x.title.contains("points")),
        "{v:?}"
    );
    assert!(v.iter().any(|x| x.title.contains("trusted-host: dl.example")), "{v:?}");
    let y = at(&f, &venvp.join("pyproject.toml"));
    assert!(y.iter().any(|x| x.title.contains("wheels.example")), "{y:?}");
}

/// Cargo: `[source.crates-io] replace-with` to a registry on another host is Medium; a
/// vendored replacement is not graded; a literal `registries.<n>.token` is a credential.
#[test]
fn project_cargo_config() {
    let home = temp_home("cargo");
    let (evil, vendored) = (home.join("evil"), home.join("vendored"));
    let token = format!("{}{}", "cio", "CANARYCARGOTOKEN99");
    write(
        &evil.join(".cargo/config.toml"),
        &format!(
            "[source.crates-io]\nreplace-with = \"mirror\"\n[source.mirror]\nregistry = \"sparse+https://crates.mirror.example/index/\"\n[registries.corp]\nindex = \"sparse+https://cargo.corp.example/\"\ntoken = \"{token}\"\n"
        ),
    );
    write(
        &vendored.join(".cargo/config.toml"),
        "[source.crates-io]\nreplace-with = \"vendored-sources\"\n[source.vendored-sources]\ndirectory = \"vendor\"\n",
    );
    register(&home, &[&evil, &vendored]);
    let (text, report) = scan(&home, &["packages"]);
    let _ = fs::remove_dir_all(&home);
    assert!(!text.contains(&token));
    let f = collect_findings(&report);
    let e = at(&f, &evil.join(".cargo/config.toml"));
    assert!(
        e.iter()
            .any(|x| x.title.contains("crates.mirror.example") && x.severity == Severity::Medium),
        "{e:?}"
    );
    assert!(e.iter().any(|x| x.title.contains("registries.corp.token")), "{e:?}");
    assert!(
        !e.iter().any(|x| x.title.contains("cargo.corp.example")),
        "a declared registry is inventory: {e:?}"
    );
    assert!(at(&f, &vendored.join(".cargo/config.toml")).is_empty());
}

/// A project `.npmrc` committed as a link out of the project is never opened.
#[test]
fn project_npmrc_link_out_of_project_is_not_read() {
    let home = temp_home("link");
    let p = home.join("proj");
    let token = format!("{}{}", "LINKCANARY", "TOKENVALUE");
    let outside = home.join("elsewhere/npmrc");
    write(
        &outside,
        &format!("registry=https://linked.example/\n_authToken={token}\n"),
    );
    fs::create_dir_all(&p).unwrap();
    std::os::unix::fs::symlink(&outside, p.join(".npmrc")).unwrap();
    register(&home, &[&p]);
    let (text, report) = scan(&home, &["packages"]);
    let _ = fs::remove_dir_all(&home);
    assert!(!text.contains("linked.example") && !text.contains(&token), "{text}");
    assert!(report.package_config_audits.iter().all(|a| a.scope.is_none()));
}
