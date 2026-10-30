/// Every registry/index value echoed into a finding goes through this. These configs
/// routinely embed basic-auth credentials, and the URL is the finding — so the
/// credential is removed and the rest kept.
fn redact(s: &str) -> String {
    crate::scanners::redact_secrets_in_text(s)
}

use crate::models::{PackageConfigAudit, PackageConfigFinding};
use crate::platform::PlatformInfo;
use crate::scanners::Scanner;
use std::path::{Path, PathBuf};

pub struct PackageConfigsScanner;

impl Scanner for PackageConfigsScanner {
    type Output = Vec<PackageConfigAudit>;

    fn scan(&self, platform: &dyn PlatformInfo) -> Vec<PackageConfigAudit> {
        let mut results = Vec::new();
        let home = platform.home_dir();

        // .npmrc locations
        for path in npmrc_paths(&home) {
            if crate::scanners::probe_file(&path)
                && let Some(content) = crate::scanners::read_bounded(&path)
            {
                let findings = audit_npmrc(&content);
                if !findings.is_empty() {
                    results.push(PackageConfigAudit {
                        manager: "npm".to_string(),
                        config_path: path.display().to_string(),
                        findings,
                        ..Default::default()
                    });
                }
            }
        }

        // pip config
        for path in pip_config_paths(&home) {
            if crate::scanners::probe_file(&path)
                && let Some(content) = crate::scanners::read_bounded(&path)
            {
                let findings = audit_pip_config(&content);
                if !findings.is_empty() {
                    results.push(PackageConfigAudit {
                        manager: "pip".to_string(),
                        config_path: path.display().to_string(),
                        findings,
                        ..Default::default()
                    });
                }
            }
        }

        // Bun's global config is `~/.bunfig.toml`; the un-dotted name is the
        // per-project form. Only the dotted one existed here, so a global bun
        // registry override was never read at all.
        if let Some(bunfig) = [home.join(".bunfig.toml"), home.join("bunfig.toml")]
            .into_iter()
            .find(|p| crate::scanners::probe_file(p))
            && let Some(content) = crate::scanners::read_bounded(&bunfig)
        {
            let findings = audit_bunfig(&content);
            if !findings.is_empty() {
                results.push(PackageConfigAudit {
                    manager: "bun".to_string(),
                    config_path: bunfig.display().to_string(),
                    findings,
                    ..Default::default()
                });
            }
        }

        // .yarnrc / .yarnrc.yml
        for (name, path) in yarn_config_paths(&home) {
            if crate::scanners::probe_file(&path)
                && let Some(content) = crate::scanners::read_bounded(&path)
            {
                let findings = audit_yarn_config(&content, &name);
                if !findings.is_empty() {
                    results.push(PackageConfigAudit {
                        manager: format!("yarn ({})", name),
                        config_path: path.display().to_string(),
                        findings,
                        ..Default::default()
                    });
                }
            }
        }

        results.extend(scan_projects(platform, &home));
        results
    }
}

fn npmrc_paths(home: &Path) -> Vec<PathBuf> {
    vec![home.join(".npmrc"), PathBuf::from("/etc/npmrc")]
}

fn pip_config_paths(home: &Path) -> Vec<PathBuf> {
    vec![
        home.join(".config/pip/pip.conf"),
        home.join(".pip/pip.conf"),
        PathBuf::from("/etc/pip.conf"),
    ]
}

fn yarn_config_paths(home: &Path) -> Vec<(String, PathBuf)> {
    vec![
        ("classic".to_string(), home.join(".yarnrc")),
        ("berry".to_string(), home.join(".yarnrc.yml")),
    ]
}

pub fn audit_npmrc(content: &str) -> Vec<PackageConfigFinding> {
    let mut findings = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
            continue;
        }

        let lower = line.to_lowercase();

        if lower.starts_with("registry=") || lower.contains(":registry=") {
            let val = line.split_once('=').map(|x| x.1).unwrap_or("");
            if !crate::scanners::is_official_registry(val, &["registry.npmjs.org"]) {
                findings.push(PackageConfigFinding {
                    severity: "high".to_string(),
                    description: format!("Custom npm registry: {}", redact(val)),
                });
            }
        }

        if lower.starts_with("//") && lower.contains(":_authtoken=") {
            findings.push(PackageConfigFinding {
                severity: "high".to_string(),
                description: "Registry auth token present in config".to_string(),
            });
        }

        if lower.starts_with("//") && lower.contains(":_auth=") {
            findings.push(PackageConfigFinding {
                severity: "high".to_string(),
                description: "Registry basic auth credentials present in config".to_string(),
            });
        }

        if lower == "strict-ssl=false" {
            findings.push(PackageConfigFinding {
                severity: "critical".to_string(),
                description: "SSL verification disabled (strict-ssl=false)".to_string(),
            });
        }

        if lower.starts_with("cafile=") || lower.starts_with("cert=") {
            findings.push(PackageConfigFinding {
                severity: "medium".to_string(),
                description: format!("Custom certificate configuration: {}", redact(line)),
            });
        }

        if lower.contains("ignore-scripts=true") {
            findings.push(PackageConfigFinding {
                severity: "info".to_string(),
                description: "Install scripts disabled (ignore-scripts=true)".to_string(),
            });
        }
    }

    findings
}

pub fn audit_pip_config(content: &str) -> Vec<PackageConfigFinding> {
    let mut findings = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        let lower = line.to_lowercase();

        if lower.starts_with("index-url") || lower.starts_with("extra-index-url") {
            let val = line.split_once('=').map(|x| x.1).unwrap_or("").trim();
            if !val.contains("pypi.org") {
                findings.push(PackageConfigFinding {
                    severity: "high".to_string(),
                    description: format!("Custom PyPI index: {}", redact(val)),
                });
            }
        }

        if lower.starts_with("trusted-host") {
            findings.push(PackageConfigFinding {
                severity: "high".to_string(),
                description: format!("Trusted host (bypasses TLS verification): {}", redact(line)),
            });
        }

        if lower.contains("cert") && lower.contains("=") && !lower.starts_with("#") && !lower.starts_with(";") {
            findings.push(PackageConfigFinding {
                severity: "medium".to_string(),
                description: format!("Custom certificate configuration: {}", redact(line)),
            });
        }
    }

    findings
}

pub fn audit_bunfig(content: &str) -> Vec<PackageConfigFinding> {
    let mut findings = Vec::new();

    let Ok(table): Result<toml::Table, _> = content.parse() else {
        return findings;
    };

    if let Some(install) = table.get("install").and_then(|v| v.as_table())
        && let Some(registry) = install.get("registry").and_then(|v| v.as_str())
        && !crate::scanners::is_official_registry(registry, &["registry.npmjs.org"])
    {
        findings.push(PackageConfigFinding {
            severity: "high".to_string(),
            description: format!("Custom bun registry: {}", redact(registry)),
        });
    }

    if let Some(scopes) = table
        .get("install")
        .and_then(|v| v.as_table())
        .and_then(|t| t.get("scopes"))
        .and_then(|v| v.as_table())
    {
        for (scope, cfg) in scopes {
            if let Some(url) = cfg.as_table().and_then(|t| t.get("url")).and_then(|v| v.as_str()) {
                findings.push(PackageConfigFinding {
                    severity: "medium".to_string(),
                    description: format!("Scoped registry for @{}: {}", scope, redact(url)),
                });
            }
        }
    }

    findings
}

pub fn audit_yarn_config(content: &str, variant: &str) -> Vec<PackageConfigFinding> {
    let mut findings = Vec::new();

    if variant == "classic" {
        for line in content.lines() {
            let line = line.trim();
            let lower = line.to_lowercase();

            if lower.starts_with("registry") {
                let val = line.split_once(' ').map(|x| x.1).unwrap_or("").trim_matches('"');
                if !crate::scanners::is_official_registry(val, &["registry.yarnpkg.com", "registry.npmjs.org"]) {
                    findings.push(PackageConfigFinding {
                        severity: "high".to_string(),
                        description: format!("Custom yarn classic registry: {}", redact(val)),
                    });
                }
            }

            if lower == "strict-ssl false" {
                findings.push(PackageConfigFinding {
                    severity: "critical".to_string(),
                    description: "SSL verification disabled (strict-ssl false)".to_string(),
                });
            }
        }
    } else {
        // Berry (.yarnrc.yml) — simple line scanning for key patterns
        for line in content.lines() {
            let line = line.trim();
            let lower = line.to_lowercase();

            if lower.starts_with("npmregistryserver:") {
                let val = line.split_once(':').map(|x| x.1).unwrap_or("").trim().trim_matches('"');
                if !crate::scanners::is_official_registry(val, &["registry.yarnpkg.com", "registry.npmjs.org"]) {
                    findings.push(PackageConfigFinding {
                        severity: "high".to_string(),
                        description: format!("Custom yarn berry registry: {}", redact(val)),
                    });
                }
            }

            if lower.starts_with("enablestrictssl:") && lower.contains("false") {
                findings.push(PackageConfigFinding {
                    severity: "critical".to_string(),
                    description: "SSL verification disabled (enableStrictSsl: false)".to_string(),
                });
            }

            if lower.starts_with("unsafehttp") && lower.contains("true") {
                findings.push(PackageConfigFinding {
                    severity: "critical".to_string(),
                    description: "Unsafe HTTP allowed (unsafeHttpWhitelist or similar)".to_string(),
                });
            }
        }
    }

    findings
}

// ---------------------------------------------------------------------------------------
// Project package-manager configs.
//
// A repository can carry its own package-manager configuration, and the tools read it
// for every install run in that tree:
// - npm: `<project>/.npmrc` ("a .npmrc file in the root of the project ... will set config
//   values specific to this project"; auth settings `_auth`, `_authToken`, `_password`
//   must be scoped to a registry `//host/:`; `${VAR}` is expanded) --
//   https://docs.npmjs.com/cli/v10/configuring-npm/npmrc. pnpm reads the same project
//   `.npmrc` (there is no `.pnpmrc`) -- https://pnpm.io/npmrc.
// - Yarn classic: `<project>/.yarnrc` (`registry`, `strict-ssl`) --
//   https://classic.yarnpkg.com/en/docs/yarnrc; Yarn berry: `<project>/.yarnrc.yml`
//   (`npmRegistryServer`, `npmAuthToken`, `npmAuthIdent`, `npmScopes`, `npmRegistries`,
//   `enableStrictSsl`, `unsafeHttpWhitelist`) -- https://yarnpkg.com/configuration/yarnrc.
// - Bun: `<project>/bunfig.toml` (`[install] registry` as a URL or a table with `token`
//   / `username` / `password`, `[install.scopes]`) -- https://bun.sh/docs/runtime/bunfig.
// - uv: `<project>/uv.toml` and `[tool.uv]` in `<project>/pyproject.toml` (`index-url`,
//   `extra-index-url`, `[[index]] url`, `find-links`, `allow-insecure-host`, and the same
//   under `pip`) -- https://docs.astral.sh/uv/reference/settings/.
// - pip has no project-local file; a virtual environment's `pip.conf` is its site config
//   (`$VIRTUAL_ENV/pip.conf`), read here for `<project>/.venv` and `<project>/venv` --
//   https://pip.pypa.io/en/stable/topics/configuration/.
// - Cargo: `<project>/.cargo/config.toml` (or `.cargo/config`, which wins when both
//   exist): `[source.crates-io] replace-with`, `[registries.<name>] index`, and
//   `token`, which "should only appear in the credentials file" --
//   https://doc.rust-lang.org/cargo/reference/config.html.
//
// Every file is repository content and goes through `read_bounded_within` (the real
// path must stay in the project; opened without following a link). Credentials are
// recorded by setting NAME only; a value is classified as a `${VAR}` / `$VAR` reference
// or a literal by its first characters and is never copied out. Registry URLs are
// recorded as their host.

/// Facts read from one project package-manager config.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ProjectPkgFacts {
    /// Setting names holding a literal credential.
    pub credential_keys: Vec<String>,
    /// Non-default registry/index hosts the file points resolution at.
    pub registry_hosts: Vec<String>,
    /// Settings that disable TLS verification or allow plain HTTP.
    pub tls_disabled: Vec<String>,
    /// Other recorded settings (`always-auth`, `ignore-scripts`, declared registries).
    pub notes: Vec<String>,
}

impl ProjectPkgFacts {
    fn cred(&mut self, name: String) {
        if !self.credential_keys.contains(&name) {
            self.credential_keys.push(name);
        }
    }
    fn tls(&mut self, what: &str) {
        if !self.tls_disabled.iter().any(|x| x == what) {
            self.tls_disabled.push(what.to_string());
        }
    }
    fn note(&mut self, what: String) {
        if !self.notes.contains(&what) {
            self.notes.push(what);
        }
    }
    /// Record a registry URL: its userinfo as a credential, its host as an override
    /// unless it is one of `official` (or a local path, which is not a host).
    fn registry(&mut self, setting: &str, url: &str, official: &[&str]) {
        let url = strip_registry_prefix(url.trim().trim_matches(['"', '\'']));
        if url.is_empty() || is_reference(url) || !url.contains("://") {
            return;
        }
        if url_has_userinfo(url) {
            self.cred(format!("{setting} URL userinfo"));
        }
        let (scheme, _) = crate::scanners::split_url_authority(url);
        if scheme.eq_ignore_ascii_case("file") {
            return;
        }
        let (host, _) = crate::scanners::host_of(url);
        if host.is_empty() || crate::scanners::is_official_registry(&format!("https://{host}/"), official) {
            return;
        }
        if !self.registry_hosts.contains(&host) {
            self.registry_hosts.push(host);
        }
    }
}

const NPM_OFFICIAL: &[&str] = &["registry.npmjs.org", "registry.yarnpkg.com"];
const PYPI_OFFICIAL: &[&str] = &["pypi.org", "files.pythonhosted.org"];

/// `sparse+https://...`, `registry+https://...`, `git+https://...` -> the URL.
fn strip_registry_prefix(url: &str) -> &str {
    for p in ["sparse+", "registry+", "git+"] {
        if let Some(rest) = url.strip_prefix(p) {
            return rest;
        }
    }
    url
}

/// The URL's authority carries `user[:password]@`.
fn url_has_userinfo(url: &str) -> bool {
    let after = url.find("://").map_or(url, |i| &url[i + 3..]);
    let end = after.find(['/', '?', '#', '\\']).unwrap_or(after.len());
    after[..end].contains('@')
}

/// A value that names a secret rather than holding one: empty, `${VAR}` / `$VAR` (npm,
/// Yarn, Bun and pnpm expand these from the environment). Only the first characters are
/// looked at.
fn is_reference(value: &str) -> bool {
    let v = value.trim().trim_matches(['"', '\'']).trim();
    v.is_empty() || v.starts_with('$')
}

/// The host of an npm-style `//host[:port]/path/:` key prefix.
fn scoped_host(prefix: &str) -> String {
    crate::scanners::host_of(&format!("https:{prefix}")).0
}

/// npm / pnpm `.npmrc` (also what Yarn classic reads beside `.yarnrc`).
pub fn project_npmrc_facts(content: &str) -> ProjectPkgFacts {
    let mut f = ProjectPkgFacts::default();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();
        npm_key(&mut f, key, value, "=");
    }
    f
}

/// One `key`/`value` of the npm config model (shared by `.npmrc` and `.yarnrc`).
fn npm_key(f: &mut ProjectPkgFacts, key: &str, value: &str, sep: &str) {
    let (scope, name) = match key.strip_prefix("//").and_then(|_| key.rsplit_once(':')) {
        Some((prefix, name)) => (Some(scoped_host(prefix)), name),
        None => (None, key),
    };
    let lname = name.to_ascii_lowercase();
    let off = value.trim_matches(['"', '\'']).eq_ignore_ascii_case("false");
    let on = value.trim_matches(['"', '\'']).eq_ignore_ascii_case("true");
    match lname.as_str() {
        "_authtoken" | "_auth" | "_password" => {
            if !is_reference(value) {
                f.cred(match scope {
                    Some(h) if !h.is_empty() => format!("{name} for {h}"),
                    _ => name.to_string(),
                });
            }
        }
        "registry" => f.registry("registry", value, NPM_OFFICIAL),
        n if n.ends_with(":registry") && key.starts_with('@') => f.registry(key, value, NPM_OFFICIAL),
        "strict-ssl" if off => f.tls(&format!("strict-ssl{sep}false")),
        "always-auth" if on => f.note(format!("always-auth{sep}true")),
        "ignore-scripts" if on => f.note(format!("ignore-scripts{sep}true")),
        _ => {}
    }
}

/// Yarn classic `.yarnrc`: `key value` lines, either side optionally quoted.
pub fn project_yarnrc_facts(content: &str) -> ProjectPkgFacts {
    let mut f = ProjectPkgFacts::default();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = if let Some(rest) = line.strip_prefix('"') {
            match rest.split_once('"') {
                Some((k, v)) => (k, v.trim()),
                None => continue,
            }
        } else {
            match line.split_once(char::is_whitespace) {
                Some((k, v)) => (k, v.trim()),
                None => continue,
            }
        };
        npm_key(&mut f, key, value, " ");
    }
    f
}

/// Yarn berry `.yarnrc.yml`. Line-based over the documented keys, at any indentation
/// (top level, under `npmScopes.<scope>` or `npmRegistries."//host"`).
pub fn project_yarnrc_yml_facts(content: &str) -> ProjectPkgFacts {
    let mut f = ProjectPkgFacts::default();
    let mut in_http_whitelist = false;
    for raw in content.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if in_http_whitelist {
            if let Some(item) = line.strip_prefix('-') {
                let h = item.trim().trim_matches(['"', '\'']);
                if !h.is_empty() {
                    f.tls(&format!(
                        "unsafeHttpWhitelist: {}",
                        crate::scanners::sanitize_display(h, 128)
                    ));
                }
                continue;
            }
            in_http_whitelist = false;
        }
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim().trim_matches(['"', '\'']);
        let value = value.trim();
        let off = value.trim_matches(['"', '\'']).eq_ignore_ascii_case("false");
        let on = value.trim_matches(['"', '\'']).eq_ignore_ascii_case("true");
        match key {
            "npmAuthToken" | "npmAuthIdent" => {
                if !is_reference(value) {
                    f.cred(key.to_string());
                }
            }
            "npmRegistryServer" | "npmPublishRegistry" => f.registry(key, value, NPM_OFFICIAL),
            "enableStrictSsl" if off => f.tls("enableStrictSsl: false"),
            "npmAlwaysAuth" if on => f.note("npmAlwaysAuth: true".to_string()),
            "enableScripts" if off => f.note("enableScripts: false".to_string()),
            "unsafeHttpWhitelist" => {
                let inline = value.trim_start_matches('[').trim_end_matches(']');
                for h in inline.split(',').map(|h| h.trim().trim_matches(['"', '\''])) {
                    if !h.is_empty() {
                        f.tls(&format!(
                            "unsafeHttpWhitelist: {}",
                            crate::scanners::sanitize_display(h, 128)
                        ));
                    }
                }
                in_http_whitelist = value.is_empty();
            }
            _ => {}
        }
    }
    f
}

/// Bun `bunfig.toml`: `[install] registry` and `[install.scopes]`.
pub fn project_bunfig_facts(content: &str) -> ProjectPkgFacts {
    let mut f = ProjectPkgFacts::default();
    let Ok(table): Result<toml::Table, _> = content.parse() else {
        return f;
    };
    let Some(install) = table.get("install").and_then(|v| v.as_table()) else {
        return f;
    };
    let one = |f: &mut ProjectPkgFacts, label: &str, v: &toml::Value| match v {
        toml::Value::String(url) => f.registry(label, url, NPM_OFFICIAL),
        toml::Value::Table(t) => {
            if let Some(url) = t.get("url").and_then(|u| u.as_str()) {
                f.registry(label, url, NPM_OFFICIAL);
            }
            for k in ["token", "password"] {
                if let Some(val) = t.get(k).and_then(|x| x.as_str())
                    && !is_reference(val)
                {
                    f.cred(format!("{label}.{k}"));
                }
            }
        }
        _ => {}
    };
    if let Some(r) = install.get("registry") {
        one(&mut f, "install.registry", r);
    }
    if let Some(scopes) = install.get("scopes").and_then(|v| v.as_table()) {
        for (scope, v) in scopes {
            let label = format!("install.scopes.{}", crate::scanners::sanitize_display(scope, 64));
            one(&mut f, &label, v);
        }
    }
    f
}

/// uv settings: a `uv.toml` table, or `[tool.uv]` of a `pyproject.toml`.
fn uv_table_facts(f: &mut ProjectPkgFacts, uv: &toml::Table, prefix: &str) {
    let urls = |v: Option<&toml::Value>| -> Vec<String> {
        match v {
            Some(toml::Value::String(s)) => vec![s.clone()],
            Some(toml::Value::Array(a)) => a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect(),
            _ => vec![],
        }
    };
    for key in ["index-url", "extra-index-url", "find-links"] {
        for u in urls(uv.get(key)) {
            f.registry(&format!("{prefix}{key}"), &u, PYPI_OFFICIAL);
        }
    }
    if let Some(toml::Value::Array(indexes)) = uv.get("index") {
        for ix in indexes.iter().filter_map(|x| x.as_table()) {
            if let Some(u) = ix.get("url").and_then(|u| u.as_str()) {
                f.registry(&format!("{prefix}index.url"), u, PYPI_OFFICIAL);
            }
        }
    }
    for h in urls(uv.get("allow-insecure-host")) {
        f.tls(&format!(
            "{prefix}allow-insecure-host: {}",
            crate::scanners::host_of(&h).0
        ));
    }
    if prefix.is_empty()
        && let Some(pip) = uv.get("pip").and_then(|p| p.as_table())
    {
        uv_table_facts(f, pip, "pip.");
    }
}

/// `<project>/uv.toml`.
pub fn project_uv_toml_facts(content: &str) -> ProjectPkgFacts {
    let mut f = ProjectPkgFacts::default();
    if let Ok(t) = content.parse::<toml::Table>() {
        uv_table_facts(&mut f, &t, "");
    }
    f
}

/// `[tool.uv]` of `<project>/pyproject.toml`; None when there is no such table.
pub fn project_pyproject_uv_facts(content: &str) -> Option<ProjectPkgFacts> {
    let t = content.parse::<toml::Table>().ok()?;
    let uv = t.get("tool")?.as_table()?.get("uv")?.as_table()?;
    let mut f = ProjectPkgFacts::default();
    uv_table_facts(&mut f, uv, "tool.uv.");
    Some(f)
}

/// A virtual environment's `pip.conf` (INI; `index-url`, `extra-index-url` with
/// continuation lines, `find-links`, `trusted-host`).
pub fn project_pip_conf_facts(content: &str) -> ProjectPkgFacts {
    let mut f = ProjectPkgFacts::default();
    let mut current: Option<String> = None;
    for raw in content.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') || line.starts_with('[') {
            if line.starts_with('[') {
                current = None;
            }
            continue;
        }
        let continuation = raw.starts_with([' ', '\t']) && current.is_some();
        let (key, value) = if continuation {
            (current.clone().unwrap_or_default(), line)
        } else {
            match line.split_once(['=', ':']) {
                Some((k, v)) if !k.contains('/') => (k.trim().to_ascii_lowercase(), v.trim()),
                _ => continue,
            }
        };
        current = Some(key.clone());
        for v in value.split_whitespace() {
            match key.as_str() {
                "index-url" | "extra-index-url" | "find-links" | "index" => f.registry(&key, v, PYPI_OFFICIAL),
                "trusted-host" => f.tls(&format!("trusted-host: {}", crate::scanners::host_of(v).0)),
                _ => {}
            }
        }
    }
    f
}

/// `<project>/.cargo/config.toml` (or `.cargo/config`).
pub fn project_cargo_config_facts(content: &str) -> ProjectPkgFacts {
    let mut f = ProjectPkgFacts::default();
    let Ok(t) = content.parse::<toml::Table>() else {
        return f;
    };
    const CRATES_OFFICIAL: &[&str] = &["crates.io"];
    let registries = t.get("registries").and_then(|v| v.as_table());
    let sources = t.get("source").and_then(|v| v.as_table());
    if let Some(tok) = t.get("registry").and_then(|r| r.get("token")).and_then(|x| x.as_str())
        && !is_reference(tok)
    {
        f.cred("registry.token".to_string());
    }
    for (name, r) in registries.into_iter().flatten() {
        let name = crate::scanners::sanitize_display(name, 64);
        if let Some(tok) = r.get("token").and_then(|x| x.as_str())
            && !is_reference(tok)
        {
            f.cred(format!("registries.{name}.token"));
        }
        // A declared registry is used only by dependencies that name it: inventory.
        if let Some(ix) = r.get("index").and_then(|x| x.as_str()) {
            let ix = strip_registry_prefix(ix);
            if url_has_userinfo(ix) {
                f.cred(format!("registries.{name}.index URL userinfo"));
            }
            let host = crate::scanners::host_of(ix).0;
            if !host.is_empty() {
                f.note(format!("declares registry {name} at {host}"));
            }
        }
    }
    // `[source.crates-io] replace-with = X` sends every crates.io dependency to X.
    let mut target = sources
        .and_then(|s| s.get("crates-io"))
        .and_then(|c| c.get("replace-with"))
        .and_then(|x| x.as_str())
        .map(str::to_string);
    let mut hops = 0;
    while let Some(name) = target.take() {
        hops += 1;
        if hops > 8 {
            break;
        }
        let label = format!(
            "source.crates-io replace-with {}",
            crate::scanners::sanitize_display(&name, 64)
        );
        if let Some(src) = sources.and_then(|s| s.get(&name)).and_then(|v| v.as_table()) {
            if let Some(next) = src.get("replace-with").and_then(|x| x.as_str()) {
                target = Some(next.to_string());
            } else if let Some(u) = src.get("registry").and_then(|x| x.as_str()) {
                f.registry(&label, u, CRATES_OFFICIAL);
            } else if src.contains_key("directory") || src.contains_key("local-registry") {
                // Vendored sources (`cargo vendor`): crates come from the tree itself.
                f.note("crates.io replaced by a local directory (vendored)".to_string());
            }
        } else if let Some(ix) = registries
            .and_then(|r| r.get(&name))
            .and_then(|r| r.get("index"))
            .and_then(|x| x.as_str())
        {
            f.registry(&label, ix, CRATES_OFFICIAL);
        }
    }
    if let Some(gh) = f.registry_hosts.iter().position(|h| h == "github.com")
        && content.contains("github.com/rust-lang/crates.io-index")
    {
        f.registry_hosts.remove(gh);
    }
    f
}

/// Turn facts into a project row (None when the file says nothing worth a row).
fn project_row(manager: &str, path: &Path, facts: ProjectPkgFacts) -> Option<PackageConfigAudit> {
    if facts == ProjectPkgFacts::default() {
        return None;
    }
    let mut findings = Vec::new();
    for k in &facts.credential_keys {
        findings.push(PackageConfigFinding {
            severity: "high".to_string(),
            description: format!("Registry credential present: {k}"),
        });
    }
    for h in &facts.registry_hosts {
        findings.push(PackageConfigFinding {
            severity: "medium".to_string(),
            description: format!("Project registry override: {h}"),
        });
    }
    for t in &facts.tls_disabled {
        findings.push(PackageConfigFinding {
            severity: "medium".to_string(),
            description: format!("TLS verification relaxed: {t}"),
        });
    }
    for n in &facts.notes {
        findings.push(PackageConfigFinding {
            severity: "info".to_string(),
            description: n.clone(),
        });
    }
    Some(PackageConfigAudit {
        manager: manager.to_string(),
        config_path: path.display().to_string(),
        findings,
        scope: Some("project".to_string()),
        git_tracked: crate::scanners::git_tracked_state(path),
        credential_keys: facts.credential_keys,
        registry_hosts: facts.registry_hosts,
        tls_disabled: facts.tls_disabled,
    })
}

/// The package-manager configs of every project this pass covers.
fn scan_projects(platform: &dyn PlatformInfo, home: &Path) -> Vec<PackageConfigAudit> {
    let scope = platform.pass_scope();
    // A scan home (or an ancestor of one) is not a project: its `.npmrc`, `.yarnrc` and
    // `.cargo/config.toml` are the user configs read above.
    let dirs = scope.excluding_scan_homes(
        scope.with_cwd(crate::scanners::python_packages::project_dirs(&home.join(".claude.json")).unwrap_or_default()),
    );
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for dir in dirs {
        let root = crate::scanners::skills::project_containment_root(&dir, home);
        let mut read = |rel: &str| -> Option<(PathBuf, String)> {
            let path = dir.join(rel);
            if !seen.insert(crate::scanners::skills::dedupe_key(&path)) || !crate::scanners::probe_exists(&path) {
                return None;
            }
            crate::scanners::read_bounded_within(&path, &root).map(|c| (path, c))
        };
        let mut push = |manager: &str, path: PathBuf, facts: ProjectPkgFacts| {
            if let Some(row) = project_row(manager, &path, facts) {
                out.push(row);
            }
        };
        if let Some((p, c)) = read(".npmrc") {
            push("npm", p, project_npmrc_facts(&c));
        }
        if let Some((p, c)) = read(".yarnrc") {
            push("yarn (classic)", p, project_yarnrc_facts(&c));
        }
        if let Some((p, c)) = read(".yarnrc.yml") {
            push("yarn (berry)", p, project_yarnrc_yml_facts(&c));
        }
        if let Some((p, c)) = read("bunfig.toml") {
            push("bun", p, project_bunfig_facts(&c));
        }
        if let Some((p, c)) = read("uv.toml") {
            push("uv", p, project_uv_toml_facts(&c));
        }
        if let Some((p, c)) = read("pyproject.toml")
            && let Some(f) = project_pyproject_uv_facts(&c)
        {
            push("uv", p, f);
        }
        for venv in [".venv", "venv"] {
            // A venv's site config, only in a real venv (pyvenv.cfg beside it).
            if std::fs::symlink_metadata(dir.join(venv).join("pyvenv.cfg")).is_ok_and(|m| m.is_file())
                && let Some((p, c)) = read(&format!("{venv}/pip.conf"))
            {
                push("pip (venv)", p, project_pip_conf_facts(&c));
            }
        }
        // Cargo prefers the extension-less file when both exist.
        let cargo = if crate::scanners::probe_exists(&dir.join(".cargo/config")) {
            ".cargo/config"
        } else {
            ".cargo/config.toml"
        };
        if let Some((p, c)) = read(cargo) {
            push("cargo", p, project_cargo_config_facts(&c));
        }
    }
    out
}
