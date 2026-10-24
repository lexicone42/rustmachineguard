use crate::models::NodePackageManager;
use crate::otel::{self, Attr, Key};
use crate::platform::PlatformInfo;
use crate::scanners::{Scanner, extract_version, get_binary_version};
use std::path::Path;

pub struct NodePackagesScanner;

/// (name, binary names, is a JavaScript package run by node). npm, yarn and pnpm are
/// npm packages whose PATH entry is (a link to) a script inside `node_modules/<name>/`,
/// so their version is read from that package's `package.json` ([`package_json_version`])
/// instead of starting node for `<tool> --version` (262 ms for pnpm, 79 ms for npm on
/// the machine this was measured on). bun is a native binary and keeps the spawn.
const PACKAGE_MANAGERS: &[(&str, &[&str], bool)] = &[
    ("npm", &["npm"], true),
    ("yarn", &["yarn"], true),
    ("pnpm", &["pnpm"], true),
    ("bun", &["bun"], false),
];

impl Scanner for NodePackagesScanner {
    type Output = Vec<NodePackageManager>;

    fn scan(&self, _platform: &dyn PlatformInfo) -> Vec<NodePackageManager> {
        let mut results = Vec::new();

        for (name, bin_names, js) in PACKAGE_MANAGERS {
            for bin_name in *bin_names {
                if let Ok(path) = which::which(bin_name) {
                    let version = if *js {
                        js_tool_version(bin_name, &path)
                    } else {
                        get_binary_version(bin_name)
                    };
                    results.push(NodePackageManager {
                        name: name.to_string(),
                        version,
                        path: Some(path.display().to_string()),
                    });
                    break;
                }
            }
        }

        // Also check for Node.js itself (a native binary: spawned)
        if let Ok(path) = which::which("node") {
            let version = get_binary_version("node");
            results.push(NodePackageManager {
                name: "node".to_string(),
                version,
                path: Some(path.display().to_string()),
            });
        }

        results
    }
}

/// The version of a JavaScript tool found on PATH at `path`: its package's `package.json`
/// when that answers ([`package_json_version`]), else `<tool> --version` as before.
///
/// Traced as a `version.read` span (`rmguard.exec.program` = the tool, a closed value;
/// `rmguard.version.source` = `package_json` when the file answered, `spawn` when it did
/// not and the `exec.version_probe` that follows, a sibling under `scanner.node`, does).
fn js_tool_version(tool: &str, path: &Path) -> Option<String> {
    let mut span = otel::span("version.read", || {
        vec![Attr::str(
            Key::ExecProgram,
            otel::exec_program(std::ffi::OsStr::new(tool)),
        )]
    });
    let read = package_json_version(path, tool);
    span.set(|| {
        vec![Attr::str(
            Key::VersionSource,
            if read.is_some() { "package_json" } else { "spawn" },
        )]
    });
    drop(span);
    read.or_else(|| get_binary_version(tool))
}

/// `version` from the `package.json` of the npm package `expected` whose file `bin` (a
/// PATH entry) is, after following its symlink chain: the innermost `node_modules/<dir>/`
/// above the resolved file must be `node_modules/<expected>/`, the manifest's `name` must
/// be `expected`, and its `version` must be plain semver text that [`extract_version`]
/// (the sanitisation a spawned `--version` gets) returns unchanged. Anything else is None,
/// and the caller spawns: a corepack shim (`node_modules/corepack/shims/pnpm`), a native
/// build (`@pnpm/exe`), a standalone install, a manifest that names another package.
///
/// The manifest is read through the bounded, counted no-follow reader
/// ([`crate::scanners::read_bounded_nofollow`]: a symlinked `package.json` is not read)
/// and only `name` and `version` are deserialized. This is the package that runs when the user
/// types the command; a `yarnPath` in some project's `.yarnrc.yml` (which `yarn
/// --version` run in that project would follow) is not consulted.
pub fn package_json_version(bin: &Path, expected: &str) -> Option<String> {
    #[derive(serde::Deserialize)]
    struct Manifest {
        name: Option<String>,
        version: Option<String>,
    }
    let real = std::fs::canonicalize(bin).ok()?;
    let pkg_dir = real
        .ancestors()
        .skip(1)
        .find(|a| a.parent().and_then(Path::file_name) == Some(std::ffi::OsStr::new("node_modules")))?;
    if pkg_dir.file_name()? != std::ffi::OsStr::new(expected) {
        return None;
    }
    // `pkg_dir` is canonical, so a symlinked package.json is a link the package did not
    // ship as its manifest: never followed (O_NOFOLLOW), and the opened file must be this
    // path.
    let manifest = pkg_dir.join("package.json");
    let text = crate::scanners::read_bounded_nofollow(&manifest, Some(&manifest))?;
    let m: Manifest = serde_json::from_str(&text).ok()?;
    if m.name.as_deref() != Some(expected) {
        return None;
    }
    let v = m.version?;
    (is_semver_text(&v) && extract_version(&v).as_deref() == Some(v.as_str())).then_some(v)
}

/// `MAJOR.MINOR.PATCH`, digits only, then an optional `-pre` and/or `+build` of ASCII
/// letters, digits, dots and hyphens; at most 64 bytes.
fn is_semver_text(v: &str) -> bool {
    if v.is_empty() || v.len() > 64 {
        return false;
    }
    let (core, rest) = match v.find(['-', '+']) {
        Some(i) => (&v[..i], &v[i..]),
        None => (v, ""),
    };
    let parts: Vec<&str> = core.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
        && rest
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'+'))
}

/// Binaries rmguard may run, for the telemetry test in `crate::scanners`.
#[cfg(test)]
pub(crate) fn spawned_binaries() -> Vec<&'static str> {
    let mut v: Vec<&'static str> = PACKAGE_MANAGERS
        .iter()
        .flat_map(|(_, b, _)| b.iter().copied())
        .collect();
    v.push("node");
    v
}

#[cfg(test)]
mod tests {
    use super::{is_semver_text, package_json_version};

    /// Only a file inside `node_modules/<tool>/` whose manifest names `<tool>` and holds
    /// plain semver answers; every other shape is left to the spawn.
    #[cfg(unix)]
    #[test]
    fn package_json_version_accepts_only_the_tools_own_package() {
        let root = std::env::temp_dir().join(format!("rmg-pkgver-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let put = |rel: &str, body: &str| {
            let p = root.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, body).unwrap();
            p
        };
        let cli = put("g/node_modules/npm/bin/npm-cli.js", "");
        put(
            "g/node_modules/npm/package.json",
            r#"{"name":"npm","version":"11.9.0"}"#,
        );
        let link = root.join("bin-npm");
        std::os::unix::fs::symlink(&cli, &link).unwrap();
        assert_eq!(package_json_version(&link, "npm").as_deref(), Some("11.9.0"));
        assert_eq!(package_json_version(&cli, "npm").as_deref(), Some("11.9.0"));
        // Another tool's package (a corepack shim), the wrong expected name, no node_modules.
        let shim = put("g/node_modules/corepack/shims/pnpm", "");
        put(
            "g/node_modules/corepack/package.json",
            r#"{"name":"corepack","version":"0.34.0"}"#,
        );
        assert_eq!(package_json_version(&shim, "pnpm"), None);
        assert_eq!(package_json_version(&cli, "pnpm"), None);
        let plain = put("opt/pnpm/pnpm", "");
        put("opt/pnpm/package.json", r#"{"name":"pnpm","version":"10.0.0"}"#);
        assert_eq!(package_json_version(&plain, "pnpm"), None);
        // A version that is not plain semver, or not a string.
        for bad in [
            r#"{"name":"yarn","version":"1.22.22\u001b[31m"}"#,
            r#"{"name":"yarn","version":"latest"}"#,
            r#"{"name":"yarn","version":1}"#,
            r#"{"name":"yarn"}"#,
        ] {
            let y = put("g/node_modules/yarn/bin/yarn.js", "");
            put("g/node_modules/yarn/package.json", bad);
            assert_eq!(package_json_version(&y, "yarn"), None, "{bad}");
        }
        // A symlinked package.json is not followed (on b21286f it was read: Some).
        let p = put("g/node_modules/pnpm/bin/pnpm.cjs", "");
        let real = put("elsewhere/manifest.json", r#"{"name":"pnpm","version":"10.1.0"}"#);
        std::os::unix::fs::symlink(&real, root.join("g/node_modules/pnpm/package.json")).unwrap();
        assert_eq!(package_json_version(&p, "pnpm"), None);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn semver_text_is_plain() {
        for ok in [
            "10.28.1",
            "11.9.0",
            "1.22.22",
            "4.0.0-rc.1",
            "1.0.0+build.5",
            "1.0.0-beta-2+x",
        ] {
            assert!(is_semver_text(ok), "{ok}");
        }
        for bad in [
            "",
            "1.2",
            "1.2.3.4",
            "v1.2.3",
            "1.2.x",
            "1.2.3 ",
            "1.2.3-\u{1b}[31m",
            "1.2.3\n",
            "01.2.3-é",
            &"9".repeat(65),
        ] {
            assert!(!is_semver_text(bad), "{bad:?}");
        }
    }
}
