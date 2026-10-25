use crate::models::{AiTool, AiToolType};
use crate::otel::{Attr, Key};
use crate::platform::PlatformInfo;
use crate::scanners::{Scanner, get_binary_version, is_process_running};
use std::path::{Path, PathBuf};

pub struct AiToolsScanner;

struct ToolDef {
    name: &'static str,
    vendor: &'static str,
    tool_type: AiToolType,
    binary_names: &'static [&'static str],
    process_name: Option<&'static str>,
    config_dir_check: Option<fn(&dyn PlatformInfo) -> std::path::PathBuf>,
    verify_binary: bool,
}

const TOOLS: &[ToolDef] = &[
    ToolDef {
        name: "Claude Code",
        vendor: "Anthropic",
        tool_type: AiToolType::CliTool,
        binary_names: &["claude"],
        process_name: Some("claude"),
        config_dir_check: Some(|p| p.claude_config_dir()),
        verify_binary: false,
    },
    ToolDef {
        name: "GitHub Copilot CLI",
        vendor: "Microsoft",
        tool_type: AiToolType::CliTool,
        binary_names: &["copilot", "gh-copilot", "github-copilot-cli", "ghcs"],
        process_name: None,
        config_dir_check: Some(|p| p.github_copilot_config_dir()),
        verify_binary: true,
    },
    ToolDef {
        name: "OpenAI Codex CLI",
        vendor: "OpenAI",
        tool_type: AiToolType::CliTool,
        binary_names: &["codex"],
        process_name: None,
        config_dir_check: Some(|p| p.codex_config_dir()),
        verify_binary: false,
    },
    ToolDef {
        name: "Gemini CLI",
        vendor: "Google",
        tool_type: AiToolType::CliTool,
        binary_names: &["gemini"],
        process_name: None,
        config_dir_check: Some(|p| p.gemini_config_dir()),
        verify_binary: false,
    },
    ToolDef {
        name: "Amazon Q CLI",
        vendor: "Amazon",
        tool_type: AiToolType::CliTool,
        binary_names: &["amazon-q"],
        process_name: None,
        config_dir_check: Some(|p| p.aws_q_config_dir()),
        verify_binary: false,
    },
    ToolDef {
        name: "Cursor Agent",
        vendor: "Anysphere",
        tool_type: AiToolType::Agent,
        binary_names: &["cursor-agent"],
        process_name: None,
        config_dir_check: None,
        verify_binary: false,
    },
    // Kiro is two products with two version lines: the CLI (`kiro-cli`, formerly
    // Amazon Q Developer CLI, 1.x/2.x) and the VS Code-based IDE (`kiro` launcher,
    // 0.x/1.x). CVE-2026-89332 is scoped to the IDE, so they must not share a row:
    // keyed together, a machine with both installed would report the CLI's version
    // against the IDE's advisory range.
    ToolDef {
        name: "Kiro CLI",
        vendor: "Amazon",
        tool_type: AiToolType::CliTool,
        binary_names: &["kiro-cli"],
        process_name: None,
        config_dir_check: Some(|p| p.kiro_config_dir()),
        verify_binary: false,
    },
    ToolDef {
        name: "Kiro IDE",
        vendor: "Amazon",
        tool_type: AiToolType::DesktopApp,
        binary_names: &["kiro"],
        process_name: None,
        config_dir_check: None,
        verify_binary: false,
    },
    ToolDef {
        name: "Microsoft AI Shell",
        vendor: "Microsoft",
        tool_type: AiToolType::CliTool,
        binary_names: &["aish"],
        process_name: None,
        config_dir_check: Some(|p| p.aish_config_dir()),
        verify_binary: false,
    },
    ToolDef {
        name: "OpenCode",
        vendor: "OpenCode",
        tool_type: AiToolType::CliTool,
        binary_names: &["opencode"],
        process_name: None,
        config_dir_check: Some(|p| p.opencode_config_dir()),
        verify_binary: false,
    },
    ToolDef {
        name: "Aider",
        vendor: "Aider",
        tool_type: AiToolType::CliTool,
        binary_names: &["aider"],
        process_name: None,
        config_dir_check: Some(|p| p.aider_config_dir()),
        verify_binary: false,
    },
    ToolDef {
        name: "Continue",
        vendor: "Continue",
        tool_type: AiToolType::CliTool,
        binary_names: &["continue"],
        process_name: None,
        config_dir_check: None,
        verify_binary: false,
    },
    ToolDef {
        name: "Cody CLI",
        vendor: "Sourcegraph",
        tool_type: AiToolType::CliTool,
        binary_names: &["cody"],
        process_name: None,
        config_dir_check: None,
        verify_binary: false,
    },
    ToolDef {
        name: "OpenClaw",
        vendor: "OpenClaw",
        tool_type: AiToolType::Agent,
        binary_names: &["openclaw"],
        process_name: None,
        config_dir_check: None,
        verify_binary: false,
    },
    ToolDef {
        name: "ClawdBot",
        vendor: "OpenSource",
        tool_type: AiToolType::Agent,
        binary_names: &["clawdbot"],
        process_name: None,
        config_dir_check: None,
        verify_binary: false,
    },
    ToolDef {
        name: "MoltBot",
        vendor: "OpenSource",
        tool_type: AiToolType::Agent,
        binary_names: &["moltbot"],
        process_name: None,
        config_dir_check: None,
        verify_binary: false,
    },
    ToolDef {
        name: "MoldBot",
        vendor: "OpenSource",
        tool_type: AiToolType::Agent,
        binary_names: &["moldbot"],
        process_name: None,
        config_dir_check: None,
        verify_binary: false,
    },
    ToolDef {
        name: "GPT Engineer",
        vendor: "GPT Engineer",
        tool_type: AiToolType::Agent,
        binary_names: &["gpt-engineer", "gpte"],
        process_name: None,
        config_dir_check: None,
        verify_binary: false,
    },
    ToolDef {
        name: "Open Interpreter",
        vendor: "Open Interpreter",
        tool_type: AiToolType::Agent,
        binary_names: &["interpreter"],
        process_name: None,
        config_dir_check: Some(|p| p.open_interpreter_config_dir()),
        verify_binary: false,
    },
    ToolDef {
        name: "Goose",
        vendor: "Block",
        tool_type: AiToolType::Agent,
        binary_names: &["goose"],
        process_name: None,
        config_dir_check: None,
        verify_binary: false,
    },
    // Mistral Vibe (github.com/mistralai/mistral-vibe): `vibe` is the CLI; `vibe-acp`, the
    // Agent Client Protocol server editors launch, is reported beside it (see `scan`).
    ToolDef {
        name: "Mistral Vibe",
        vendor: "Mistral AI",
        tool_type: AiToolType::CliTool,
        binary_names: &["vibe"],
        process_name: None,
        config_dir_check: Some(|p| p.home_dir().join(".vibe")),
        verify_binary: false,
    },
    ToolDef {
        name: "Tabby",
        vendor: "TabbyML",
        tool_type: AiToolType::CliTool,
        binary_names: &["tabby"],
        process_name: Some("tabby"),
        config_dir_check: None,
        verify_binary: false,
    },
];

/// (tool, Python distribution) for the CLIs that are Python console scripts. Their version
/// is read from the distribution's `METADATA` in the virtual environment the PATH entry
/// lives in ([`venv_dist_version`]) instead of starting an interpreter for `--version`
/// (`vibe --version` took about 1.2 s of a 1.3 s scan on the machine this was measured on).
const PYTHON_DISTS: &[(&str, &str)] = &[("Mistral Vibe", "mistral-vibe")];

/// The version of tool `name` found at `path`: from its Python distribution on disk when
/// that answers, else `<binary> --version` as before.
///
/// For a Python tool this is traced as a `version.read` span, the shape the Node tools use
/// (`rmguard.exec.program` = the binary, a closed value; `rmguard.version.source` =
/// `dist_info` when `METADATA` answered, `spawn` when it did not and the
/// `exec.version_probe` that follows does).
fn tool_version(name: &str, path: &Path) -> Option<String> {
    let Some((_, dist)) = PYTHON_DISTS.iter().find(|(t, _)| *t == name) else {
        return get_binary_version(path.to_str().unwrap_or(""));
    };
    let program = path.file_name().unwrap_or_default().to_os_string();
    let mut span = crate::otel::span("version.read", || {
        vec![Attr::str(Key::ExecProgram, crate::otel::exec_program(&program))]
    });
    let read = venv_dist_version(path, dist);
    span.set(|| {
        vec![Attr::str(
            Key::VersionSource,
            if read.is_some() { "dist_info" } else { "spawn" },
        )]
    });
    drop(span);
    read.or_else(|| get_binary_version(path.to_str().unwrap_or("")))
}

/// Most `lib/python3.*` directories and `site-packages` entries looked at per venv.
const MAX_VENV_ENTRIES: usize = 4096;

/// `Version:` of the Python distribution `dist` (PEP 503 normalised, e.g. `mistral-vibe`)
/// installed in the virtual environment whose console script `bin` (a PATH entry) is,
/// after following its symlink chain.
///
/// The resolved file must sit in `<venv>/bin/` (`Scripts\` on Windows) and `<venv>` must
/// carry a `pyvenv.cfg`: the layout of a uv tool (`~/.local/share/uv/tools/<name>/`, see
/// <https://docs.astral.sh/uv/concepts/tools/>) and of a pipx venv
/// (`~/.local/share/pipx/venvs/<name>/`). uv's `uv-receipt.toml` records the requested
/// requirement and entry points but not the installed version, so it is not used. The
/// distribution is the `<name>-<version>.dist-info` directory in
/// `<venv>/lib/python3.*/site-packages/` (`Lib\site-packages\` on Windows) whose name
/// normalises to `dist`; its `METADATA` is read through the bounded no-follow reader
/// (64 KiB head, header block only), its `Name:` must normalise to `dist`, and its
/// `Version:` must agree with the directory name and be plain version text that
/// [`crate::scanners::extract_version`] (the sanitisation a spawned `--version` gets)
/// returns unchanged. Anything else is None, and the caller spawns.
pub fn venv_dist_version(bin: &Path, dist: &str) -> Option<String> {
    use crate::scanners::exposure::pep503_normalize;
    let real = std::fs::canonicalize(bin).ok()?;
    let bin_dir = real.parent()?;
    let bin_name = bin_dir.file_name()?.to_str()?;
    if bin_name != "bin" && bin_name != "Scripts" {
        return None;
    }
    let venv = bin_dir.parent()?;
    if !std::fs::symlink_metadata(venv.join("pyvenv.cfg")).is_ok_and(|m| m.is_file()) {
        return None;
    }
    let mut site_dirs: Vec<PathBuf> = vec![venv.join("Lib").join("site-packages")];
    if let Ok(entries) = crate::scanners::probe_read_dir(venv.join("lib")) {
        let mut libs: Vec<PathBuf> = entries
            .flatten()
            .take(MAX_VENV_ENTRIES)
            .filter(|e| e.file_name().to_str().is_some_and(|n| n.starts_with("python")))
            .map(|e| e.path().join("site-packages"))
            .collect();
        libs.sort();
        site_dirs.extend(libs);
    }
    for site in site_dirs {
        let Ok(entries) = crate::scanners::probe_read_dir(&site) else {
            continue;
        };
        let mut hits: Vec<(String, PathBuf)> = entries
            .flatten()
            .take(MAX_VENV_ENTRIES)
            .filter_map(|e| {
                let n = e.file_name().to_str()?.to_string();
                let stem = n.strip_suffix(".dist-info")?;
                let (name, ver) = stem.split_once('-')?;
                (pep503_normalize(name) == dist).then(|| (ver.to_string(), e.path()))
            })
            .collect();
        hits.sort();
        // Two dist-info directories for one project is a broken environment: no answer.
        if hits.len() != 1 {
            continue;
        }
        let (dir_ver, dir) = hits.pop()?;
        let meta = dir.join("METADATA");
        let head = crate::scanners::read_head_bytes_nofollow(&meta, 64 * 1024)?;
        let text = String::from_utf8_lossy(&head);
        let (mut name, mut version) = (None, None);
        for line in text.lines() {
            if line.trim().is_empty() {
                break; // end of headers; the long description follows
            }
            if let Some(v) = line.strip_prefix("Name:") {
                name.get_or_insert_with(|| v.trim().to_string());
            } else if let Some(v) = line.strip_prefix("Version:") {
                version.get_or_insert_with(|| v.trim().to_string());
            }
        }
        let (name, v) = (name?, version?);
        let ok = pep503_normalize(&name) == dist
            && v == dir_ver
            && crate::scanners::npm_packages::is_valid_version(&v)
            && crate::scanners::extract_version(&v).as_deref() == Some(v.as_str());
        return ok.then_some(v);
    }
    None
}

/// Verify a binary is real (not a shim that says "not installed").
fn verify_binary_works(path: &std::path::Path) -> bool {
    let mut x = crate::otel::exec_span("verify_binary", path.as_os_str());
    let output = crate::scanners::child_command(path)
        .arg("--version")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output();
    match &output {
        Ok(o) => super::note_exit(&mut x, &o.status),
        Err(_) => x.outcome("spawn_failed"),
    }
    drop(x);
    match output {
        Ok(o) => {
            if !o.status.success() {
                return false;
            }
            let text =
                String::from_utf8_lossy(&o.stdout).to_lowercase() + &String::from_utf8_lossy(&o.stderr).to_lowercase();
            !text.contains("not installed") && !text.contains("command not found")
        }
        Err(_) => false,
    }
}

impl Scanner for AiToolsScanner {
    type Output = Vec<AiTool>;

    fn scan(&self, platform: &dyn PlatformInfo) -> Vec<AiTool> {
        let mut results = Vec::new();

        let home = platform.home_dir();
        let fallback_paths: &[(&str, &[std::path::PathBuf])] = &[
            (
                "Claude Code",
                &[home.join(".claude/local/claude"), home.join(".local/bin/claude")],
            ),
            ("OpenCode", &[home.join(".opencode/bin/opencode")]),
        ];

        for def in TOOLS {
            let mut found_binary: Option<std::path::PathBuf> = None;

            for bin_name in def.binary_names {
                if let Ok(path) = which::which(bin_name) {
                    found_binary = Some(path);
                    break;
                }
            }

            if found_binary.is_none() {
                for (name, paths) in fallback_paths {
                    if *name == def.name {
                        for p in *paths {
                            if crate::scanners::probe_file(p) {
                                found_binary = Some(p.clone());
                                break;
                            }
                        }
                    }
                }
            }

            // Reject shims that aren't actually installed
            if def.verify_binary
                && let Some(ref path) = found_binary
                && !verify_binary_works(path)
            {
                found_binary = None;
            }

            let has_config = def
                .config_dir_check
                .map(|f| crate::scanners::probe_dir(&f(platform)))
                .unwrap_or(false);

            if found_binary.is_some() || has_config {
                let version = found_binary.as_ref().and_then(|p| tool_version(def.name, p));

                let is_running = def.process_name.map(is_process_running).unwrap_or(false);

                let config_dir = def
                    .config_dir_check
                    .map(|f| f(platform))
                    .filter(|p| crate::scanners::probe_dir(p))
                    .map(|p| p.display().to_string());

                results.push(AiTool {
                    name: def.name.to_string(),
                    vendor: def.vendor.to_string(),
                    tool_type: match def.tool_type {
                        AiToolType::CliTool => AiToolType::CliTool,
                        AiToolType::DesktopApp => AiToolType::DesktopApp,
                        AiToolType::Agent => AiToolType::Agent,
                    },
                    version,
                    binary_path: found_binary.map(|p| p.display().to_string()),
                    config_dir,
                    install_path: None,
                    is_running,
                });
            }
        }

        // `vibe-acp`: "Mistral Vibe includes the `vibe-acp` tool" that editors run as an ACP
        // agent server (mistral-vibe docs/acp-setup.md, fetched 2026-10-24). It ships in the
        // same distribution as `vibe` (one `entry_points.txt`), so it is not run again for
        // a version: the CLI row's version is its version.
        if let Ok(acp) = which::which("vibe-acp") {
            let version = results
                .iter()
                .find(|t| t.name == "Mistral Vibe")
                .and_then(|t| t.version.clone());
            results.push(AiTool {
                name: "Mistral Vibe ACP server".to_string(),
                vendor: "Mistral AI".to_string(),
                tool_type: AiToolType::Agent,
                version,
                binary_path: Some(acp.display().to_string()),
                config_dir: None,
                install_path: None,
                is_running: false,
            });
        }

        if let Some(app_path) = platform.claude_desktop_app()
            && let Some(version) = read_claude_desktop_version(&app_path)
            && version_gte(&version, (0, 7))
        {
            results.push(AiTool {
                name: "Claude Cowork".to_string(),
                vendor: "Anthropic".to_string(),
                tool_type: AiToolType::Agent,
                version: Some(crate::scanners::sanitize_display(&version, 64)),
                binary_path: None,
                config_dir: None,
                install_path: Some(app_path.display().to_string()),
                is_running: false,
            });
        }

        for (name, vendor, path) in platform.ai_desktop_app_paths() {
            if crate::scanners::probe_exists(&path) {
                let is_running = is_process_running(path.file_stem().and_then(|s| s.to_str()).unwrap_or(""));
                results.push(AiTool {
                    name,
                    vendor,
                    tool_type: AiToolType::DesktopApp,
                    version: None,
                    binary_path: None,
                    config_dir: None,
                    install_path: Some(path.display().to_string()),
                    is_running,
                });
            }
        }

        results
    }
}

fn read_claude_desktop_version(app_path: &std::path::Path) -> Option<String> {
    #[cfg(target_os = "macos")]
    {
        let plist = app_path.join("Contents/Info.plist");
        if crate::scanners::probe_file(&plist) {
            if let Some(output) = crate::scanners::output_with_timeout(
                crate::scanners::system_command("defaults").args([
                    "read",
                    plist.to_str().unwrap_or(""),
                    "CFBundleShortVersionString",
                ]),
                std::time::Duration::from_secs(5),
            ) {
                let v = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !v.is_empty() {
                    return Some(v);
                }
            }
        }
    }
    #[cfg(target_os = "linux")]
    {
        if crate::scanners::probe_file(app_path) {
            return crate::scanners::get_binary_version(app_path.to_str().unwrap_or(""));
        }
    }
    let _ = app_path;
    None
}

pub fn version_gte(version: &str, target: (u32, u32)) -> bool {
    let parts: Vec<u32> = version
        .trim_start_matches('v')
        .split('.')
        .take(2)
        .map(|p| {
            p.chars()
                .take_while(|c| c.is_ascii_digit())
                .collect::<String>()
                .parse::<u32>()
                .unwrap_or(0)
        })
        .collect();
    if parts.is_empty() {
        return false;
    }
    let major = parts[0];
    let minor = parts.get(1).copied().unwrap_or(0);
    (major, minor) >= target
}

/// (binaries rmguard may run, process names it asks about), for the telemetry and
/// process-snapshot tests in `crate::scanners`.
#[cfg(test)]
pub(crate) fn spawn_and_process_names() -> (Vec<&'static str>, Vec<&'static str>) {
    (
        TOOLS.iter().flat_map(|d| d.binary_names.iter().copied()).collect(),
        TOOLS.iter().filter_map(|d| d.process_name).collect(),
    )
}
