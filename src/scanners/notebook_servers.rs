use crate::models::NotebookServer;
use crate::platform::PlatformInfo;
use crate::scanners::{get_binary_version, is_process_running, Scanner};

pub struct NotebookServersScanner;

struct NotebookDef {
    name: &'static str,
    binary: &'static str,
    process_name: &'static str,
}

const NOTEBOOKS: &[NotebookDef] = &[
    NotebookDef {
        name: "Jupyter Notebook",
        binary: "jupyter-notebook",
        process_name: "jupyter-noteboo",
    },
    NotebookDef {
        name: "JupyterLab",
        binary: "jupyter-lab",
        process_name: "jupyter-lab",
    },
    NotebookDef {
        name: "Jupyter",
        binary: "jupyter",
        process_name: "jupyter",
    },
    NotebookDef {
        name: "Marimo",
        binary: "marimo",
        process_name: "marimo",
    },
];

impl Scanner for NotebookServersScanner {
    type Output = Vec<NotebookServer>;

    fn scan(&self, _platform: &dyn PlatformInfo) -> Vec<NotebookServer> {
        let mut results = Vec::new();

        for def in NOTEBOOKS {
            if let Ok(path) = which::which(def.binary) {
                let version = get_binary_version(def.binary);
                let is_running = is_process_running(def.process_name);

                results.push(NotebookServer {
                    name: def.name.to_string(),
                    version,
                    binary_path: Some(path.display().to_string()),
                    is_running,
                });
            }
        }

        results
    }
}

/// (binaries rmguard may run, process names it asks about), for the telemetry and
/// process-snapshot tests in `crate::scanners`.
#[cfg(test)]
pub(crate) fn spawn_and_process_names() -> (Vec<&'static str>, Vec<&'static str>) {
    (NOTEBOOKS.iter().map(|d| d.binary).collect(), NOTEBOOKS.iter().map(|d| d.process_name).collect())
}
