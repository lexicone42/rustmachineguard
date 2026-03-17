use crate::models::ContainerTool;
use crate::platform::PlatformInfo;
use crate::scanners::{get_binary_version, is_process_running, Scanner};

pub struct ContainerToolsScanner;

struct ContainerDef {
    name: &'static str,
    binary: &'static str,
    process_name: &'static str,
}

const CONTAINER_TOOLS: &[ContainerDef] = &[
    ContainerDef {
        name: "Docker",
        binary: "docker",
        process_name: "dockerd",
    },
    ContainerDef {
        name: "Podman",
        binary: "podman",
        process_name: "podman",
    },
    ContainerDef {
        name: "nerdctl",
        binary: "nerdctl",
        process_name: "containerd",
    },
    ContainerDef {
        name: "Lima",
        binary: "limactl",
        process_name: "limactl",
    },
    ContainerDef {
        name: "Colima",
        binary: "colima",
        process_name: "colima",
    },
    ContainerDef {
        name: "Rancher Desktop",
        binary: "rdctl",
        process_name: "rancher-desktop",
    },
    ContainerDef {
        name: "Finch",
        binary: "finch",
        process_name: "finch",
    },
];

impl Scanner for ContainerToolsScanner {
    type Output = Vec<ContainerTool>;

    fn scan(&self, _platform: &dyn PlatformInfo) -> Vec<ContainerTool> {
        let mut results = Vec::new();

        for def in CONTAINER_TOOLS {
            if let Ok(path) = which::which(def.binary) {
                let version = get_binary_version(def.binary);
                let is_running = is_process_running(def.process_name);

                results.push(ContainerTool {
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
