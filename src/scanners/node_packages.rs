use crate::models::NodePackageManager;
use crate::platform::PlatformInfo;
use crate::scanners::{get_binary_version, Scanner};

pub struct NodePackagesScanner;

const PACKAGE_MANAGERS: &[(&str, &[&str])] = &[
    ("npm", &["npm"]),
    ("yarn", &["yarn"]),
    ("pnpm", &["pnpm"]),
    ("bun", &["bun"]),
];

impl Scanner for NodePackagesScanner {
    type Output = Vec<NodePackageManager>;

    fn scan(&self, _platform: &dyn PlatformInfo) -> Vec<NodePackageManager> {
        let mut results = Vec::new();

        for (name, bin_names) in PACKAGE_MANAGERS {
            for bin_name in *bin_names {
                if let Ok(path) = which::which(bin_name) {
                    let version = get_binary_version(bin_name);
                    results.push(NodePackageManager {
                        name: name.to_string(),
                        version,
                        path: Some(path.display().to_string()),
                    });
                    break;
                }
            }
        }

        // Also check for Node.js itself
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
