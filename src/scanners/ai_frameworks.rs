use crate::models::AiFramework;
use crate::platform::PlatformInfo;
use crate::scanners::{get_binary_version, is_process_running, Scanner};

pub struct AiFrameworksScanner;

struct FrameworkDef {
    name: &'static str,
    vendor: &'static str,
    binary_names: &'static [&'static str],
    process_name: &'static str,
}

const FRAMEWORKS: &[FrameworkDef] = &[
    FrameworkDef {
        name: "Ollama",
        vendor: "Ollama",
        binary_names: &["ollama"],
        process_name: "ollama",
    },
    FrameworkDef {
        name: "LocalAI",
        vendor: "LocalAI",
        binary_names: &["local-ai", "localai"],
        process_name: "local-ai",
    },
    FrameworkDef {
        name: "LM Studio",
        vendor: "LM Studio",
        binary_names: &["lms"],
        process_name: "lm-studio",
    },
    FrameworkDef {
        name: "llama.cpp Server",
        vendor: "ggerganov",
        binary_names: &["llama-server", "llama-cli"],
        process_name: "llama-server",
    },
    // New: additional frameworks
    FrameworkDef {
        name: "vLLM",
        vendor: "vLLM",
        binary_names: &["vllm"],
        process_name: "vllm",
    },
    FrameworkDef {
        name: "text-generation-inference",
        vendor: "Hugging Face",
        binary_names: &["text-generation-launcher"],
        process_name: "text-generation",
    },
];

impl Scanner for AiFrameworksScanner {
    type Output = Vec<AiFramework>;

    fn scan(&self, _platform: &dyn PlatformInfo) -> Vec<AiFramework> {
        let mut results = Vec::new();

        for def in FRAMEWORKS {
            let mut found_binary: Option<std::path::PathBuf> = None;

            for bin_name in def.binary_names {
                if let Ok(path) = which::which(bin_name) {
                    found_binary = Some(path);
                    break;
                }
            }

            let is_running = is_process_running(def.process_name);

            if found_binary.is_some() || is_running {
                let version = found_binary
                    .as_ref()
                    .and_then(|p| get_binary_version(p.to_str().unwrap_or("")));

                results.push(AiFramework {
                    name: def.name.to_string(),
                    vendor: def.vendor.to_string(),
                    version,
                    binary_path: found_binary.map(|p| p.display().to_string()),
                    is_running,
                });
            }
        }

        results
    }
}
