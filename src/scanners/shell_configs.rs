use crate::models::ShellConfig;
use crate::platform::PlatformInfo;
use crate::scanners::Scanner;

pub struct ShellConfigsScanner;

/// Patterns that indicate AI-related configuration in shell files.
/// These are matched as whole-word prefixes to avoid false positives
/// (e.g., MAIL_DELIVERY matching "AI_").
const AI_KEY_PATTERNS: &[&str] = &[
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "CLAUDE_API_KEY",
    "CLAUDE_CODE",
    "COPILOT_TOKEN",
    "GEMINI_API_KEY",
    "GOOGLE_AI_STUDIO",
    "HF_TOKEN",
    "HUGGING_FACE_HUB_TOKEN",
    "REPLICATE_API_TOKEN",
    "TOGETHER_API_KEY",
    "GROQ_API_KEY",
    "MISTRAL_API_KEY",
    "COHERE_API_KEY",
    "OLLAMA_HOST",
    "OLLAMA_MODELS",
];

/// Alias patterns (these don't contain secrets, safe to report as-is).
const ALIAS_PATTERNS: &[&str] = &[
    "alias claude",
    "alias copilot",
    "alias aider",
    "alias ollama",
];

impl Scanner for ShellConfigsScanner {
    type Output = Vec<ShellConfig>;

    fn scan(&self, platform: &dyn PlatformInfo) -> Vec<ShellConfig> {
        let mut results = Vec::new();

        for (shell, path) in platform.shell_config_paths() {
            if !path.is_file() {
                continue;
            }

            // Size guard: skip files over 1MB
            let meta = match std::fs::metadata(&path) {
                Ok(m) => m,
                Err(_) => continue,
            };
            if meta.len() > 1_048_576 {
                continue;
            }

            let content = match std::fs::read_to_string(&path) {
                Ok(c) => c,
                Err(_) => continue,
            };

            let mut ai_entries = Vec::new();
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with('#') || trimmed.is_empty() {
                    continue;
                }

                // Check for key patterns — report only the variable name, never the value
                for pattern in AI_KEY_PATTERNS {
                    if trimmed.contains(pattern) {
                        ai_entries.push(format!("{pattern}=<redacted>"));
                        break;
                    }
                }

                // Check alias patterns (safe to report)
                for pattern in ALIAS_PATTERNS {
                    if trimmed.starts_with(pattern) {
                        ai_entries.push(format!("{pattern} (alias defined)"));
                        break;
                    }
                }
            }

            if !ai_entries.is_empty() {
                results.push(ShellConfig {
                    shell,
                    config_path: path.display().to_string(),
                    ai_related_entries: ai_entries,
                });
            }
        }

        results
    }
}
