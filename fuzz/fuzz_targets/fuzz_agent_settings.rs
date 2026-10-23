#![no_main]
use libfuzzer_sys::fuzz_target;
use rustmachineguard::scanners::hook_sources::{self as hs, Dialect, HookCtx, RegistersRule};

const DIALECTS: [Dialect; 7] = [
    Dialect::Claude,
    Dialect::Cursor,
    Dialect::Copilot,
    Dialect::DevinDesktop,
    Dialect::Gemini,
    Dialect::DevinCli,
    Dialect::Codex,
];

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let p = std::path::Path::new("/p/.claude/settings.json");
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(s) {
            let _ = rustmachineguard::scanners::agent_settings::extract_hooks(&v, p);
            let _ = rustmachineguard::scanners::agent_settings::extract_cursor_hooks(&v, p);
            let _ = rustmachineguard::scanners::agent_settings::extract_helper_commands(&v, p);
            let _ = rustmachineguard::scanners::agent_settings::extract_login_gateway(&v, "user-global");
            // Every hook dialect: the `hooks` map, or the whole file for Devin CLI's
            // hooks.v1.json.
            for d in DIALECTS {
                let map = if d == Dialect::DevinCli { &v } else { v.get("hooks").unwrap_or(&v) };
                let _ = hs::extract_hook_map(map, &HookCtx::new(p, d));
            }
            let _ = hs::extract_kiro_hooks(&v, &HookCtx::new(p, Dialect::Claude));
            let _ = hs::extract_settings_commands(&v, p);
        }
        // The hook-command classifier walks arbitrary command text and resolves
        // referenced paths; it must be total on junk input.
        let _ = rustmachineguard::scanners::agent_settings::classify_hook_command(s, p);
        let _ = rustmachineguard::scanners::agent_settings::helper_dangerous(s);
        let _ = rustmachineguard::scanners::skills::frontmatter_hooks(s, p, p, None);
        let _ = hs::module_registers(s, RegistersRule::ClaudeMod);
        let _ = hs::module_registers(s, RegistersRule::OpenCode);
        // The guard/loopback segmenter, the module source lexer and the hook redactor
        // walk attacker-chosen text byte by byte.
        let _ = hs::command_verdict(s);
        let _ = hs::module_hook("m.ts", Some(s), RegistersRule::OpenCode);
        let shown = hs::shown_text(s, 4000);
        assert!(!shown.contains('\u{1b}'));
        let _ = rustmachineguard::scanners::redact_webhook_urls(s);
    }
});
