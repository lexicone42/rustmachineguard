use crate::models::{PassphraseStatus, ScanReport};
use serde::Serialize;

/// Generate a CycloneDX 2.0 Blueprint document from scan results.
///
/// Conforms to the draft CycloneDX 2.0 threat-modeling schema (branch
/// `2.0-dev`, head 72b37340 as of 2026-08-26). The 2.0 milestone was due 2026-08-31 but
/// has slipped — upstream now targets a fall 2026 release. Schema source:
/// github.com/CycloneDX/specification (Apache-2.0).
///
/// Output is validated against the vendored schema by `tests/blueprint_schema.rs`,
/// which is the conformance gate — drift in either the generator or a re-vendored
/// schema fails the build. Notable structural requirements of this draft:
/// - root envelope is `specFormat` (renamed from `bomFormat`), `specVersion` "2.0"
/// - `metadata.tools` is an object `{ components, services }`, not an array
/// - components have no top-level `purl` (we carry it as an `rmg:purl` property)
/// - `behaviors` is an object `{ instances: [...] }`, not a bare array
/// - each `behaviorInstance` requires a `bom-ref`, forbids `properties`, and its
///   `behavior` must be a value from the closed behavior taxonomy (e.g.
///   `ai:agent:invokesTool`) — so human-readable specifics live on the related asset
/// - `acknowledgment` is an array of enum values (declared | observed)
/// - `flow` carries required `type` and `destination` (not `target`)
///
/// The draft is still moving; re-vendor `tests/fixtures/` and re-run the gate when
/// bumping the pin.
pub fn render(report: &ScanReport) -> String {
    let doc = BlueprintDocument::from_report(report);
    serde_json::to_string_pretty(&doc).unwrap_or_default()
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BlueprintDocument {
    // CycloneDX 2.0 renamed the root envelope: `specFormat` (was `bomFormat`).
    spec_format: &'static str,
    spec_version: &'static str,
    version: u32,
    metadata: DocMetadata,
    components: Vec<Component>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    dependencies: Vec<Dependency>,
    blueprints: Vec<Blueprint>,
    // The risk layer — omitted entirely when there's nothing to say.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    vulnerabilities: Vec<Vulnerability>,
    #[serde(skip_serializing_if = "Option::is_none")]
    threats: Option<ThreatsWrapper>,
    #[serde(skip_serializing_if = "Option::is_none")]
    risks: Option<RisksWrapper>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    controls: Vec<Control>,
}

#[derive(Serialize)]
struct DocMetadata {
    timestamp: String,
    // CycloneDX 2.0: `tools` is an object { components, services }, not an array.
    tools: DocTools,
    component: DocComponent,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    properties: Vec<Property>,
}

#[derive(Serialize)]
struct DocTools {
    components: Vec<DocToolComponent>,
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct DocToolComponent {
    #[serde(rename = "type")]
    component_type: &'static str,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    group: Option<String>,
    version: String,
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct DocComponent {
    #[serde(rename = "type")]
    component_type: &'static str,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct Component {
    #[serde(rename = "type")]
    component_type: String,
    #[serde(rename = "bom-ref")]
    bom_ref: String,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    group: Option<String>,
    // CycloneDX 2.0 components have no top-level `purl`; we carry it as a property.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    properties: Vec<Property>,
}

#[derive(Serialize, Clone)]
struct Property {
    name: String,
    value: String,
}

#[derive(Serialize)]
struct Dependency {
    #[serde(rename = "ref")]
    dep_ref: String,
    #[serde(rename = "dependsOn")]
    depends_on: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Blueprint {
    #[serde(rename = "bom-ref")]
    bom_ref: String,
    name: String,
    description: String,
    model_types: Vec<String>,
    assets: Vec<Asset>,
    #[serde(skip_serializing_if = "Behaviors::is_empty")]
    behaviors: Behaviors,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    flows: Vec<Flow>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    zones: Vec<Zone>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    boundaries: Vec<Boundary>,
}

/// CycloneDX 2.0 `behaviors` is an object with `instances` (and optional `graphs`).
#[derive(Serialize, Default)]
struct Behaviors {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    instances: Vec<BehaviorInstance>,
}

impl Behaviors {
    fn is_empty(&self) -> bool {
        self.instances.is_empty()
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Asset {
    #[serde(rename = "bom-ref")]
    bom_ref: String,
    #[serde(rename = "type")]
    asset_type: String,
    // Omitted for component-backed assets to satisfy the asset `oneOf`
    // (Component Reference branch vs Inline Asset branch).
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    zone: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    component_ref: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    responsibilities: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    interfaces: Vec<Interface>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    properties: Vec<Property>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Interface {
    name: String,
    #[serde(rename = "type")]
    interface_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    protocol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    data_format: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BehaviorInstance {
    #[serde(rename = "bom-ref")]
    bom_ref: String,
    behavior: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    acknowledgment: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    actors: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    targets: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Flow {
    #[serde(rename = "bom-ref")]
    bom_ref: String,
    name: String,
    #[serde(rename = "type")]
    flow_type: String,
    source: String,
    destination: String,
    /// Whether the hop is encrypted. `Some(false)` on a plaintext (http://) remote MCP
    /// flow makes the transport risk visible in the model; `None` for local stdio pipes
    /// where transport encryption doesn't apply.
    #[serde(skip_serializing_if = "Option::is_none")]
    encrypted: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Zone {
    #[serde(rename = "bom-ref")]
    bom_ref: String,
    name: String,
    #[serde(rename = "type")]
    zone_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Boundary {
    #[serde(rename = "bom-ref")]
    bom_ref: String,
    #[serde(rename = "type")]
    boundary_type: String,
    zones: Vec<String>,
}

// ── The risk layer (top-level in CycloneDX 2.0) ──────────────────────────────
// These carry what used to live only in `rmg:` properties or the separate terminal
// report: each finding is a `threat`, the toxic-flow surface is a scored `risk`, and
// the compliance assessment becomes `controls` — all native, standards-track fields.

/// `threats` is an object wrapper (`{ threats: [...], attackPatterns: [...] }`).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ThreatsWrapper {
    threats: Vec<Threat>,
    /// The CAPEC attack-pattern objects threats reference by bom-ref.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    attack_patterns: Vec<AttackPattern>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Threat {
    #[serde(rename = "bom-ref")]
    bom_ref: String,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    /// bom-refs of assets this threat acts on. Kept to emitted refs (no dangling links).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    affected_assets: Vec<String>,
    /// bom-refs of top-level `vulnerabilities[]` entries (CVEs).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    related_vulnerabilities: Vec<String>,
    /// bom-refs of `attackPattern` objects in the threats wrapper (CAPEC).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    attack_patterns: Vec<String>,
}

/// A CAPEC attack pattern. `capecId` is a native integer field in the schema.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AttackPattern {
    #[serde(rename = "bom-ref")]
    bom_ref: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    capec_id: Option<u32>,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
}

/// A top-level CycloneDX vulnerability (a CVE), referenced by a threat.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Vulnerability {
    #[serde(rename = "bom-ref")]
    bom_ref: String,
    id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    ratings: Vec<VulnRating>,
}

/// A CVSS rating for a vulnerability. We emit `score` + the derived `severity` band
/// only: the advisory text states a base score but not the scoring method version or
/// the vector string, and inventing either would be a fabrication.
#[derive(Serialize)]
struct VulnRating {
    score: f64,
    severity: String,
}

/// `risks` is an object wrapper (`{ risks: [...] }`).
#[derive(Serialize)]
struct RisksWrapper {
    risks: Vec<Risk>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Risk {
    #[serde(rename = "bom-ref")]
    bom_ref: String,
    name: String,
    statement: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    affects: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    related_threats: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    inherent_risk: Option<Rating>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    responses: Vec<RiskResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<String>,
}

/// A likelihood × impact rating. Both sub-objects carry a required `level` (from
/// different enums, but the same field name).
#[derive(Serialize)]
struct Rating {
    likelihood: Level,
    impact: Level,
}

#[derive(Serialize)]
struct Level {
    level: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RiskResponse {
    #[serde(rename = "bom-ref")]
    bom_ref: String,
    /// avoid | reduce | transfer | accept | exploit | enhance
    strategy: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    priority: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Control {
    #[serde(rename = "bom-ref")]
    bom_ref: String,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    /// implementationStatus: recommended | planned | in-progress | implemented | …
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    applies_to: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    effectiveness: Option<Effectiveness>,
}

#[derive(Serialize)]
struct Effectiveness {
    /// ineffective | marginal | adequate | good | excellent
    rating: String,
}

// Injection-specific phrases that suggest MCP tool/resource description poisoning
// (hidden instructions aimed at the agent). Chosen to be multi-word to minimise
// false positives on benign descriptions like "Always returns JSON". Covers the
// Trail-of-Bits "line jumping" / Invariant Labs tool-poisoning families and the
// CyberArk "Poison everywhere" resource-description variant.
const POISONING_PATTERNS: &[&str] = &[
    "ignore previous",
    "ignore all previous",
    "disregard previous",
    "disregard the above",
    "you must ignore",
    "override previous instructions",
    "do not tell the user",
    "do not mention",
    "do not display",
    "do not show the user",
    "never reveal",
    "always include the contents of",
    "before using this tool",
    "before you use this tool",
    "first read",
    "pass as a sidenote",
    "this is very important",
    "system prompt",
    "hidden instruction",
    "<important>",
    "</important>",
    "<secret>",
    "<system-prompt>",
    "<system>",
    "```system",
];

/// Recursively append every `"description"` string found in a JSON-Schema value to
/// `out` (separated by spaces), so parameter descriptions are scanned for injection.
fn collect_schema_descriptions(schema: &serde_json::Value, out: &mut String) {
    match schema {
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                if k == "description" {
                    if let Some(s) = v.as_str() {
                        out.push(' ');
                        out.push_str(s);
                    }
                } else {
                    collect_schema_descriptions(v, out);
                }
            }
        }
        serde_json::Value::Array(arr) => {
            for v in arr {
                collect_schema_descriptions(v, out);
            }
        }
        _ => {}
    }
}

/// Scan text for known prompt-injection / line-jumping phrases.
/// Lowercases once; returns the matched patterns in catalog order.
fn scan_injection_text(text: &str) -> Vec<&'static str> {
    let lower = text.to_lowercase();
    POISONING_PATTERNS
        .iter()
        .filter(|p| lower.contains(**p))
        .copied()
        .collect()
}

// Invisible-Unicode detection lives in `scanners` so every text surface (MCP tool
// descriptions, rules files, skills) uses the same detector.
use crate::scanners::scan_suspicious_unicode;


/// Map an internal behavior label to a value from the CycloneDX 2.0 behavior
/// taxonomy (a closed enum). The schema requires `behaviorInstance.behavior` to be
/// a taxonomy value, so the human-readable specifics live on the related asset
/// instead. `prefix:rest` labels are matched on their prefix.
fn map_behavior_to_taxonomy(label: &str) -> &'static str {
    let head = label.split(':').next().unwrap_or(label);
    match head {
        // Capability labels (skills + observed probe capabilities)
        "shell" => "application:codeExecution:executesNativeCommand",
        "network" => "network",
        "filesystem" => "file",
        "environment" => "system:configuration:readsEnvironmentVariable",
        "database" => "data:query",
        "browser" => "application",
        "source_control" => "data",
        "communication" => "network:transmission:sendsData",
        "clipboard" => "system",
        "skill_invoke" => "ai:agent:invokesTool",
        // Probe-derived tool invocations
        "mcp-tool" => "ai:agent:invokesTool",
        // Settings hooks run shell commands on agent events
        "hook-exec" => "application:codeExecution:executesNativeCommand",
        "mcp-auto-approve" => "security",
        // Two servers offering the same tool name (confused-deputy / shadowing)
        "tool-shadowing" => "security",
        // Lethal-trifecta surface: sensitive source + exfil sink across the surface
        "toxic-flow-surface" => "security",
        // Rules-file dangerous patterns → code execution risk (detail on the asset)
        "dangerous-pattern" => "application:codeExecution",
        // Threat-catalog match and blast-radius are security findings; detail lives
        // on the exposure / ssh-key / cloud-credential asset.
        "exposure-catalog-match" => "security",
        "blast-radius" => "security:authentication",
        // Anything else falls back to the agent-action domain.
        _ => "ai:agent:executesAction",
    }
}

/// Accumulates behaviors and assigns each a unique bom-ref.
struct BehaviorBuilder {
    instances: Vec<BehaviorInstance>,
    next: usize,
}

impl BehaviorBuilder {
    fn new() -> Self {
        Self {
            instances: Vec::new(),
            next: 0,
        }
    }

    /// `label` is an internal, human-readable behavior label; it is mapped to a
    /// CycloneDX behavior-taxonomy value for the emitted `behavior` field.
    fn push(
        &mut self,
        label: String,
        acknowledgment: Vec<String>,
        actors: Vec<String>,
        targets: Vec<String>,
    ) {
        let bom_ref = format!("behavior:{}", self.next);
        self.next += 1;
        self.instances.push(BehaviorInstance {
            bom_ref,
            behavior: map_behavior_to_taxonomy(&label).to_string(),
            acknowledgment,
            actors,
            targets,
        });
    }
}

/// The first single-quoted token in a string, e.g. the server name in
/// "MCP server 'analytics' uses plaintext HTTP …". Used to link a finding to the
/// specific asset it names. The finding titles are generated by this crate, so the
/// format is stable (guarded by tests).
fn first_single_quoted(s: &str) -> Option<&str> {
    let start = s.find('\'')? + 1;
    let rest = s.get(start..)?;
    let end = rest.find('\'')?;
    rest.get(..end)
}

/// Locate every `CVE-YYYY-NNNN` in `text`, returning `(start, end, id)` byte spans.
/// ASCII-case-insensitive; the returned id is normalized to upper case.
fn find_cve_spans(text: &str) -> Vec<(usize, usize, String)> {
    let b = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 4 <= b.len() {
        if b[i..i + 4].eq_ignore_ascii_case(b"CVE-") {
            let year_start = i + 4;
            let mut j = year_start;
            while j < b.len() && b[j].is_ascii_digit() {
                j += 1;
            }
            if j - year_start >= 4 && j < b.len() && b[j] == b'-' {
                let num_start = j + 1;
                let mut k = num_start;
                while k < b.len() && b[k].is_ascii_digit() {
                    k += 1;
                }
                if k > num_start {
                    out.push((
                        i,
                        k,
                        format!("CVE-{}-{}", &text[year_start..j], &text[num_start..k]),
                    ));
                    i = k;
                    continue;
                }
            }
        }
        i += 1;
    }
    out
}

/// Find a CVSS base score in `window` — the first number in 0.0..=10.0 following a
/// "CVSS" marker that is not part of a version token. Numbers directly preceded by
/// `v`/`V` or `:` are version markers ("CVSS v3.1", "CVSS:3.1/AV:N/...") and skipped,
/// so "CVSS v3.1 9.6" yields 9.6, not 3.1.
fn cvss_score_in(window: &str) -> Option<f64> {
    let b = window.as_bytes();
    let mut i = 0usize;
    while i + 4 <= b.len() {
        if !b[i..i + 4].eq_ignore_ascii_case(b"CVSS") {
            i += 1;
            continue;
        }
        let mut j = i + 4;
        while j < b.len() {
            if b[j].is_ascii_digit() {
                let is_version_token =
                    j > 0 && (b[j - 1] == b'v' || b[j - 1] == b'V' || b[j - 1] == b':');
                let start = j;
                while j < b.len() && (b[j].is_ascii_digit() || b[j] == b'.') {
                    j += 1;
                }
                if !is_version_token
                    && let Ok(score) = window[start..j].trim_end_matches('.').parse::<f64>()
                    && (0.0..=10.0).contains(&score)
                {
                    return Some(score);
                }
            } else {
                j += 1;
            }
        }
        i += 1;
    }
    None
}

/// Pull CVE identifiers out of advisory text along with an adjacent CVSS base score
/// when the advisory states one. A score is only attributed to a CVE if it appears
/// before the NEXT CVE id, so "CVE-A (CVSS 8.4) + CVE-B (CVSS 7.3)" attributes each
/// score correctly and a CVE with no stated score gets `None`.
fn extract_cve_ratings(text: &str) -> Vec<(String, Option<f64>)> {
    let spans = find_cve_spans(text);
    let mut out: Vec<(String, Option<f64>)> = Vec::new();
    for (idx, (_, end, id)) in spans.iter().enumerate() {
        // The window runs to the next CVE id (so scores aren't stolen from a later CVE),
        // capped so a score far downstream isn't misattributed.
        let next_start = spans.get(idx + 1).map(|(s, _, _)| *s).unwrap_or(text.len());
        let cap = (end + 40).min(text.len());
        let mut window_end = next_start.min(cap);
        while window_end < text.len() && !text.is_char_boundary(window_end) {
            window_end += 1;
        }
        let score = text.get(*end..window_end).and_then(cvss_score_in);
        if !out.iter().any(|(existing, _)| existing == id) {
            out.push((id.clone(), score));
        }
    }
    out
}

/// CVSS severity band for a base score. The bands are identical in CVSS v3.x and v4,
/// so this is safe without knowing which version produced the score.
fn cvss_severity(score: f64) -> &'static str {
    if score >= 9.0 {
        "critical"
    } else if score >= 7.0 {
        "high"
    } else if score >= 4.0 {
        "medium"
    } else if score > 0.0 {
        "low"
    } else {
        "none"
    }
}

/// Map a finding category to a CAPEC attack pattern `(id, name, plain-language gloss)`.
/// Only well-established, defensible mappings are returned; categories without a clean
/// CAPEC (e.g. prompt-injection via a rules file) return None rather than force a fit.
fn capec_for_category(category: &str) -> Option<(u32, &'static str, &'static str)> {
    Some(match category {
        "MCP transport" => (
            157,
            "Sniffing Attacks",
            "Intercepting unencrypted traffic to capture tokens and data in transit.",
        ),
        "Gateway routing" => (
            94,
            "Adversary in the Middle (AiTM)",
            "Routing requests through an attacker-controlled host that can read and alter them.",
        ),
        "MCP command" => (
            185,
            "Malicious Software Download",
            "Causing the victim to fetch and run attacker-controlled code at startup.",
        ),
        "Exposure" => (
            437,
            "Supply Chain",
            "Compromise introduced through a dependency or package the victim trusts.",
        ),
        "Hook" => (
            242,
            "Code Injection",
            "Injecting commands that execute in the victim's context.",
        ),
        "MCP secret" | "Settings secret" | "Secret leak" | "Secret exposure" | "Credential"
        | "Transcript exposure" => (
            37,
            "Retrieve Embedded Sensitive Data",
            "Reading credentials or sensitive data left accessible at rest.",
        ),
        _ => return None,
    })
}

impl BlueprintDocument {
    fn from_report(report: &ScanReport) -> Self {
        let mut components = Vec::new();
        let mut assets = Vec::new();
        let mut behaviors = BehaviorBuilder::new();
        let mut flows = Vec::new();
        let mut host_deps = Vec::new();

        let host_ref = format!(
            "host:{}",
            report.device.hostname.replace(' ', "-").to_lowercase()
        );

        // Zone definitions
        let zones = vec![
            Zone {
                bom_ref: "zone:local".into(),
                name: "Local Machine".into(),
                zone_type: "trust".into(),
                description: Some("Developer workstation — local processes and files".into()),
            },
            Zone {
                bom_ref: "zone:remote".into(),
                name: "Remote Services".into(),
                zone_type: "trust".into(),
                description: Some("External MCP servers, APIs, and cloud services".into()),
            },
        ];

        let boundaries = vec![Boundary {
            bom_ref: "boundary:local-remote".into(),
            boundary_type: "trust".into(),
            zones: vec!["zone:local".into(), "zone:remote".into()],
        }];

        // The scanned machine itself — a `system` asset that the risk layer
        // (threats / risks / controls) attaches to. Per-asset precision (a threat
        // pointing at the exact gateway/endpoint) is the next refinement; for now the
        // machine is the shared, always-valid anchor.
        let machine_ref = format!("asset:{host_ref}");
        assets.push(Asset {
            bom_ref: machine_ref.clone(),
            asset_type: "system".into(),
            name: Some(report.device.hostname.clone()),
            description: Some(format!(
                "The scanned developer machine ({} {})",
                report.device.os_name, report.device.os_version
            )),
            zone: Some("zone:local".into()),
            component_ref: None,
            responsibilities: Vec::new(),
            interfaces: Vec::new(),
            properties: Vec::new(),
        });

        // AI tools → agent assets
        for tool in &report.ai_agents_and_tools {
            let comp_ref = format!("ai-tool:{}", tool.name.replace(' ', "-").to_lowercase());

            components.push(Component {
                component_type: "application".into(),
                bom_ref: comp_ref.clone(),
                name: tool.name.clone(),
                version: tool.version.clone(),
                group: None,
                properties: vec![Property {
                    name: "rmg:tool-type".into(),
                    value: format!("{:?}", tool.tool_type),
                }],
            });

            assets.push(Asset {
                bom_ref: format!("asset:{}", comp_ref),
                asset_type: "agent".into(),
                name: None, // component-backed
                description: Some(format!("{} by {}", tool.name, tool.vendor)),
                zone: Some("zone:local".into()),
                component_ref: Some(comp_ref.clone()),
                responsibilities: vec!["Code generation".into(), "Tool orchestration".into()],
                interfaces: Vec::new(),
                properties: Vec::new(),
            });

            host_deps.push(comp_ref);
        }

        // MCP servers → tool assets + flows
        for mcp in &report.mcp_configs {
            for server in &mcp.servers {
                let comp_ref = format!("mcp:{}", server.name);

                let mut props = vec![
                    Property {
                        name: "rmg:transport".into(),
                        value: server.transport.clone(),
                    },
                    Property {
                        name: "rmg:config-source".into(),
                        value: mcp.config_source.clone(),
                    },
                ];
                // CycloneDX 2.0 components have no top-level purl; carry it as a property.
                if let Some(purl) = build_purl(
                    server.package_ecosystem.as_deref(),
                    server.package_name.as_deref(),
                    server.package_version.as_deref(),
                ) {
                    props.push(Property {
                        name: "rmg:purl".into(),
                        value: purl,
                    });
                }
                if let Some(ref cmd) = server.command {
                    props.push(Property {
                        name: "rmg:command".into(),
                        value: cmd.clone(),
                    });
                }
                if !server.args.is_empty() {
                    props.push(Property {
                        name: "rmg:args".into(),
                        value: server.args.join(" "),
                    });
                }

                components.push(Component {
                    component_type: "application".into(),
                    bom_ref: comp_ref.clone(),
                    name: server
                        .package_name
                        .clone()
                        .unwrap_or_else(|| server.name.clone()),
                    version: server.package_version.clone(),
                    group: server
                        .package_ecosystem
                        .as_ref()
                        .map(|e| format!("mcp-server/{}", e)),
                    properties: props,
                });

                let zone = match server.transport.as_str() {
                    "sse" | "http" => "zone:remote",
                    _ => "zone:local",
                };

                let interface_type = match server.transport.as_str() {
                    "sse" => "stream",
                    "stdio" => "cli",
                    _ => "api",
                };

                assets.push(Asset {
                    bom_ref: format!("asset:{}", comp_ref),
                    asset_type: "tool".into(),
                    name: None, // component-backed
                    description: Some(format!(
                        "MCP server '{}' ({} transport)",
                        server.name, server.transport
                    )),
                    zone: Some(zone.into()),
                    component_ref: Some(comp_ref.clone()),
                    responsibilities: Vec::new(),
                    interfaces: vec![Interface {
                        name: format!("{}-interface", server.name),
                        interface_type: interface_type.into(),
                        protocol: Some("mcp".into()),
                        data_format: Some("JSON-RPC".into()),
                    }],
                    properties: Vec::new(),
                });

                // Flow from each agent to this tool (control edge: agent invokes tool)
                for tool in &report.ai_agents_and_tools {
                    let agent_ref = format!(
                        "asset:ai-tool:{}",
                        tool.name.replace(' ', "-").to_lowercase()
                    );
                    flows.push(Flow {
                        bom_ref: format!(
                            "flow:{}->{}",
                            tool.name.replace(' ', "-").to_lowercase(),
                            server.name
                        ),
                        name: format!("{} → {}", tool.name, server.name),
                        flow_type: "control".into(),
                        source: agent_ref,
                        destination: format!("asset:{}", comp_ref),
                        // A remote http:// server is a plaintext hop; https:// is encrypted;
                        // a local stdio pipe has no transport encryption to speak of.
                        encrypted: server.url.as_deref().map(|u| {
                            !u.to_ascii_lowercase().starts_with("http://")
                        }),
                        description: Some(format!(
                            "MCP tool invocation via {} transport",
                            server.transport
                        )),
                    });
                }

                host_deps.push(comp_ref);
            }
        }

        // Agent skills → tool assets with capability behaviors
        for skill in &report.agent_skills {
            let comp_ref = format!("skill:{}:{}", skill.framework, skill.name);

            components.push(Component {
                component_type: "application".into(),
                bom_ref: comp_ref.clone(),
                name: skill.name.clone(),
                version: None,
                group: Some(format!("agent-skill/{}", skill.framework)),
                properties: vec![
                    Property {
                        name: "rmg:skill-hash".into(),
                        value: format!("sha256:{}", skill.sha256),
                    },
                    Property {
                        name: "rmg:skill-type".into(),
                        value: skill.scope.clone(),
                    },
                ],
            });

            assets.push(Asset {
                bom_ref: format!("asset:{}", comp_ref),
                asset_type: "tool".into(),
                name: None, // component-backed
                description: Some(format!(
                    "{} {} skill ({})",
                    skill.framework, skill.scope, skill.file_type
                )),
                zone: Some("zone:local".into()),
                component_ref: Some(comp_ref.clone()),
                responsibilities: Vec::new(),
                interfaces: Vec::new(),
                properties: Vec::new(),
            });

            // Each capability becomes a declared behavior
            for cap in &skill.capabilities {
                behaviors.push(
                    cap.clone(),
                    vec!["declared".into()],
                    vec![format!("asset:{}", comp_ref)],
                    Vec::new(),
                );
            }

            // Flow from agent to skill (control edge: agent executes skill)
            for tool in &report.ai_agents_and_tools {
                let agent_ref = format!(
                    "asset:ai-tool:{}",
                    tool.name.replace(' ', "-").to_lowercase()
                );
                flows.push(Flow {
                    bom_ref: format!(
                        "flow:{}->{}",
                        tool.name.replace(' ', "-").to_lowercase(),
                        sanitize_ref(&skill.name)
                    ),
                    name: format!("{} → {}", tool.name, skill.name),
                    flow_type: "control".into(),
                    source: agent_ref,
                    destination: format!("asset:{}", comp_ref),
                    encrypted: None,
                    description: Some(format!("Agent executes {} skill", skill.scope)),
                });
            }

            // If skill has skill_invoke capability, flow to MCP servers (control edge)
            if skill.capabilities.iter().any(|c| c == "skill_invoke") {
                for mcp in &report.mcp_configs {
                    for server in &mcp.servers {
                        flows.push(Flow {
                            bom_ref: format!(
                                "flow:{}->mcp:{}",
                                sanitize_ref(&skill.name),
                                server.name
                            ),
                            name: format!("{} → {}", skill.name, server.name),
                            flow_type: "control".into(),
                            source: format!("asset:{}", comp_ref),
                            destination: format!("asset:mcp:{}", server.name),
                            encrypted: None,
                            description: Some("Skill invokes MCP tool".into()),
                        });
                    }
                }
            }

            host_deps.push(comp_ref);
        }

        // Rules files → data assets with dangerous-pattern behaviors
        for rf in &report.rules_files {
            let comp_ref = format!("rules:{}", sanitize_ref(&rf.path));

            components.push(Component {
                component_type: "data".into(),
                bom_ref: comp_ref.clone(),
                name: rf.file_name.clone(),
                version: None,
                group: Some("agent-rules".into()),
                properties: vec![
                    Property {
                        name: "rmg:rules-hash".into(),
                        value: format!("sha256:{}", rf.sha256),
                    },
                    Property {
                        name: "rmg:git-tracked".into(),
                        value: rf.git_tracked.to_string(),
                    },
                ],
            });

            // Per-finding detail lives on the asset (the behavior is mapped to a
            // taxonomy value that cannot carry it).
            let finding_props: Vec<Property> = rf
                .findings
                .iter()
                .enumerate()
                .map(|(i, f)| Property {
                    name: format!("rmg:finding-{}", i),
                    value: format!("{}: {}", f.severity, f.pattern),
                })
                .collect();

            assets.push(Asset {
                bom_ref: format!("asset:{}", comp_ref),
                asset_type: "data".into(),
                name: None, // component-backed
                description: Some(format!(
                    "Agent rules file ({} bytes, {})",
                    rf.size_bytes,
                    if rf.git_tracked {
                        "git-tracked"
                    } else {
                        "untracked"
                    }
                )),
                zone: Some("zone:local".into()),
                component_ref: Some(comp_ref.clone()),
                responsibilities: vec!["Agent behavior configuration".into()],
                interfaces: Vec::new(),
                properties: finding_props,
            });

            for finding in &rf.findings {
                behaviors.push(
                    format!("dangerous-pattern:{}:{}", finding.severity, finding.pattern),
                    vec!["declared".into()],
                    vec![format!("asset:{}", comp_ref)],
                    Vec::new(),
                );
            }

            // Flow from rules file to each agent (control edge: configures agent)
            for tool in &report.ai_agents_and_tools {
                let agent_ref = format!(
                    "asset:ai-tool:{}",
                    tool.name.replace(' ', "-").to_lowercase()
                );
                flows.push(Flow {
                    bom_ref: format!(
                        "flow:{}->{}",
                        sanitize_ref(&rf.file_name),
                        tool.name.replace(' ', "-").to_lowercase()
                    ),
                    name: format!("{} → {}", rf.file_name, tool.name),
                    flow_type: "control".into(),
                    source: format!("asset:{}", comp_ref),
                    destination: agent_ref,
                    encrypted: None,
                    description: Some("Rules file configures agent behavior".into()),
                });
            }

            host_deps.push(comp_ref);
        }

        // MCP probe results → observed behaviors + resources + version enrichment
        for probe in &report.mcp_probes {
            if !probe.success {
                continue;
            }
            let server_ref = format!("asset:mcp:{}", probe.server_name);
            // Whether the probed server actually exists as an asset (created above).
            let server_asset_exists = report
                .mcp_configs
                .iter()
                .flat_map(|c| &c.servers)
                .any(|s| s.name == probe.server_name);

            // Enrich component version from probe server_info
            if let Some(ref info) = probe.server_info
                && let Some(ref ver) = info.version
            {
                let comp_bom_ref = format!("mcp:{}", probe.server_name);
                if let Some(comp) = components.iter_mut().find(|c| c.bom_ref == comp_bom_ref) {
                    if comp.version.is_none() {
                        comp.version = Some(ver.clone());
                    }
                    if info.name != probe.server_name {
                        comp.properties.push(Property {
                            name: "rmg:probe-reported-name".into(),
                            value: info.name.clone(),
                        });
                    }
                }
            }

            // Observed capabilities (only attach an actor if its asset exists)
            for cap in &probe.observed_capabilities {
                let actors = if server_asset_exists {
                    vec![server_ref.clone()]
                } else {
                    Vec::new()
                };
                behaviors.push(cap.clone(), vec!["observed".into()], actors, Vec::new());
            }

            // Each probed tool becomes its own asset (holds description + poisoning
            // signal as asset properties, which the schema permits) plus an observed
            // behavior referencing it.
            for tool in &probe.tools {
                let desc = tool.description.as_deref().unwrap_or("");
                let tool_ref = format!("mcp-tool:{}:{}", probe.server_name, sanitize_ref(&tool.name));

                let mut tool_props = Vec::new();
                if !desc.is_empty() {
                    tool_props.push(Property {
                        name: "rmg:tool-description".into(),
                        value: desc.to_string(),
                    });
                }

                // Scan the tool name, description, AND every nested description in
                // the parameter schema — injection hides in param descriptions too.
                let mut scan_target = format!("{} {}", tool.name, desc);
                if let Some(ref schema) = tool.input_schema {
                    collect_schema_descriptions(schema, &mut scan_target);
                }
                let poisoning_signals = scan_injection_text(&scan_target);
                if !poisoning_signals.is_empty() {
                    tool_props.push(Property {
                        name: "rmg:poisoning-risk".into(),
                        value: format!("suspicious patterns: {}", poisoning_signals.join(", ")),
                    });
                }
                let unicode_signals = scan_suspicious_unicode(&scan_target);
                if !unicode_signals.is_empty() {
                    tool_props.push(Property {
                        name: "rmg:hidden-unicode-risk".into(),
                        value: unicode_signals.join(", "),
                    });
                }

                assets.push(Asset {
                    bom_ref: format!("asset:{}", tool_ref),
                    asset_type: "tool".into(),
                    name: Some(tool.name.clone()),
                    description: tool.description.clone(),
                    zone: Some("zone:remote".into()),
                    component_ref: None,
                    responsibilities: Vec::new(),
                    interfaces: Vec::new(),
                    properties: tool_props,
                });

                behaviors.push(
                    format!("mcp-tool:{}", tool.name),
                    vec!["observed".into()],
                    if server_asset_exists {
                        vec![server_ref.clone()]
                    } else {
                        vec![format!("asset:{}", tool_ref)]
                    },
                    vec![format!("asset:{}", tool_ref)],
                );
            }

            // Map MCP probe resources to data assets + flows (data edge)
            for resource in &probe.resources {
                let res_ref = format!(
                    "mcp-resource:{}:{}",
                    probe.server_name,
                    sanitize_ref(&resource.uri)
                );
                let zone = if resource.uri.starts_with("file://") {
                    "zone:local"
                } else {
                    "zone:remote"
                };

                // Injection can hide in resource name/description too (CyberArk
                // "Poison everywhere"), so scan them as well as tools.
                let res_scan = format!(
                    "{} {}",
                    resource.name.as_deref().unwrap_or(""),
                    resource.description.as_deref().unwrap_or("")
                );
                let mut res_props = vec![Property {
                    name: "rmg:resource-uri".into(),
                    value: resource.uri.clone(),
                }];
                let res_poison = scan_injection_text(&res_scan);
                if !res_poison.is_empty() {
                    res_props.push(Property {
                        name: "rmg:poisoning-risk".into(),
                        value: format!("suspicious patterns: {}", res_poison.join(", ")),
                    });
                }
                let res_unicode = scan_suspicious_unicode(&res_scan);
                if !res_unicode.is_empty() {
                    res_props.push(Property {
                        name: "rmg:hidden-unicode-risk".into(),
                        value: res_unicode.join(", "),
                    });
                }

                assets.push(Asset {
                    bom_ref: format!("asset:{}", res_ref),
                    asset_type: "data".into(),
                    name: Some(resource.name.clone().unwrap_or_else(|| resource.uri.clone())),
                    description: resource.description.clone(),
                    zone: Some(zone.into()),
                    component_ref: None,
                    responsibilities: Vec::new(),
                    interfaces: Vec::new(),
                    properties: res_props,
                });

                // Only emit the flow if the source MCP server asset exists.
                if server_asset_exists {
                    flows.push(Flow {
                        bom_ref: format!(
                            "flow:{}->res:{}",
                            probe.server_name,
                            sanitize_ref(&resource.uri)
                        ),
                        name: format!(
                            "{} → {}",
                            probe.server_name,
                            resource.name.as_deref().unwrap_or(&resource.uri)
                        ),
                        flow_type: "data".into(),
                        source: server_ref.clone(),
                        destination: format!("asset:{}", res_ref),
                        encrypted: None,
                        description: Some("MCP server accesses resource".into()),
                    });
                }
            }
        }

        // Cross-server tool shadowing: a tool name offered by more than one probed
        // server is a confused-deputy risk — the agent may invoke the wrong (possibly
        // malicious) server's implementation. Correlate tool names across all probes.
        {
            use std::collections::BTreeMap;
            let mut tool_servers: BTreeMap<String, Vec<String>> = BTreeMap::new();
            for probe in &report.mcp_probes {
                if !probe.success {
                    continue;
                }
                let server_exists = report
                    .mcp_configs
                    .iter()
                    .flat_map(|c| &c.servers)
                    .any(|s| s.name == probe.server_name);
                if !server_exists {
                    continue;
                }
                for tool in &probe.tools {
                    tool_servers
                        .entry(tool.name.clone())
                        .or_default()
                        .push(probe.server_name.clone());
                }
            }
            for (tool_name, servers) in tool_servers {
                // Dedupe servers (a server listing the same tool twice isn't shadowing).
                let mut uniq = servers.clone();
                uniq.sort();
                uniq.dedup();
                if uniq.len() > 1 {
                    // A dedicated asset carries the tool name + colliding servers (the
                    // behavior is mapped to a taxonomy value that cannot).
                    let shadow_ref = format!("tool-shadow:{}", sanitize_ref(&tool_name));
                    assets.push(Asset {
                        bom_ref: format!("asset:{}", shadow_ref),
                        asset_type: "data".into(),
                        name: Some(tool_name.clone()),
                        description: Some(format!(
                            "Tool '{}' offered by {} servers (shadowing / confused-deputy risk)",
                            tool_name,
                            uniq.len()
                        )),
                        zone: Some("zone:remote".into()),
                        component_ref: None,
                        responsibilities: Vec::new(),
                        interfaces: Vec::new(),
                        properties: vec![Property {
                            name: "rmg:shadowed-by".into(),
                            value: uniq.join(", "),
                        }],
                    });
                    let actors: Vec<String> =
                        uniq.iter().map(|s| format!("asset:mcp:{}", s)).collect();
                    behaviors.push(
                        format!("tool-shadowing:{}", tool_name),
                        vec!["observed".into()],
                        actors,
                        vec![format!("asset:{}", shadow_ref)],
                    );
                }
            }
        }

        // Toxic-flow / lethal-trifecta surface: sensitive source + exfil sink across
        // the aggregate agent capability surface. A dedicated asset holds the source
        // and sink lists; the behavior's actors are the agent(s) wielding the surface.
        if let Some(tf) = crate::analysis::analyze_toxic_flow(report) {
            let surface_ref = "agent-surface";
            assets.push(Asset {
                bom_ref: format!("asset:{}", surface_ref),
                asset_type: "data".into(),
                name: Some("Aggregate agent capability surface".into()),
                description: Some(
                    "Connected agent surface combines a sensitive-data source with an \
                     exfiltration sink (lethal-trifecta / toxic-flow risk)"
                        .into(),
                ),
                zone: Some("zone:local".into()),
                component_ref: None,
                responsibilities: Vec::new(),
                interfaces: Vec::new(),
                properties: vec![
                    Property {
                        name: "rmg:sources".into(),
                        value: tf.sources.join(", "),
                    },
                    Property {
                        name: "rmg:sinks".into(),
                        value: tf.sinks.join(", "),
                    },
                ],
            });
            // Actors = agent assets if any, else the surface asset (never dangling).
            let agent_actors: Vec<String> = report
                .ai_agents_and_tools
                .iter()
                .map(|t| format!("asset:ai-tool:{}", t.name.replace(' ', "-").to_lowercase()))
                .collect();
            let actors = if agent_actors.is_empty() {
                vec![format!("asset:{}", surface_ref)]
            } else {
                agent_actors
            };
            behaviors.push(
                "toxic-flow-surface".into(),
                vec!["observed".into()],
                actors,
                vec![format!("asset:{}", surface_ref)],
            );
        }

        // Exposure findings → dedicated exposure data assets + behaviors.
        // The asset (always created) holds the advisory metadata in a schema-legal
        // place and guarantees the behavior's actor never dangles.
        for (idx, finding) in report.exposure_findings.iter().enumerate() {
            let exposure_ref = format!("exposure:{}:{}", idx, sanitize_ref(&finding.name));

            assets.push(Asset {
                bom_ref: format!("asset:{}", exposure_ref),
                asset_type: "data".into(),
                name: Some(format!("threat-match: {}", finding.name)),
                description: Some(finding.advisory.clone()),
                zone: Some("zone:local".into()),
                component_ref: None,
                responsibilities: Vec::new(),
                interfaces: Vec::new(),
                properties: vec![
                    Property {
                        name: "rmg:advisory".into(),
                        value: finding.advisory.clone(),
                    },
                    Property {
                        name: "rmg:severity".into(),
                        value: "critical".into(),
                    },
                    Property {
                        name: "rmg:ecosystem".into(),
                        value: finding.ecosystem.clone(),
                    },
                    Property {
                        name: "rmg:matched-version".into(),
                        value: finding.version.clone(),
                    },
                    Property {
                        name: "rmg:found-in".into(),
                        value: finding.found_in.clone(),
                    },
                ],
            });

            // Actor = matched MCP server asset if one exists, else the exposure asset
            // itself (never a fabricated/dangling ref).
            let matched_server = report
                .mcp_configs
                .iter()
                .flat_map(|c| &c.servers)
                .find(|s| {
                    s.package_name.as_deref() == Some(finding.name.as_str())
                        || s.name == finding.name
                })
                .map(|s| format!("asset:mcp:{}", s.name));

            let actor = matched_server.unwrap_or_else(|| format!("asset:{}", exposure_ref));

            behaviors.push(
                format!("exposure-catalog-match:{}", finding.name),
                vec!["declared".into()],
                vec![actor],
                Vec::new(),
            );
        }

        // SSH keys as blast-radius data assets
        for key in &report.ssh_keys {
            let key_ref = format!("ssh-key:{}", sanitize_ref(&key.path));

            let mut key_props = vec![
                Property {
                    name: "rmg:key-type".into(),
                    value: key.key_type.clone(),
                },
                Property {
                    name: "rmg:passphrase-status".into(),
                    value: match key.has_passphrase {
                        PassphraseStatus::Encrypted => "encrypted".into(),
                        PassphraseStatus::NoPassphrase => "no_passphrase".into(),
                        PassphraseStatus::Unknown => "unknown".into(),
                    },
                },
            ];
            if let Some(ref comment) = key.comment {
                key_props.push(Property {
                    name: "rmg:key-comment".into(),
                    value: comment.clone(),
                });
            }

            assets.push(Asset {
                bom_ref: format!("asset:{}", key_ref),
                asset_type: "data".into(),
                name: Some(key.path.rsplit('/').next().unwrap_or(&key.path).to_string()),
                description: Some(format!(
                    "SSH {} key ({})",
                    key.key_type,
                    match key.has_passphrase {
                        PassphraseStatus::Encrypted => "passphrase-protected",
                        PassphraseStatus::NoPassphrase => "NO PASSPHRASE",
                        PassphraseStatus::Unknown => "passphrase status unknown",
                    }
                )),
                zone: Some("zone:local".into()),
                component_ref: None,
                responsibilities: vec!["Remote authentication".into()],
                interfaces: Vec::new(),
                properties: key_props,
            });

            // Unprotected keys are accessible blast radius for any shell-capable agent
            if key.has_passphrase == PassphraseStatus::NoPassphrase {
                behaviors.push(
                    "blast-radius:high:unprotected-ssh-key".into(),
                    vec!["observed".into()],
                    vec![format!("asset:{}", key_ref)],
                    Vec::new(),
                );
            }
        }

        // Cloud credentials as blast-radius data assets
        for cred in &report.cloud_credentials {
            let cred_ref = format!(
                "cloud-cred:{}:{}",
                sanitize_ref(&cred.provider),
                sanitize_ref(&cred.credential_type)
            );

            let mut cred_props = vec![
                Property {
                    name: "rmg:provider".into(),
                    value: cred.provider.clone(),
                },
                Property {
                    name: "rmg:credential-type".into(),
                    value: cred.credential_type.clone(),
                },
                Property {
                    name: "rmg:profile-count".into(),
                    value: cred.profiles.len().to_string(),
                },
            ];
            if !cred.profiles.is_empty() {
                cred_props.push(Property {
                    name: "rmg:profiles".into(),
                    value: cred.profiles.join(", "),
                });
            }

            assets.push(Asset {
                bom_ref: format!("asset:{}", cred_ref),
                asset_type: "data".into(),
                name: Some(format!("{} {}", cred.provider, cred.credential_type)),
                description: Some(format!(
                    "{} {} ({} profiles)",
                    cred.provider,
                    cred.credential_type,
                    cred.profiles.len()
                )),
                zone: Some("zone:local".into()),
                component_ref: None,
                responsibilities: vec!["Cloud service authentication".into()],
                interfaces: Vec::new(),
                properties: cred_props,
            });

            behaviors.push(
                format!(
                    "blast-radius:cloud-credential:{}",
                    cred.provider.to_lowercase()
                ),
                vec!["observed".into()],
                vec![format!("asset:{}", cred_ref)],
                Vec::new(),
            );
        }

        // Agent settings files → data assets; hooks + auto-approval → behaviors.
        for (idx, settings) in report.agent_settings.iter().enumerate() {
            let set_ref = format!("agent-settings:{}:{}", idx, sanitize_ref(&settings.path));

            let mut props = vec![
                Property {
                    name: "rmg:source".into(),
                    value: settings.source.clone(),
                },
                Property {
                    name: "rmg:git-tracked".into(),
                    value: settings.git_tracked.to_string(),
                },
            ];
            if let Some(ref mode) = settings.permission_mode {
                props.push(Property {
                    name: "rmg:permission-mode".into(),
                    value: mode.clone(),
                });
            }
            if settings.auto_approve_mcp {
                props.push(Property {
                    name: "rmg:auto-approve-mcp".into(),
                    value: "true".into(),
                });
            }
            for (hi, h) in settings.hooks.iter().enumerate() {
                props.push(Property {
                    name: format!("rmg:hook-{}", hi),
                    value: format!(
                        "{}[{}]{}: {}",
                        h.event,
                        h.matcher.as_deref().unwrap_or("*"),
                        if h.dangerous { " DANGEROUS" } else { "" },
                        h.command
                    ),
                });
            }

            assets.push(Asset {
                bom_ref: format!("asset:{}", set_ref),
                asset_type: "data".into(),
                name: Some(
                    std::path::Path::new(&settings.path)
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or(&settings.path)
                        .to_string(),
                ),
                description: Some(format!(
                    "{} agent settings ({} hooks)",
                    settings.source,
                    settings.hooks.len()
                )),
                zone: Some("zone:local".into()),
                component_ref: None,
                responsibilities: vec!["Agent configuration".into()],
                interfaces: Vec::new(),
                properties: props,
            });

            // Each hook command is silent code execution on the agent host.
            for _ in &settings.hooks {
                behaviors.push(
                    "hook-exec".into(),
                    vec!["declared".into()],
                    vec![format!("asset:{}", set_ref)],
                    Vec::new(),
                );
            }
            if settings.auto_approve_mcp {
                behaviors.push(
                    "mcp-auto-approve".into(),
                    vec!["declared".into()],
                    vec![format!("asset:{}", set_ref)],
                    Vec::new(),
                );
            }
        }

        // Build dependency graph
        let mut dependencies = Vec::new();
        if !host_deps.is_empty() {
            dependencies.push(Dependency {
                dep_ref: host_ref,
                depends_on: host_deps,
            });
        }

        // ── Finding → asset link index, so a threat points at the specific asset it
        // concerns (the plaintext endpoint, the poisoned rules file, the gateway), not
        // just the machine. MCP-server and rules assets already exist; gateway and
        // transcript assets are emitted here so those findings have concrete targets too.
        let mut link_index: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
        for mcp in &report.mcp_configs {
            for s in &mcp.servers {
                link_index.insert(format!("mcp:{}", s.name), format!("asset:mcp:{}", s.name));
            }
        }
        for rf in &report.rules_files {
            link_index.insert(
                format!("rules:{}", rf.path),
                format!("asset:rules:{}", sanitize_ref(&rf.path)),
            );
        }
        // Gateway overrides → `gateway` assets in the remote zone (deduped by var).
        for settings in &report.agent_settings {
            for gw in &settings.gateway_overrides {
                if gw.official {
                    continue;
                }
                let key = format!("gwvar:{}", gw.var);
                if link_index.contains_key(&key) {
                    continue;
                }
                let asset_ref = format!("asset:gateway:{}", sanitize_ref(&gw.var));
                assets.push(Asset {
                    bom_ref: asset_ref.clone(),
                    asset_type: "gateway".into(),
                    name: Some(format!("{} → {}", gw.var, gw.host)),
                    description: Some(format!(
                        "AI base-URL override routing requests (and the API key) through non-official host {}",
                        gw.host
                    )),
                    zone: Some("zone:remote".into()),
                    component_ref: None,
                    responsibilities: Vec::new(),
                    interfaces: Vec::new(),
                    properties: Vec::new(),
                });
                link_index.insert(key, asset_ref);
            }
        }
        // Transcript stores → `data-store` assets in the local zone.
        for t in &report.transcripts {
            let asset_ref = format!("asset:transcript:{}", sanitize_ref(&t.path));
            assets.push(Asset {
                bom_ref: asset_ref.clone(),
                asset_type: "data-store".into(),
                name: Some(format!("{} {}", t.framework, t.kind)),
                description: Some(format!(
                    "Agent {} store — {} file(s) of conversation state",
                    t.kind, t.file_count
                )),
                zone: Some("zone:local".into()),
                component_ref: None,
                responsibilities: Vec::new(),
                interfaces: Vec::new(),
                properties: Vec::new(),
            });
            link_index.insert(format!("transcript:{}", t.path), asset_ref);
        }

        let blueprint = Blueprint {
            bom_ref: "blueprint:agent-posture".into(),
            name: "Agent Security Posture".into(),
            description: format!(
                "Security posture blueprint for {} — agent tools, MCP servers, skills, and rules files with capability analysis",
                report.device.hostname
            ),
            model_types: vec!["behavioral".into(), "data-flow".into()],
            assets,
            behaviors: Behaviors {
                instances: behaviors.instances,
            },
            flows,
            zones,
            boundaries,
        };

        // ── Risk layer: reuse the same analysis the terminal/HTML reports lead with,
        // expressed as native CycloneDX 2.0 constructs instead of rmg: properties.
        // Resolve a finding to the specific asset it concerns, falling back to the
        // machine when there's no more precise target.
        let resolve_asset = |f: &crate::analysis::Finding| -> String {
            let key = match f.category.as_str() {
                "MCP transport" | "MCP scope" | "MCP secret" | "MCP command" => {
                    first_single_quoted(&f.title).map(|n| format!("mcp:{n}"))
                }
                "Rules file" => Some(format!("rules:{}", f.location)),
                "Gateway routing" => {
                    f.title.split_whitespace().next().map(|v| format!("gwvar:{v}"))
                }
                "Transcript exposure" => Some(format!("transcript:{}", f.location)),
                _ => None,
            };
            key.and_then(|k| link_index.get(&k).cloned())
                .unwrap_or_else(|| machine_ref.clone())
        };

        let findings = crate::analysis::collect_findings(report);

        // CVEs mentioned in exposure advisories, keyed by the finding title we can
        // reconstruct, plus a description per CVE.
        let mut cves_by_title: std::collections::HashMap<String, Vec<String>> =
            std::collections::HashMap::new();
        let mut cve_desc: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
        let mut cve_score: std::collections::HashMap<String, f64> =
            std::collections::HashMap::new();
        for e in &report.exposure_findings {
            let rated = extract_cve_ratings(&e.advisory);
            if rated.is_empty() {
                continue;
            }
            for (cve, score) in &rated {
                cve_desc.entry(cve.clone()).or_insert_with(|| e.advisory.clone());
                if let Some(sc) = score {
                    cve_score.entry(cve.clone()).or_insert(*sc);
                }
            }
            let title = format!("Known-bad {} package: {} {}", e.ecosystem, e.name, e.version);
            cves_by_title.insert(title, rated.into_iter().map(|(c, _)| c).collect());
        }
        // The hostile-gateway (EAA-007) finding maps to a known CVE.
        const GATEWAY_CVE: &str = "CVE-2026-21852";
        cve_desc.entry(GATEWAY_CVE.into()).or_insert_with(|| {
            "AI base-URL / gateway override enabling API-key exfiltration via a malicious proxy (EAA-007).".into()
        });

        let mut used_cves: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        let mut used_capec: std::collections::BTreeMap<u32, (&'static str, &'static str)> =
            std::collections::BTreeMap::new();

        let threat_list: Vec<Threat> = findings
            .iter()
            .enumerate()
            .map(|(i, f)| {
                let mut related_vulnerabilities = Vec::new();
                match f.category.as_str() {
                    "Exposure" => {
                        if let Some(cves) = cves_by_title.get(&f.title) {
                            for cve in cves {
                                used_cves.insert(cve.clone());
                                related_vulnerabilities.push(format!("vuln:{}", cve.to_lowercase()));
                            }
                        }
                    }
                    "Gateway routing" => {
                        used_cves.insert(GATEWAY_CVE.into());
                        related_vulnerabilities
                            .push(format!("vuln:{}", GATEWAY_CVE.to_lowercase()));
                    }
                    _ => {}
                }
                let mut attack_patterns = Vec::new();
                if let Some((id, name, desc)) = capec_for_category(&f.category) {
                    used_capec.insert(id, (name, desc));
                    attack_patterns.push(format!("attack:capec-{id}"));
                }
                Threat {
                    bom_ref: format!("threat:{i}"),
                    name: f.title.clone(),
                    description: Some(format!(
                        "{} severity · {} · at {}",
                        f.severity.label(),
                        f.category,
                        f.location
                    )),
                    affected_assets: vec![resolve_asset(f)],
                    related_vulnerabilities,
                    attack_patterns,
                }
            })
            .collect();

        let vulnerabilities: Vec<Vulnerability> = used_cves
            .iter()
            .map(|cve| Vulnerability {
                bom_ref: format!("vuln:{}", cve.to_lowercase()),
                id: cve.clone(),
                description: cve_desc.get(cve).cloned(),
                ratings: cve_score
                    .get(cve)
                    .map(|score| VulnRating {
                        score: *score,
                        severity: cvss_severity(*score).to_string(),
                    })
                    .into_iter()
                    .collect(),
            })
            .collect();
        let attack_patterns: Vec<AttackPattern> = used_capec
            .iter()
            .map(|(id, (name, desc))| AttackPattern {
                bom_ref: format!("attack:capec-{id}"),
                capec_id: Some(*id),
                name: (*name).to_string(),
                description: Some((*desc).to_string()),
            })
            .collect();

        let threats = (!threat_list.is_empty()).then_some(ThreatsWrapper {
            threats: threat_list,
            attack_patterns,
        });

        // The toxic-flow (lethal-trifecta) surface → a single scored risk.
        let risks = crate::analysis::analyze_toxic_flow(report).map(|tf| RisksWrapper {
            risks: vec![Risk {
                bom_ref: "risk:toxic-flow".into(),
                name: "Toxic flow (lethal trifecta)".into(),
                statement: format!(
                    "The connected agent surface combines a sensitive-data source ({}) with an exfiltration sink ({}), so a single prompt injection can read private data and send it out.",
                    tf.sources.join("/"),
                    tf.sinks.join("/")
                ),
                affects: vec![machine_ref.clone()],
                related_threats: Vec::new(),
                inherent_risk: Some(Rating {
                    likelihood: Level { level: "high".into() },
                    impact: Level { level: "major".into() },
                }),
                responses: vec![RiskResponse {
                    bom_ref: "response:toxic-flow".into(),
                    strategy: "reduce".into(),
                    description: Some(
                        "Separate the source and sink so no single agent context holds both, or require human approval on outbound flows."
                            .into(),
                    ),
                    priority: Some("high".into()),
                }],
                status: Some("identified".into()),
            }],
        });

        // Compliance coverage → controls, limited to the controls this machine's
        // findings actually exercise (so the section reflects real posture, not the
        // full 29-control catalog on every scan).
        let controls: Vec<Control> = crate::compliance::assess(report)
            .assessments
            .iter()
            .filter(|a| {
                a.finding_count > 0
                    && !matches!(a.control.coverage, crate::compliance::Coverage::OutOfScope)
            })
            .map(|a| {
                let c = a.control;
                let covered = matches!(c.coverage, crate::compliance::Coverage::Covered);
                Control {
                    bom_ref: format!("control:{}", sanitize_ref(c.id)),
                    name: format!("{} — {}", c.id, c.title),
                    description: Some(c.how.to_string()),
                    status: Some(if covered { "implemented" } else { "in-progress" }.into()),
                    applies_to: vec![machine_ref.clone()],
                    effectiveness: Some(Effectiveness {
                        rating: if covered { "good" } else { "marginal" }.into(),
                    }),
                }
            })
            .collect();

        // Surface scan warnings in document metadata as properties (schema-legal).
        let warning_props: Vec<Property> = report
            .warnings
            .iter()
            .map(|w| Property {
                name: format!("rmg:warning:{}", w.scanner),
                value: w.message.clone(),
            })
            .collect();

        BlueprintDocument {
            spec_format: "CycloneDX",
            spec_version: "2.0",
            version: 1,
            vulnerabilities,
            threats,
            risks,
            controls,
            metadata: DocMetadata {
                timestamp: report.scan_timestamp_iso.clone(),
                tools: DocTools {
                    components: vec![DocToolComponent {
                        component_type: "application",
                        name: "rmguard".into(),
                        group: Some("rustmachineguard".into()),
                        version: report.agent_version.clone(),
                    }],
                },
                component: DocComponent {
                    component_type: "device",
                    name: report.device.hostname.clone(),
                    version: Some(format!(
                        "{} {}",
                        report.device.os_name, report.device.os_version
                    )),
                },
                properties: warning_props,
            },
            components,
            dependencies,
            blueprints: vec![blueprint],
        }
    }
}

fn sanitize_ref(path: &str) -> String {
    path.replace('/', "_").replace(' ', "-").to_lowercase()
}

fn build_purl(
    ecosystem: Option<&str>,
    name: Option<&str>,
    version: Option<&str>,
) -> Option<String> {
    let eco = ecosystem?;
    let name = name?;
    let purl_type = match eco {
        "npm" => "npm",
        "pypi" => "pypi",
        "docker" => "docker",
        _ => return None,
    };
    let (namespace, pkg_name) = if let Some(rest) = name.strip_prefix('@') {
        if let Some(slash_idx) = rest.find('/') {
            (
                Some(format!("@{}", &rest[..slash_idx])),
                rest[slash_idx + 1..].to_string(),
            )
        } else {
            (None, name.to_string())
        }
    } else if eco == "docker" && name.contains('/') {
        let parts: Vec<&str> = name.rsplitn(2, '/').collect();
        (Some(parts[1].to_string()), parts[0].to_string())
    } else {
        (None, name.to_string())
    };
    let mut purl = if let Some(ns) = namespace {
        format!("pkg:{}/{}/{}", purl_type, ns, pkg_name)
    } else {
        format!("pkg:{}/{}", purl_type, pkg_name)
    };
    if let Some(v) = version {
        purl.push('@');
        purl.push_str(v);
    }
    Some(purl)
}

#[cfg(test)]
mod cvss_tests {
    use super::*;

    #[test]
    fn parses_the_advisory_formats_in_the_catalog() {
        // Parenthesized, adjacent — the most common form.
        assert_eq!(
            extract_cve_ratings("CVE-2025-6514 (CVSS 9.6): OS command injection."),
            vec![("CVE-2025-6514".to_string(), Some(9.6))]
        );
        // Comma-separated form.
        assert_eq!(
            extract_cve_ratings("CVE-2026-45321, CVSS 9.1: something bad"),
            vec![("CVE-2026-45321".to_string(), Some(9.1))]
        );
        // No score stated -> None, not a guess.
        assert_eq!(
            extract_cve_ratings("CVE-2025-66414: DNS rebinding vulnerability"),
            vec![("CVE-2025-66414".to_string(), None)]
        );
    }

    #[test]
    fn attributes_each_score_to_its_own_cve() {
        // The real server-filesystem advisory: two CVEs, each with its own score.
        let adv = "CVE-2025-53109 (CVSS 8.4) + CVE-2025-53110 (CVSS 7.3): symlink bypass";
        assert_eq!(
            extract_cve_ratings(adv),
            vec![
                ("CVE-2025-53109".to_string(), Some(8.4)),
                ("CVE-2025-53110".to_string(), Some(7.3)),
            ]
        );
        // A scoreless CVE must NOT inherit a later CVE's score.
        let mixed = "CVE-2025-11111: no score here. CVE-2025-22222 (CVSS 9.8): critical";
        assert_eq!(
            extract_cve_ratings(mixed),
            vec![
                ("CVE-2025-11111".to_string(), None),
                ("CVE-2025-22222".to_string(), Some(9.8)),
            ]
        );
    }

    #[test]
    fn version_tokens_are_not_mistaken_for_scores() {
        assert_eq!(cvss_score_in(" (CVSS v3.1 9.6)"), Some(9.6));
        assert_eq!(cvss_score_in(" (CVSS:3.1/AV:N/AC:L 8.8)"), Some(8.8));
        assert_eq!(cvss_score_in(" no score here"), None);
        // Out-of-range numbers are rejected rather than emitted as a bogus score.
        assert_eq!(cvss_score_in(" CVSS 42"), None);
    }

    #[test]
    fn severity_bands_match_cvss() {
        assert_eq!(cvss_severity(9.8), "critical");
        assert_eq!(cvss_severity(9.0), "critical");
        assert_eq!(cvss_severity(8.9), "high");
        assert_eq!(cvss_severity(7.0), "high");
        assert_eq!(cvss_severity(6.9), "medium");
        assert_eq!(cvss_severity(4.0), "medium");
        assert_eq!(cvss_severity(3.9), "low");
        assert_eq!(cvss_severity(0.0), "none");
    }

    #[test]
    fn cve_scan_is_total_on_arbitrary_text() {
        for s in ["", "CVE-", "CVE-20", "cve-2025-1", "CVE--", "…CVE-2025-1234…", "CVE-2025-"] {
            let _ = extract_cve_ratings(s);
        }
        // Lower-case ids are normalized to upper case.
        assert_eq!(extract_cve_ratings("cve-2025-1234")[0].0, "CVE-2025-1234");
    }
}
