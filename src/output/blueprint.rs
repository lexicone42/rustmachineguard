use crate::models::{PassphraseStatus, ScanReport};
use serde::Serialize;

/// Generate a CycloneDX 2.0 Blueprint document from scan results.
///
/// Conforms to the draft CycloneDX 2.0 threat-modeling schema (branch
/// `2.0-dev-threatmodeling`, head 03a8eaa7 as of 2026-06-30; milestone 2.0 ~30%,
/// due 2026-08-31). Schema source: github.com/CycloneDX/specification (Apache-2.0).
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

/// Detect invisible / smuggled Unicode that ASCII pattern-matching is blind to —
/// the dominant 2025-2026 evasion (a "Provides weather forecasts" tool can carry a
/// full invisible exfiltration prompt). Returns deduped, stable-ordered category
/// labels. Character-class based, so language-agnostic.
fn scan_suspicious_unicode(s: &str) -> Vec<&'static str> {
    let mut cats: Vec<&'static str> = Vec::new();
    for ch in s.chars() {
        let label = match ch as u32 {
            0xE0000..=0xE007F => "tag-block",
            0xE0100..=0xE01EF => "variation-selector-smuggler",
            0x200B | 0x200C | 0x200D | 0xFEFF => "zero-width",
            0x00AD => "soft-hyphen",
            0x202A..=0x202E | 0x2066..=0x2069 => "bidi-control",
            _ if ch.is_control() && ch != '\t' && ch != '\n' && ch != '\r' => "other-control",
            _ => continue,
        };
        if !cats.contains(&label) {
            cats.push(label);
        }
    }
    cats
}

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

                // Scan both the tool name and description (an attacker can hide
                // payloads in either).
                let scan_target = format!("{} {}", tool.name, desc);
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
                        description: Some("MCP server accesses resource".into()),
                    });
                }
            }
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
            metadata: DocMetadata {
                timestamp: report.scan_timestamp_iso.clone(),
                tools: DocTools {
                    components: vec![DocToolComponent {
                        component_type: "application",
                        name: "dev-machine-guard".into(),
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
