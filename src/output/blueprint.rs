use crate::models::{PassphraseStatus, ScanReport};
use serde::Serialize;

/// Generate a CycloneDX 2.0 Blueprint document from scan results.
///
/// This is an early implementation targeting the draft Blueprint schema
/// from CycloneDX 2.0 (PR #951, milestone due 2026-08-31).
/// Schema source: github.com/CycloneDX/specification (Apache-2.0)
pub fn render(report: &ScanReport) -> String {
    let doc = BlueprintDocument::from_report(report);
    serde_json::to_string_pretty(&doc).unwrap_or_default()
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BlueprintDocument {
    bom_format: &'static str,
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
    tools: Vec<DocTool>,
    component: DocComponent,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    warnings: Vec<DocWarning>,
}

#[derive(Serialize)]
struct DocTool {
    vendor: String,
    name: String,
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
struct DocWarning {
    scanner: String,
    message: String,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    purl: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    properties: Vec<Property>,
}

#[derive(Serialize)]
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
    #[serde(skip_serializing_if = "Vec::is_empty")]
    behaviors: Vec<BehaviorInstance>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    flows: Vec<Flow>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    zones: Vec<Zone>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    boundaries: Vec<Boundary>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Asset {
    #[serde(rename = "bom-ref")]
    bom_ref: String,
    #[serde(rename = "type")]
    asset_type: String,
    name: String,
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
    behavior: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    acknowledgment: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    actors: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    targets: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    properties: Vec<Property>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Flow {
    #[serde(rename = "bom-ref")]
    bom_ref: String,
    name: String,
    source: String,
    target: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    properties: Vec<Property>,
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

// Patterns that suggest tool description poisoning (hidden instructions for AI)
const POISONING_PATTERNS: &[&str] = &[
    "important:",
    "you must",
    "always ",
    "never ",
    "ignore previous",
    "disregard",
    "override",
    "system prompt",
    "do not tell",
    "secretly",
    "hidden instruction",
    "<system>",
    "{{",
    "```system",
];

impl BlueprintDocument {
    fn from_report(report: &ScanReport) -> Self {
        let mut components = Vec::new();
        let mut assets = Vec::new();
        let mut behaviors = Vec::new();
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
            let comp_ref = format!(
                "ai-tool:{}",
                tool.name.replace(' ', "-").to_lowercase()
            );

            components.push(Component {
                component_type: "application".into(),
                bom_ref: comp_ref.clone(),
                name: tool.name.clone(),
                version: tool.version.clone(),
                group: None,
                purl: None,
                properties: vec![Property {
                    name: "rmg:tool-type".into(),
                    value: format!("{:?}", tool.tool_type),
                }],
            });

            assets.push(Asset {
                bom_ref: format!("asset:{}", comp_ref),
                asset_type: "agent".into(),
                name: tool.name.clone(),
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
                let purl = build_purl(
                    server.package_ecosystem.as_deref(),
                    server.package_name.as_deref(),
                    server.package_version.as_deref(),
                );

                // #3: Add command/args to Blueprint properties
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
                    purl,
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
                    name: server.name.clone(),
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

                // Create flows from each agent to this tool
                for tool in &report.ai_agents_and_tools {
                    let agent_ref = format!(
                        "asset:ai-tool:{}",
                        tool.name.replace(' ', "-").to_lowercase()
                    );
                    let tool_ref = format!("asset:{}", comp_ref);

                    flows.push(Flow {
                        bom_ref: format!(
                            "flow:{}->{}",
                            tool.name.replace(' ', "-").to_lowercase(),
                            server.name
                        ),
                        name: format!("{} → {}", tool.name, server.name),
                        source: agent_ref,
                        target: tool_ref,
                        description: Some(format!(
                            "MCP tool invocation via {} transport",
                            server.transport
                        )),
                        properties: Vec::new(),
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
                purl: None,
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
                name: skill.name.clone(),
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

            // #5: Each capability becomes a behavior with native acknowledgment field
            for cap in &skill.capabilities {
                behaviors.push(BehaviorInstance {
                    behavior: cap.clone(),
                    acknowledgment: Some("declared".into()),
                    actors: vec![format!("asset:{}", comp_ref)],
                    targets: Vec::new(),
                    properties: vec![Property {
                        name: "rmg:capability-source".into(),
                        value: "static-inference".into(),
                    }],
                });
            }

            // #9: Flow from agent to skill (execution)
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
                    source: agent_ref,
                    target: format!("asset:{}", comp_ref),
                    description: Some(format!(
                        "Agent executes {} skill",
                        skill.scope
                    )),
                    properties: Vec::new(),
                });
            }

            // #9: If skill has skill_invoke capability, flow to MCP servers
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
                            source: format!("asset:{}", comp_ref),
                            target: format!("asset:mcp:{}", server.name),
                            description: Some("Skill invokes MCP tool".into()),
                            properties: Vec::new(),
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
                purl: None,
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

            assets.push(Asset {
                bom_ref: format!("asset:{}", comp_ref),
                asset_type: "data".into(),
                name: rf.file_name.clone(),
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
                properties: Vec::new(),
            });

            for finding in &rf.findings {
                behaviors.push(BehaviorInstance {
                    behavior: format!("dangerous-pattern:{}", finding.pattern),
                    acknowledgment: Some("declared".into()),
                    actors: vec![format!("asset:{}", comp_ref)],
                    targets: Vec::new(),
                    properties: vec![Property {
                        name: "rmg:severity".into(),
                        value: finding.severity.clone(),
                    }],
                });
            }

            // #9: Flow from rules file to each agent (configuration control)
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
                    source: format!("asset:{}", comp_ref),
                    target: agent_ref,
                    description: Some("Rules file configures agent behavior".into()),
                    properties: Vec::new(),
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

            // #4: Enrich component version from probe server_info
            if let Some(ref info) = probe.server_info {
                if let Some(ref ver) = info.version {
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
            }

            // #5: Observed capabilities with native acknowledgment field
            for cap in &probe.observed_capabilities {
                behaviors.push(BehaviorInstance {
                    behavior: cap.clone(),
                    acknowledgment: Some("observed".into()),
                    actors: vec![server_ref.clone()],
                    targets: Vec::new(),
                    properties: vec![Property {
                        name: "rmg:capability-source".into(),
                        value: "observed-probe".into(),
                    }],
                });
            }

            // #10: Check for tool description poisoning
            for tool in &probe.tools {
                let desc = tool.description.as_deref().unwrap_or("");
                let mut tool_props = vec![Property {
                    name: "rmg:tool-description".into(),
                    value: desc.to_string(),
                }];

                let poisoning_signals: Vec<&&str> = POISONING_PATTERNS
                    .iter()
                    .filter(|p| desc.to_lowercase().contains(**p))
                    .collect();

                if !poisoning_signals.is_empty() {
                    tool_props.push(Property {
                        name: "rmg:poisoning-risk".into(),
                        value: format!(
                            "suspicious patterns: {}",
                            poisoning_signals.iter().map(|p| **p).collect::<Vec<_>>().join(", ")
                        ),
                    });
                }

                behaviors.push(BehaviorInstance {
                    behavior: format!("mcp-tool:{}", tool.name),
                    acknowledgment: Some("observed".into()),
                    actors: vec![server_ref.clone()],
                    targets: Vec::new(),
                    properties: tool_props,
                });
            }

            // #2: Map MCP probe resources to data assets + flows
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

                assets.push(Asset {
                    bom_ref: format!("asset:{}", res_ref),
                    asset_type: "data".into(),
                    name: resource
                        .name
                        .clone()
                        .unwrap_or_else(|| resource.uri.clone()),
                    description: resource.description.clone(),
                    zone: Some(zone.into()),
                    component_ref: None,
                    responsibilities: Vec::new(),
                    interfaces: Vec::new(),
                    properties: vec![Property {
                        name: "rmg:resource-uri".into(),
                        value: resource.uri.clone(),
                    }],
                });

                flows.push(Flow {
                    bom_ref: format!("flow:{}->res:{}", probe.server_name, sanitize_ref(&resource.uri)),
                    name: format!(
                        "{} → {}",
                        probe.server_name,
                        resource.name.as_deref().unwrap_or(&resource.uri)
                    ),
                    source: server_ref.clone(),
                    target: format!("asset:{}", res_ref),
                    description: Some("MCP server accesses resource".into()),
                    properties: Vec::new(),
                });
            }
        }

        // #1: Map exposure findings to Blueprint behaviors
        for finding in &report.exposure_findings {
            let actor_ref = format!("asset:mcp:{}", finding.found_in
                .rsplit('/')
                .next()
                .unwrap_or(&finding.found_in)
                .replace(".json", ""));

            // Try to match to a known MCP server asset
            let matched_actor = report.mcp_configs.iter()
                .flat_map(|c| &c.servers)
                .find(|s| {
                    s.package_name.as_deref() == Some(&finding.name)
                        || s.name == finding.name
                })
                .map(|s| format!("asset:mcp:{}", s.name))
                .unwrap_or(actor_ref);

            behaviors.push(BehaviorInstance {
                behavior: format!("exposure-catalog-match:{}", finding.name),
                acknowledgment: Some("declared".into()),
                actors: vec![matched_actor],
                targets: Vec::new(),
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
                ],
            });
        }

        // #7: SSH keys as blast-radius data assets
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
                name: key.path.rsplit('/').next().unwrap_or(&key.path).to_string(),
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
                behaviors.push(BehaviorInstance {
                    behavior: "blast-radius:unprotected-ssh-key".into(),
                    acknowledgment: Some("observed".into()),
                    actors: vec![format!("asset:{}", key_ref)],
                    targets: Vec::new(),
                    properties: vec![Property {
                        name: "rmg:severity".into(),
                        value: "high".into(),
                    }],
                });
            }
        }

        // #7: Cloud credentials as blast-radius data assets
        for cred in &report.cloud_credentials {
            let cred_ref = format!("cloud-cred:{}:{}",
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
                name: format!("{} {}", cred.provider, cred.credential_type),
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

            behaviors.push(BehaviorInstance {
                behavior: format!("blast-radius:cloud-credential:{}", cred.provider.to_lowercase()),
                acknowledgment: Some("observed".into()),
                actors: vec![format!("asset:{}", cred_ref)],
                targets: Vec::new(),
                properties: vec![Property {
                    name: "rmg:profile-count".into(),
                    value: cred.profiles.len().to_string(),
                }],
            });
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
            behaviors,
            flows,
            zones,
            boundaries,
        };

        // #6: Surface scan warnings in Blueprint metadata
        let warnings: Vec<DocWarning> = report
            .warnings
            .iter()
            .map(|w| DocWarning {
                scanner: w.scanner.clone(),
                message: w.message.clone(),
            })
            .collect();

        BlueprintDocument {
            bom_format: "CycloneDX",
            spec_version: "2.0-draft",
            version: 1,
            metadata: DocMetadata {
                timestamp: report.scan_timestamp_iso.clone(),
                tools: vec![DocTool {
                    vendor: "rustmachineguard".into(),
                    name: "dev-machine-guard".into(),
                    version: report.agent_version.clone(),
                }],
                component: DocComponent {
                    component_type: "device",
                    name: report.device.hostname.clone(),
                    version: Some(format!(
                        "{} {}",
                        report.device.os_name, report.device.os_version
                    )),
                },
                warnings,
            },
            components,
            dependencies,
            blueprints: vec![blueprint],
        }
    }
}

fn sanitize_ref(path: &str) -> String {
    path.replace('/', "_")
        .replace(' ', "-")
        .to_lowercase()
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
