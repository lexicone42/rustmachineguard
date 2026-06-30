use crate::models::ScanReport;
use serde::Serialize;

pub fn render(report: &ScanReport) -> String {
    let bom = CycloneDxBom::from_report(report);
    serde_json::to_string_pretty(&bom).unwrap_or_default()
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CycloneDxBom {
    bom_format: &'static str,
    spec_version: &'static str,
    version: u32,
    metadata: BomMetadata,
    components: Vec<BomComponent>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    dependencies: Vec<BomDependency>,
}

#[derive(Serialize)]
struct BomMetadata {
    timestamp: String,
    tools: Vec<BomTool>,
    component: BomMetadataComponent,
}

#[derive(Serialize)]
struct BomTool {
    vendor: String,
    name: String,
    version: String,
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct BomMetadataComponent {
    #[serde(rename = "type")]
    component_type: &'static str,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct BomComponent {
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
    publisher: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    purl: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    properties: Vec<BomProperty>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    external_references: Vec<BomExternalRef>,
}

#[derive(Serialize)]
struct BomProperty {
    name: String,
    value: String,
}

#[derive(Serialize)]
struct BomExternalRef {
    #[serde(rename = "type")]
    ref_type: String,
    url: String,
}

#[derive(Serialize)]
struct BomDependency {
    #[serde(rename = "ref")]
    dep_ref: String,
    #[serde(rename = "dependsOn")]
    depends_on: Vec<String>,
}

impl CycloneDxBom {
    fn from_report(report: &ScanReport) -> Self {
        let mut components = Vec::new();
        let mut dependencies = Vec::new();
        let host_ref = format!(
            "host:{}",
            report.device.hostname.replace(' ', "-").to_lowercase()
        );

        let mut host_deps = Vec::new();

        // MCP servers as components
        for mcp in &report.mcp_configs {
            for server in &mcp.servers {
                let bom_ref = format!("mcp:{}", server.name);
                let purl = build_purl(
                    server.package_ecosystem.as_deref(),
                    server.package_name.as_deref(),
                    server.package_version.as_deref(),
                );

                let mut properties = vec![
                    BomProperty {
                        name: "rmg:transport".to_string(),
                        value: server.transport.clone(),
                    },
                    BomProperty {
                        name: "rmg:config-source".to_string(),
                        value: mcp.config_source.clone(),
                    },
                ];

                if let Some(ref cmd) = server.command {
                    properties.push(BomProperty {
                        name: "rmg:command".to_string(),
                        value: cmd.clone(),
                    });
                }

                let mut external_refs = Vec::new();
                if let Some(ref url) = server.url {
                    external_refs.push(BomExternalRef {
                        ref_type: "distribution".to_string(),
                        url: url.clone(),
                    });
                }

                components.push(BomComponent {
                    component_type: "application".to_string(),
                    bom_ref: bom_ref.clone(),
                    name: server
                        .package_name
                        .clone()
                        .unwrap_or_else(|| server.name.clone()),
                    version: server.package_version.clone(),
                    group: server
                        .package_ecosystem
                        .as_ref()
                        .map(|e| format!("mcp-server/{}", e)),
                    publisher: Some(mcp.vendor.clone()),
                    description: Some(format!(
                        "MCP server '{}' from {}",
                        server.name, mcp.config_source
                    )),
                    purl,
                    properties,
                    external_references: external_refs,
                });

                host_deps.push(bom_ref);
            }

            // For MCP servers we couldn't get detail on, still record by name
            if mcp.servers.is_empty() {
                for name in &mcp.server_names {
                    let bom_ref = format!("mcp:{}", name);
                    components.push(BomComponent {
                        component_type: "application".to_string(),
                        bom_ref: bom_ref.clone(),
                        name: name.clone(),
                        version: None,
                        group: Some("mcp-server/unknown".to_string()),
                        publisher: Some(mcp.vendor.clone()),
                        description: Some(format!(
                            "MCP server '{}' from {} (no package identity resolved)",
                            name, mcp.config_source
                        )),
                        purl: None,
                        properties: vec![BomProperty {
                            name: "rmg:config-source".to_string(),
                            value: mcp.config_source.clone(),
                        }],
                        external_references: Vec::new(),
                    });
                    host_deps.push(bom_ref);
                }
            }
        }

        // IDE extensions as components
        for ext in &report.ide_extensions {
            let bom_ref = format!("ide-ext:{}:{}", ext.ide_type, ext.id);
            let purl = Some(format!(
                "pkg:vscode/{}/{}@{}",
                ext.publisher, ext.name, ext.version
            ));

            components.push(BomComponent {
                component_type: "library".to_string(),
                bom_ref: bom_ref.clone(),
                name: ext.name.clone(),
                version: Some(ext.version.clone()),
                group: Some(ext.ide_type.clone()),
                publisher: Some(ext.publisher.clone()),
                description: None,
                purl,
                properties: vec![BomProperty {
                    name: "rmg:ide-type".to_string(),
                    value: ext.ide_type.clone(),
                }],
                external_references: Vec::new(),
            });
            host_deps.push(bom_ref);
        }

        // Browser extensions as components
        for ext in &report.browser_extensions {
            let bom_ref = format!("browser-ext:{}:{}", ext.browser, ext.id);

            components.push(BomComponent {
                component_type: "library".to_string(),
                bom_ref: bom_ref.clone(),
                name: ext.name.clone(),
                version: Some(ext.version.clone()),
                group: Some(ext.browser.clone()),
                publisher: None,
                description: ext.description.clone(),
                purl: None,
                properties: vec![
                    BomProperty {
                        name: "rmg:browser".to_string(),
                        value: ext.browser.clone(),
                    },
                    BomProperty {
                        name: "rmg:profile".to_string(),
                        value: ext.profile.clone(),
                    },
                ],
                external_references: Vec::new(),
            });
            host_deps.push(bom_ref);
        }

        // Rules files as data components
        for rf in &report.rules_files {
            let bom_ref = format!("rules:{}", rf.file_name);
            let mut properties = vec![
                BomProperty {
                    name: "rmg:rules-hash".to_string(),
                    value: format!("sha256:{}", rf.sha256),
                },
                BomProperty {
                    name: "rmg:git-tracked".to_string(),
                    value: rf.git_tracked.to_string(),
                },
            ];
            for finding in &rf.findings {
                properties.push(BomProperty {
                    name: format!("rmg:finding:{}", finding.severity),
                    value: finding.pattern.clone(),
                });
            }

            components.push(BomComponent {
                component_type: "data".to_string(),
                bom_ref: bom_ref.clone(),
                name: rf.file_name.clone(),
                version: None,
                group: Some("agent-rules".to_string()),
                publisher: None,
                description: Some(format!(
                    "Agent rules file ({} bytes)",
                    rf.size_bytes
                )),
                purl: None,
                properties,
                external_references: Vec::new(),
            });
            host_deps.push(bom_ref);
        }

        // Agent skills as application components
        for skill in &report.agent_skills {
            let bom_ref = format!("skill:{}:{}", skill.framework, skill.name);
            let mut properties = vec![
                BomProperty {
                    name: "rmg:skill-type".to_string(),
                    value: skill.scope.clone(),
                },
                BomProperty {
                    name: "rmg:framework".to_string(),
                    value: skill.framework.clone(),
                },
                BomProperty {
                    name: "rmg:file-type".to_string(),
                    value: skill.file_type.clone(),
                },
                BomProperty {
                    name: "rmg:skill-hash".to_string(),
                    value: format!("sha256:{}", skill.sha256),
                },
            ];
            if !skill.capabilities.is_empty() {
                properties.push(BomProperty {
                    name: "rmg:capabilities".to_string(),
                    value: skill.capabilities.join(","),
                });
            }

            components.push(BomComponent {
                component_type: "application".to_string(),
                bom_ref: bom_ref.clone(),
                name: skill.name.clone(),
                version: None,
                group: Some(format!("agent-skill/{}", skill.framework)),
                publisher: None,
                description: Some(format!(
                    "{} skill ({})",
                    skill.framework, skill.scope
                )),
                purl: None,
                properties,
                external_references: Vec::new(),
            });
            host_deps.push(bom_ref);
        }

        // AI tools as components
        for tool in &report.ai_agents_and_tools {
            let bom_ref = format!(
                "ai-tool:{}",
                tool.name.replace(' ', "-").to_lowercase()
            );

            let mut properties = vec![BomProperty {
                name: "rmg:tool-type".to_string(),
                value: format!("{:?}", tool.tool_type),
            }];
            if tool.is_running {
                properties.push(BomProperty {
                    name: "rmg:running".to_string(),
                    value: "true".to_string(),
                });
            }

            components.push(BomComponent {
                component_type: "application".to_string(),
                bom_ref: bom_ref.clone(),
                name: tool.name.clone(),
                version: tool.version.clone(),
                group: None,
                publisher: Some(tool.vendor.clone()),
                description: None,
                purl: None,
                properties,
                external_references: Vec::new(),
            });
            host_deps.push(bom_ref);
        }

        if !host_deps.is_empty() {
            dependencies.push(BomDependency {
                dep_ref: host_ref.clone(),
                depends_on: host_deps,
            });
        }

        CycloneDxBom {
            bom_format: "CycloneDX",
            spec_version: "1.6",
            version: 1,
            metadata: BomMetadata {
                timestamp: report.scan_timestamp_iso.clone(),
                tools: vec![BomTool {
                    vendor: "rustmachineguard".to_string(),
                    name: "dev-machine-guard".to_string(),
                    version: report.agent_version.clone(),
                }],
                component: BomMetadataComponent {
                    component_type: "device",
                    name: report.device.hostname.clone(),
                    version: Some(format!(
                        "{} {}",
                        report.device.os_name, report.device.os_version
                    )),
                },
            },
            components,
            dependencies,
        }
    }
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
        (
            Some(parts[1].to_string()),
            parts[0].to_string(),
        )
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
