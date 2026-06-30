# Agent Dependency SBOM: A Proposal for MCP Servers and AI Agent Skills

**Status**: Draft proposal  
**Date**: June 2026  
**Authors**: rustmachineguard contributors  

## Problem Statement

AI coding agents (Claude Code, Codex, Cursor, Copilot, etc.) depend on a new class of software components that existing SBOM standards don't adequately cover:

1. **MCP Servers** — installed via `npx`, `pip`, `docker`, or as local scripts with zero provenance tracking
2. **Agent Skills** — instruction files (.claude/commands/, OpenClaw skills, .cursorrules) treated as inert text despite executing arbitrary actions
3. **Agent Plugins/Extensions** — marketplace-distributed packages (DXT, Claude plugins) with no code signing

These components form the **agent supply chain** — the software an AI agent depends on to function, which a developer implicitly trusts by enabling it. Unlike traditional dependencies (npm packages, Python libraries), these components:

- Have **no lockfile discipline** — MCP configs reference packages by name without pinned versions
- Have **no integrity verification** — no checksums, no signatures, no provenance attestation
- Have **no unified inventory** — scattered across 10+ config file formats and locations
- Are **actively exploited** — the ClawHavoc campaign planted 1,200+ malicious skills; the "postmark-mcp" incident silently BCC'd emails for 300 organizations; 82% of MCP implementations are vulnerable to path traversal

## Landscape Analysis

### What Exists

| Tool/Standard | Coverage | Limitation |
|---|---|---|
| **CycloneDX ML-BOM v1.7** | Models, APIs, datasets | No MCP/skill/plugin components |
| **SkillFortify ASBOM** | 22 agent frameworks | Research project (26 GitHub stars), no rules file coverage |
| **Bumblebee** (Perplexity) | npm/PyPI/Go lockfiles + MCP configs | Package inventory only, no SBOM output |
| **APIsec mcp-audit** | MCP server configs | CycloneDX output, but MCP-only |
| **vercel-labs/skills** | Skill lock files | SHA-256 hashes, but ecosystem-specific |
| **OWASP MCP Top 10** | Recommends SBOMs | No format specification |
| **Traditional SBOMs** (Syft, Trivy) | Package dependencies | Unaware of MCP configs, skills, or agent-specific surfaces |

### What's Missing

**No single standard covers the full agent dependency surface:**

- MCP servers (STDIO + SSE + HTTP transports)
- Agent skills (bash scripts, markdown instructions, YAML definitions)
- Rules/instruction files (.cursorrules, copilot-instructions.md, CLAUDE.md, AGENTS.md)
- Agent plugins (DXT archives, Claude Code plugins)
- Agent hooks (pre/post tool use, session lifecycle)

**No cross-tool auditing** — Bumblebee scans lockfiles, mcp-scan checks MCP servers, Pillar scans rules files, SkillFortify scans skills, but nothing produces a unified inventory.

**Rules files are completely ungoverned** — no integrity verification, no signing, no provenance, no SBOM inclusion. Yet they directly control agent behavior and have been weaponized (Rules File Backdoor attack, 84% success rate).

## Proposed Solution: Agent Dependency BOM (ADBOM)

We propose extending CycloneDX with agent-specific component types and properties, producing a unified inventory of everything an AI agent depends on.

### Component Taxonomy

```
Agent Dependency BOM
├── MCP Servers (application components)
│   ├── STDIO transport (local process)
│   │   └── Package identity: ecosystem, name, version, PURL
│   ├── SSE/HTTP transport (remote)
│   │   └── Endpoint URL (sanitized), auth method
│   └── Metadata: config source, activation state
├── Agent Skills (application components)
│   ├── Built-in skills (.claude/commands/)
│   ├── Marketplace skills (installed, with provenance)
│   └── Project-local skills (per-repo)
├── Rules Files (data components)
│   ├── .cursorrules, CLAUDE.md, copilot-instructions.md, AGENTS.md
│   └── Integrity: SHA-256 hash, git-tracked status
├── Agent Plugins (library components)
│   ├── DXT archives (Claude Desktop extensions)
│   ├── Claude Code plugins (marketplace + community)
│   └── IDE extensions with AI capabilities
└── Agent Hooks (application components)
    ├── Pre/post tool use hooks
    └── Session lifecycle hooks
```

### CycloneDX Property Namespace

We propose the `rmg:` (rustmachineguard) property namespace for agent-specific metadata:

| Property | Description | Example |
|---|---|---|
| `rmg:transport` | MCP transport type | `stdio`, `sse`, `http` |
| `rmg:config-source` | Where the component was discovered | `Claude Code`, `Cursor`, `Project MCP (/home/user/proj)` |
| `rmg:command` | Launch command for STDIO servers | `npx` |
| `rmg:skill-type` | Skill classification | `builtin`, `marketplace`, `project-local` |
| `rmg:rules-hash` | SHA-256 of rules file content | `a1b2c3...` |
| `rmg:git-tracked` | Whether the file is under git | `true` |
| `rmg:activation-state` | Whether the component is currently active | `enabled`, `disabled` |
| `rmg:auth-method` | Authentication for remote transports | `oauth`, `bearer`, `none` |
| `rmg:tool-type` | AI tool classification | `cli_tool`, `desktop_app`, `agent` |

### PURL Extensions

Package URLs for agent components:

```
# npm MCP server
pkg:npm/@modelcontextprotocol/server-filesystem@1.0.0

# PyPI MCP server
pkg:pypi/mcp-server-sqlite@0.3.1

# Docker MCP server
pkg:docker/mcp/postgres@latest

# VSCode extension
pkg:vscode/publisher/extension-name@1.2.3

# Agent skill (proposed new PURL type)
pkg:agent-skill/openclaw/skill-name@0.1.0

# Claude Code plugin (proposed new PURL type)
pkg:claude-plugin/marketplace/plugin-name@1.0.0
```

### Example Output

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "metadata": {
    "timestamp": "2026-06-30T12:00:00Z",
    "tools": [{
      "vendor": "rustmachineguard",
      "name": "dev-machine-guard",
      "version": "0.2.0"
    }],
    "component": {
      "type": "device",
      "name": "dev-laptop-01",
      "version": "Gentoo Linux 2.15"
    }
  },
  "components": [
    {
      "type": "application",
      "bom-ref": "mcp:filesystem",
      "name": "@modelcontextprotocol/server-filesystem",
      "version": "1.0.0",
      "group": "mcp-server/npm",
      "purl": "pkg:npm/@modelcontextprotocol/server-filesystem@1.0.0",
      "properties": [
        {"name": "rmg:transport", "value": "stdio"},
        {"name": "rmg:config-source", "value": "Claude Code"},
        {"name": "rmg:command", "value": "npx"}
      ]
    },
    {
      "type": "application",
      "bom-ref": "mcp:remote-api",
      "name": "remote-api",
      "group": "mcp-server/unknown",
      "properties": [
        {"name": "rmg:transport", "value": "sse"},
        {"name": "rmg:config-source", "value": "Cursor"}
      ],
      "externalReferences": [
        {"type": "distribution", "url": "https://mcp.example.com"}
      ]
    },
    {
      "type": "data",
      "bom-ref": "rules:cursorrules",
      "name": ".cursorrules",
      "properties": [
        {"name": "rmg:rules-hash", "value": "sha256:a1b2c3..."},
        {"name": "rmg:git-tracked", "value": "true"}
      ]
    }
  ],
  "dependencies": [
    {
      "ref": "host:dev-laptop-01",
      "dependsOn": ["mcp:filesystem", "mcp:remote-api", "rules:cursorrules"]
    }
  ]
}
```

## Implementation in rustmachineguard

### Current State (v0.2.0)

We have implemented the foundation:

1. **Deep MCP package identity parsing** (`infer_package_from_command`) — extracts ecosystem, package name, and version from npx/bunx/uvx/pipx/docker/python launcher commands
2. **CycloneDX SBOM output** (`--format sbom`) — generates a valid CycloneDX 1.6 BOM with MCP servers, IDE extensions, browser extensions, and AI tools as components
3. **PURL generation** — produces valid Package URLs for npm, PyPI, and Docker MCP servers
4. **URL sanitization** — strips credentials and paths from remote MCP endpoints
5. **Exposure catalog matching** (`--threat-catalog`) — checks discovered components against a JSON catalog of known-bad packages

### Planned Additions

| Feature | Priority | Effort |
|---|---|---|
| Skill scanning (Claude Code .claude/commands/, OpenClaw) | High | Medium |
| Rules file inventory (.cursorrules, CLAUDE.md, AGENTS.md) | High | Low |
| Rules file integrity hashing (SHA-256) | High | Low |
| Plugin scanning (Claude Code plugins, DXT) | Medium | Medium |
| YAML/TOML MCP server detail extraction | Medium | Low |
| Hook inventory (Claude Code hooks, Codex hooks) | Medium | Medium |
| VEX overlay generation for exposure findings | Low | Medium |
| SPDX output format | Low | High |
| Sigstore-compatible signing of SBOM output | Low | High |

## Security Considerations

### What This Enables

1. **Incident response**: "Which developer machines have the compromised `postmark-mcp@0.3.1` installed?" — answered in seconds by querying SBOMs
2. **Compliance**: EU AI Act requires inventory of AI components; an ADBOM provides auditable evidence
3. **Drift detection**: Comparing SBOMs across runs detects unauthorized MCP server additions or version changes
4. **Fleet visibility**: Aggregating SBOMs across an organization reveals the total agent attack surface

### What This Does Not Address

- **Runtime behavior**: An SBOM inventories what's installed, not what it does at runtime. Runtime monitoring requires hooks (like upstream's `aiagents` subsystem) or proxy-based approaches (like Snyk's agent-scan proxy mode)
- **Transitive dependencies**: We resolve the MCP server's package identity but not its dependency tree. Traditional SBOM tools (Syft, Trivy) can be pointed at the resolved package for full dependency analysis
- **Payload analysis**: We don't inspect MCP server code for malicious behavior. Tools like Cisco's MCP Scanner (YARA rules) or SkillFortify (formal analysis) complement our inventory approach

## Relationship to Existing Standards

### CycloneDX

We target CycloneDX 1.6 because:
- It has the most flexible property system for agent-specific metadata
- ML-BOM v1.7 provides precedent for AI component types
- The `application` and `data` component types map naturally to MCP servers and rules files

### OWASP MCP Top 10

Our ADBOM addresses several OWASP MCP risk categories:
- **MCP04 (Tool Poisoning)**: Exposure catalog matching detects known-poisoned tools
- **MCP08 (Supply Chain)**: Package identity resolution enables version pinning and vulnerability scanning
- **MCP10 (Logging)**: SBOM generation provides auditable inventory

### Package URL (PURL)

We follow the PURL specification for npm, PyPI, and Docker ecosystems. We propose new PURL types for agent-specific components (`agent-skill`, `claude-plugin`) that don't fit existing types.

## Call to Action

1. **Standardize the taxonomy**: The component types and property namespace proposed here should be reviewed by the CycloneDX and MCP communities
2. **Add skill/rules scanning**: rustmachineguard should scan Claude Code commands, OpenClaw skills, and rules files to complete the agent dependency surface
3. **Registry integration**: MCP registries should publish package metadata in a format consumable by SBOM generators
4. **Signing**: Both SBOMs and the components they describe need cryptographic provenance — Sigstore/Cosign for SBOMs, registry-level signing for MCP servers and skills

The agent supply chain is the least-governed software surface in modern development. An ADBOM doesn't solve the governance problem, but it makes the problem visible — and visibility is the prerequisite for every other defense.
