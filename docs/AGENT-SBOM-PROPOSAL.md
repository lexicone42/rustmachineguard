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

### Current State

We have implemented the foundation:

1. **Deep MCP package identity parsing** (`infer_package_from_command`) — extracts ecosystem, package name, and version from npx/bunx/uvx/pipx/docker/python launcher commands
2. **CycloneDX SBOM output** (`--format sbom`) — generates a valid CycloneDX 1.6 BOM with MCP servers, IDE extensions, browser extensions, and AI tools as components
3. **PURL generation** — produces valid Package URLs for npm, PyPI, and Docker MCP servers
4. **URL sanitization** — strips credentials and paths from remote MCP endpoints
5. **Exposure catalog matching** (`--threat-catalog`) — checks discovered components against a JSON catalog of known-bad packages

### Completed

**Inventory & integrity**

| Feature | Status |
|---|---|
| Skill scanning (Claude Code commands, hooks, Codex) | Done |
| Rules/memory file inventory (.cursorrules, CLAUDE.md, AGENTS.md, MEMORY.md, SOUL.md, …) | Done |
| Rules file integrity hashing (SHA-256, native `sha2`) | Done |
| Dangerous pattern detection (3 severity levels) | Done |
| Capability inference (8-resource taxonomy) | Done |
| Agent settings scanner (hooks = shell exec on tool-use, MCP auto-approval, permission mode) | Done |
| AI credential scanner (at-rest tokens + permissions, values never read) | Done |
| `.env` scanner in agent project roots (git-tracked/world-readable, key names only) | Done |

**Threat intelligence**

| Feature | Status |
|---|---|
| Built-in threat catalog (62 entries, fully attributed — see THREAT-CATALOG.md) | Done |
| Exact + **semver version-range** matching (`version_range`, e.g. `<1.4.3`) | Done |
| MCP live probing (`--probe-mcp`) — tools/resources enumeration over JSON-RPC | Done |
| Tool & parameter description poisoning + invisible-Unicode smuggling detection | Done |

**Composition & temporal analysis** (signals no single MCP client sees)

| Feature | Status |
|---|---|
| Scan diffing (`--diff baseline.json`) — drift across runs | Done |
| Rug-pull detection — a trusted tool mutating its description/parameter schema between scans | Done |
| Cross-server tool shadowing — same tool name from two servers (confused-deputy) | Done |
| Toxic-flow / lethal-trifecta surface — sensitive source + exfil sink across the agent surface | Done |

**Standards output**

| Feature | Status |
|---|---|
| CycloneDX 1.6 SBOM output (`--format sbom`) | Done |
| CycloneDX 2.0 Blueprint output (`--format blueprint`) | Done |
| **Blueprint schema-validation gate** — output validated against the vendored 2.0 draft schema in CI | Done |
| Referential-integrity invariant — no dangling behavior/flow references | Done |

### Planned Additions

| Feature | Priority | Effort |
|---|---|---|
| Plugin scanning (Claude Code plugins, DXT) | Medium | Medium |
| JetBrains plugin scanner (catalog has entries; no scanner yet) | Medium | Medium |
| VEX overlay generation for exposure findings | Low | Medium |
| SPDX output format | Low | High |
| Sigstore-compatible signing of SBOM output | Low | High |
| Native `threats`/`risks` modeling once CycloneDX 2.0 finalizes (2026-08-31) | Medium | Medium |
| Runtime behavior monitoring (declared → observed) | Low | High |

### Blueprint Example Output

```json
{
  "specFormat": "CycloneDX",
  "specVersion": "2.0",
  "version": 1,
  "metadata": {
    "timestamp": "2026-06-30T18:14:27Z",
    "tools": { "components": [
      { "type": "application", "group": "rustmachineguard", "name": "dev-machine-guard", "version": "0.1.0" }
    ]},
    "component": { "type": "device", "name": "bertie", "version": "Gentoo Linux 2.18" }
  },
  "components": [
    {
      "type": "application",
      "bom-ref": "ai-tool:claude-code",
      "name": "Claude Code",
      "version": "2.1.196"
    },
    {
      "type": "application",
      "bom-ref": "mcp:filesystem",
      "name": "@modelcontextprotocol/server-filesystem",
      "version": "1.0.0",
      "properties": [{ "name": "rmg:purl", "value": "pkg:npm/@modelcontextprotocol/server-filesystem@1.0.0" }]
    },
    {
      "type": "application",
      "bom-ref": "skill:claude-code:deploy",
      "name": "deploy",
      "group": "agent-skill/claude-code"
    },
    {
      "type": "data",
      "bom-ref": "rules:claude.md",
      "name": "CLAUDE.md",
      "group": "agent-rules"
    }
  ],
  "blueprints": [
    {
      "bom-ref": "blueprint:agent-posture",
      "name": "Agent Security Posture",
      "modelTypes": ["behavioral", "data-flow"],
      "assets": [
        {
          "bom-ref": "asset:ai-tool:claude-code",
          "type": "agent",
          "zone": "zone:local",
          "componentRef": "ai-tool:claude-code",
          "responsibilities": ["Code generation", "Tool orchestration"]
        },
        {
          "bom-ref": "asset:mcp:filesystem",
          "type": "tool",
          "zone": "zone:local",
          "componentRef": "mcp:filesystem",
          "interfaces": [{
            "name": "filesystem-interface",
            "type": "cli",
            "protocol": "mcp",
            "dataFormat": "JSON-RPC"
          }]
        },
        {
          "bom-ref": "asset:skill:claude-code:deploy",
          "type": "tool",
          "zone": "zone:local",
          "componentRef": "skill:claude-code:deploy"
        }
      ],
      "behaviors": {
        "instances": [
          {
            "bom-ref": "behavior:0",
            "behavior": "application:codeExecution:executesNativeCommand",
            "acknowledgment": ["declared"],
            "actors": ["asset:skill:claude-code:deploy"]
          },
          {
            "bom-ref": "behavior:1",
            "behavior": "application:codeExecution",
            "acknowledgment": ["declared"],
            "actors": ["asset:rules:claude.md"]
          }
        ]
      },
      "flows": [
        {
          "bom-ref": "flow:claude-code->filesystem",
          "name": "Claude Code → filesystem",
          "type": "control",
          "source": "asset:ai-tool:claude-code",
          "destination": "asset:mcp:filesystem",
          "description": "MCP tool invocation via stdio transport"
        }
      ],
      "zones": [
        {"bom-ref": "zone:local", "type": "trust", "name": "Local Machine"},
        {"bom-ref": "zone:remote", "type": "trust", "name": "Remote Services"}
      ],
      "boundaries": [
        {"bom-ref": "boundary:local-remote", "type": "trust", "zones": ["zone:local", "zone:remote"]}
      ]
    }
  ]
}
```

**Schema conformance (enforced).** The Blueprint output is validated against the
vendored CycloneDX 2.0 draft schema (branch `2.0-dev-threatmodeling`, head `03a8eaa7`)
by `tests/blueprint_schema.rs`, using the `jsonschema` crate. This is a real gate:
drift in either the generator or a re-vendored schema fails the build. Highlights of
the draft we conform to:

- root envelope is `specFormat` (renamed from `bomFormat`), `specVersion` `"2.0"`,
  `additionalProperties: false`
- `metadata.tools` is an object `{ components, services }`, not an array
- components carry no top-level `purl` (we emit it as an `rmg:purl` property)
- `behaviors` is an object with an `instances` array (not a bare array)
- each `behaviorInstance` requires a `bom-ref`, forbids `properties`, and its
  `behavior` must be a value from the **closed 740-value behavior taxonomy** (e.g.
  `ai:agent:invokesTool`, `application:codeExecution:executesNativeCommand`,
  `security:authentication`). Human-readable specifics (advisories, severities,
  capability names) therefore live on the related asset, which permits properties.
- `acknowledgment` is an array of enum values (`declared` | `observed`)
- `flow` carries a required `type` (control/data/…) and `destination` (not `target`)

A separate `tests/property_tests.rs` invariant asserts every behavior actor/target and
flow source/destination resolves to an emitted asset `bom-ref` — no dangling references.
The draft is still moving (milestone due 2026-08-31); re-vendor the fixtures and re-run
the gate when bumping the pin.

## Security Considerations

### What This Enables

1. **Incident response**: "Which developer machines have the compromised `postmark-mcp@0.3.1` installed?" — answered in seconds by querying SBOMs
2. **Compliance**: EU AI Act requires inventory of AI components; an ADBOM provides auditable evidence
3. **Drift detection**: Comparing SBOMs across runs detects unauthorized MCP server additions or version changes
4. **Fleet visibility**: Aggregating SBOMs across an organization reveals the total agent attack surface

### What This Does Not Address

- **Runtime behavior**: Our `--format sbom` inventories what's installed; our `--format blueprint` adds static capability inference (declared behaviors). Neither performs runtime monitoring. Runtime monitoring requires hooks (like upstream's `aiagents` subsystem) or proxy-based approaches (like Snyk's agent-scan proxy mode). When CycloneDX 2.0 finalizes, the behavior acknowledgment field (`declared` vs `observed`) will allow combining our static output with runtime observations
- **Transitive dependencies**: We resolve the MCP server's package identity but not its dependency tree. Traditional SBOM tools (Syft, Trivy) can be pointed at the resolved package for full dependency analysis
- **Payload analysis**: We don't inspect MCP server code for malicious behavior. Tools like Cisco's MCP Scanner (YARA rules) or SkillFortify (formal analysis) complement our inventory approach

## Relationship to Existing Standards

### CycloneDX 1.6 (Current Stable)

We target CycloneDX 1.6 for our `--format sbom` output because:
- It has the most flexible property system for agent-specific metadata
- ML-BOM v1.7 provides precedent for AI component types
- The `application` and `data` component types map naturally to MCP servers and rules files
- Wide tooling support (dependency-track, grype, etc.)

### CycloneDX 2.0 Blueprints (Draft — `--format blueprint`)

CycloneDX 2.0 (milestone due 2026-08-31, 27/89 issues closed) introduces **Blueprints** — a schema that describes *what software does*, not just what it contains. This is the standards-track successor to both our `rmg:` property approach and SkillFortify's ASBOM.

**Key references:**
- Milestone: https://github.com/CycloneDX/specification/milestone/8
- Blueprint schema PR: https://github.com/CycloneDX/specification/pull/951 (merged into staging)
- TM-BOM issue: https://github.com/CycloneDX/specification/issues/462
- Blueprints issue: https://github.com/CycloneDX/specification/issues/463
- 2.0 dev tracking: https://github.com/CycloneDX/specification/issues/678
- MLBOM 2.0 agent cards: https://github.com/CycloneDX/specification/issues/702
- Agent BOM (closed as duplicate → #462+#463): https://github.com/CycloneDX/specification/issues/895

**Blueprint schema highlights** (from `cyclonedx-blueprint-2.0.schema.json`):

| Concept | Description | How We Map It |
|---|---|---|
| **Asset types** | `agent`, `tool`, `data`, `model`, `api`, `data-store`, `endpoint` | AI tools → `agent`; MCP servers + skills → `tool`; rules files → `data` |
| **Behaviors** | What objects do, who performs them, what they target | Capability inference results (`filesystem`, `network`, `shell`, etc.) |
| **Flows** | Data/control movement between assets | Agent → MCP server invocations |
| **Zones** | Trust/network/process isolation groups | `local` (workstation) vs `remote` (SSE/HTTP MCP servers) |
| **Boundaries** | Edges between zones with crossing requirements | Trust boundary between local and remote zones |
| **Interfaces** | API/CLI/stream endpoints on assets | MCP transport (stdio→CLI, SSE→stream, HTTP→API) |
| **Model types** | `behavioral`, `data-flow`, `architecture`, etc. | We emit `behavioral` + `data-flow` |

**Behavior schema highlights** (from `cyclonedx-behavior-2.0.schema.json`):
- Behavior instances: actors (who does it) + targets (what it acts on)
- Behavior graphs: activity flows and state machines
- Triggers: startup, shutdown, scheduled
- Acknowledgment: `declared` vs `observed` — maps to our static-inference vs runtime distinction
- Node types: activity, state, event, gateway

**Why Blueprints supersede ASBOM:**
- SkillFortify's ASBOM uses CycloneDX 1.6 + custom `skillfortify:` properties — functionally similar to our `rmg:` approach
- Blueprints provide **native schema fields** for everything ASBOM encodes in properties: asset types, behaviors, flows, zones
- Blueprints are backed by OWASP/Ecma standardization, not a single researcher
- SkillFortify is Elastic License 2.0 (not open source); Blueprints are Apache 2.0

**Our implementation** (`--format blueprint`):
- Generates a CycloneDX 2.0 draft document (`specVersion "2.0"`, `blueprints[]` top-level field), **validated against the vendored draft schema in CI**
- Maps AI tools to agent assets, MCP servers/skills to tool assets, rules/memory files to data assets
- Capability inference results become behavior instances (mapped to the closed behavior taxonomy)
- Agent-to-MCP, agent-to-skill, and rules-to-agent connections become typed flows
- Local vs remote MCP servers are placed in trust zones
- Probed tool/resource poisoning, cross-server shadowing, exposure matches, blast-radius (SSH/cloud), and the toxic-flow surface all surface as assets + behaviors
- Still includes `components[]` (PURLs carried as `rmg:purl` properties) for inventory compatibility

### CycloneDX Agent BOM History

The concept of an "Agent BOM" was proposed as issue #895 on the CycloneDX spec. It was closed as a duplicate because the use case is already addressed by the combination of:
- **#462 (TM-BOM)**: Threat Model BOM — threat modeling constructs including zones, boundaries, flows
- **#463 (Blueprints)**: Behavioral modeling — assets, behaviors, interfaces
- **#678 (2.0 dev tracking)**: The 2.0 release that merges all of the above

The actual work landed in PR #951 (blueprint schema) and PR #760 (Petra's schema contributions). The `agent` and `tool` asset types were explicitly added for AI agent use cases.

### OWASP MCP Top 10

Our ADBOM addresses several OWASP MCP risk categories:
- **MCP04 (Tool Poisoning)**: Exposure catalog matching detects known-poisoned tools
- **MCP08 (Supply Chain)**: Package identity resolution enables version pinning and vulnerability scanning
- **MCP10 (Logging)**: SBOM generation provides auditable inventory

### Package URL (PURL)

We follow the PURL specification for npm, PyPI, and Docker ecosystems. We propose new PURL types for agent-specific components (`agent-skill`, `claude-plugin`) that don't fit existing types.

## Call to Action

1. **Track CycloneDX 2.0**: The Blueprint schema (due 2026-08-31) will formalize everything we currently encode in `rmg:` properties. Our `--format blueprint` output is an early implementation — we should update it as the schema stabilizes and contribute feedback to the spec process
2. **Contribute to the spec**: Our practical experience mapping agent capabilities, MCP transports, and rules files to Blueprints could inform the CycloneDX 2.0 design. The `agent` and `tool` asset types exist because of use cases like ours
3. **Registry integration**: MCP registries should publish package metadata in a format consumable by SBOM generators
4. **Signing**: Both SBOMs and the components they describe need cryptographic provenance — Sigstore/Cosign for SBOMs, registry-level signing for MCP servers and skills
5. **Benchmark against peers**: Compare output quality with NVIDIA SkillSpector, Bumblebee, mcp-scan, and Snyk Agent Scan to identify coverage gaps

The agent supply chain is the least-governed software surface in modern development. An ADBOM doesn't solve the governance problem, but it makes the problem visible — and visibility is the prerequisite for every other defense.

## Acknowledgments

Our capability taxonomy, dangerous pattern detection, and trust-level classification are informed by the SkillFortify project and its companion paper:

- **SkillFortify** (Varun Pratap Bhardwaj / Qualixar, 2026) — the first formal analysis framework for agent skill supply chains. SkillFortify introduced the Agent Skill Bill of Materials (ASBOM) concept, the DY-Skill attacker model, and a capability-based sandboxing system with formal proofs. Licensed under Elastic License 2.0. https://github.com/qualixar/skillfortify
- **"Formal Analysis and Supply Chain Security for Agentic AI Skills"** (Bhardwaj, 2026) — arXiv:2603.00195. Defines the 8-resource capability taxonomy ({filesystem, network, environment, shell, skill_invoke, clipboard, browser, database} × {NONE, READ, WRITE, ADMIN}), the five-phase skill lifecycle, and the trust score algebra we adapt here.

Our implementation is an independent Rust reimplementation. We do not use or redistribute SkillFortify code. The concepts we adopt from the paper — capability categories, trust levels, and dangerous pattern classes — are academic contributions in the public domain. We credit this work because good ideas deserve attribution.

- **CycloneDX 2.0 Blueprint Schema** (OWASP Foundation / Ecma International, 2026) — the draft specification for behavioral modeling of software systems, including native `agent` and `tool` asset types designed for AI agent use cases. Our `--format blueprint` output implements a subset of this draft schema. Licensed under Apache 2.0. https://github.com/CycloneDX/specification (PR #951, milestone 2.0 due 2026-08-31)
