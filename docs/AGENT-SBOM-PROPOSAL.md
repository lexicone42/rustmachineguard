# Agent Dependency SBOM: A Proposal for MCP Servers and AI Agent Skills

**Status**: Draft proposal — the forward plan is CycloneDX 2.0 Blueprints  
**Date**: July 2026  
**Authors**: rustmachineguard contributors  

> **Direction (2026-07):** we are **not** extending CycloneDX 1.6 with more
> agent-specific machinery. The custom `rmg:` property approach was an interim step to
> prove the model; the plan going forward is the **CycloneDX 2.0 Blueprint** draft
> (`--format blueprint`), which expresses agent posture — assets, behaviors, flows,
> trust zones — as **native, standards-track schema fields** instead of vendor
> properties. `--format sbom` (CycloneDX 1.6) is kept only as a frozen, plain
> component inventory for wide tooling compatibility (Dependency-Track, grype); no new
> agent-specific surface is being retrofitted onto it. This document is a plan for the
> Blueprint work, not a proposal to grow the 1.6 output.

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

## Proposed Direction: CycloneDX 2.0 Blueprints

The question is not *"what custom fields do we bolt onto an SBOM?"* — it is *"which
standard already models what an agent **does**, so we don't invent a private schema?"*
CycloneDX 2.0's **Blueprint** draft answers that: it describes software *behaviorally* —
**assets**, the **behaviors** they exhibit, the **flows** between them, and the trust
**zones** they sit in — with first-class `agent` and `tool` asset types added
specifically for AI use cases.

**Decision: build forward on Blueprints; freeze the 1.6 SBOM.** Our earlier work
encoded agent posture in a custom `rmg:` property namespace on a CycloneDX 1.6 document.
That proved the model — but it is a private dialect no other tool reads. Every signal we
expressed as an `rmg:` property (transport, config source, skill type, capabilities,
findings) has a **native** home in the Blueprint schema. So instead of retrofitting more
`rmg:` properties onto 1.6, **all new agent-posture work targets 2.0 Blueprints**. The
1.6 SBOM stays as a plain component inventory (see below), unextended.

### Why not keep extending 1.6?

| Custom 1.6 + `rmg:` properties | CycloneDX 2.0 Blueprint |
|---|---|
| Agent posture lives in vendor properties no other tool understands | Posture lives in native schema fields (assets, behaviors, flows, zones) |
| We define and maintain the vocabulary ourselves | Closed 740-value behavior taxonomy, OWASP / Ecma-governed |
| Flat component list; "what does it do?" is left for the reader to infer | Explicit behavioral model; capability + risk are first-class |
| Functionally identical to SkillFortify's private `skillfortify:` properties | The standards-track successor to both |

### How agent surfaces map to Blueprint constructs

| Agent surface rmguard discovers | Blueprint construct |
|---|---|
| AI tools (Claude Code, Cursor, Codex, …) | `agent` assets |
| MCP servers, agent skills | `tool` assets (transport modeled as `interfaces`) |
| Rules / memory files (CLAUDE.md, .cursorrules, …) | `data` assets |
| Inferred capabilities (filesystem, network, shell, …) | `behavior` instances (mapped to the closed taxonomy) |
| agent→MCP, agent→skill, rules→agent connections | typed `flows` (control / data) |
| Local workstation vs remote SSE/HTTP endpoints | trust `zones` + a `boundary` between them |
| Static inference vs live probing | behavior `acknowledgment`: `declared` vs `observed` |

**Forward roadmap** (tracks the draft to its 2026-08-31 milestone — see
[Planned Additions](#planned-additions)): adopt the 2.0 `threats` / `risks` constructs
when they land so findings move from asset properties onto native threat objects; grow
`observed` acknowledgments as `--probe-mcp` coverage increases; and re-vendor the schema
fixtures (and re-run the conformance gate) on each draft bump. Feedback from this
implementation goes back to the spec process — the `agent` and `tool` asset types exist
because of use cases like this one.

## Inventory layer (frozen): `--format sbom`, CycloneDX 1.6

`--format sbom` emits a **plain CycloneDX 1.6 component inventory** — "what is installed"
— for compatibility with existing SBOM tooling (Dependency-Track, grype). It is
**frozen**: it still carries agent metadata via the `rmg:` property namespace we already
ship, but no *new* agent-specific surface is added here — that all goes to Blueprints.

What it emits today: MCP servers, IDE / browser extensions, AI tools, rules files, and
skills as CycloneDX `application` / `data` components, PURLs for npm/PyPI/Docker MCP
packages, and properties including `rmg:transport`, `rmg:config-source`, `rmg:command`,
`rmg:rules-hash`, `rmg:git-tracked`, `rmg:skill-type`, `rmg:capabilities`,
`rmg:finding:<severity>`, and `rmg:tool-type`.

> **PURL note:** MCP packages get real PURLs (`pkg:npm/…`, `pkg:pypi/…`, `pkg:docker/…`).
> We do **not** mint custom `pkg:agent-skill/…` / `pkg:claude-plugin/…` PURL types — the
> 1.6 SBOM carries skills/plugins as component *groups*, and the Blueprint models them as
> native `tool` assets, so a bespoke PURL type isn't needed.

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
| Transcript/state store inventory (EAA-005; existence/count/size/perms, content never read) | Done |
| Plugin marketplace inventory (EAA-009; source, official-vs-third-party, auto-update, plugin counts) | Done |
| Agent identity posture (static keys vs OAuth vs SPIFFE; OWASP ASI03) | Done |

**Threat intelligence**

| Feature | Status |
|---|---|
| Built-in threat catalog (82 entries, fully attributed — see THREAT-CATALOG.md) | Done |
| Exact + **semver version-range** matching (`version_range`, e.g. `<1.4.3`) | Done |
| MCP live probing (`--probe-mcp`) — tools/resources enumeration over JSON-RPC | Done |
| Tool & parameter description poisoning + invisible-Unicode smuggling detection | Done |
| MCP config-risk detection — plaintext transport, over-broad fs scope, inline secrets (names only), download-and-execute launch, hostile gateway routing (EAA-007) | Done |
| Official MCP registry verification (`--verify-registry`) — provenance, deprecation, typosquat | Done |

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

**Blueprint track (the plan) — as the 2.0 draft stabilizes toward 2026-08-31:**

| Feature | Priority | Effort |
|---|---|---|
| Adopt native `threats` / `risks` constructs — move findings off asset properties onto first-class threat objects | High | Medium |
| Grow `observed` acknowledgments as `--probe-mcp` coverage expands (declared → observed) | High | High |
| Re-vendor schema fixtures + re-run the conformance gate on each draft bump | High | Low |
| Contribute mapping feedback (agent/tool assets, MCP transports, rules files) back to the spec | Medium | Low |

**Inventory / scanning track (feeds both outputs):**

| Feature | Priority | Effort |
|---|---|---|
| Per-plugin / DXT content scanning (marketplace-level inventory already Done) | Medium | Medium |
| JetBrains plugin scanner (catalog has entries; no scanner yet) | Medium | Medium |

**Not planned for the frozen 1.6 SBOM** (would be Blueprint work instead): VEX overlays,
SPDX output, Sigstore signing, runtime monitoring — parked at low priority; if pursued,
they attach to the Blueprint, not the 1.6 inventory.

### Blueprint Example Output

```json
{
  "specFormat": "CycloneDX",
  "specVersion": "2.0",
  "version": 1,
  "metadata": {
    "timestamp": "2026-06-30T18:14:27Z",
    "tools": { "components": [
      { "type": "application", "group": "rustmachineguard", "name": "rmguard", "version": "0.1.0" }
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
vendored CycloneDX 2.0 draft schema (branch `2.0-dev`, head `72b37340`)
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
2. **Compliance**: EU AI Act requires inventory of AI components; the SBOM + Blueprint outputs provide auditable evidence
3. **Drift detection**: Comparing SBOMs across runs detects unauthorized MCP server additions or version changes
4. **Fleet visibility**: Aggregating SBOMs across an organization reveals the total agent attack surface

### What This Does Not Address

- **Runtime behavior**: Our `--format sbom` inventories what's installed; our `--format blueprint` adds static capability inference (declared behaviors). Neither performs runtime monitoring. Runtime monitoring requires hooks (like upstream's `aiagents` subsystem) or proxy-based approaches (like Snyk's agent-scan proxy mode). When CycloneDX 2.0 finalizes, the behavior acknowledgment field (`declared` vs `observed`) will allow combining our static output with runtime observations
- **Transitive dependencies**: We resolve the MCP server's package identity but not its dependency tree. Traditional SBOM tools (Syft, Trivy) can be pointed at the resolved package for full dependency analysis
- **Payload analysis**: We don't inspect MCP server code for malicious behavior. Tools like Cisco's MCP Scanner (YARA rules) or SkillFortify (formal analysis) complement our inventory approach

## Relationship to Existing Standards

### CycloneDX 1.6 (frozen inventory only)

`--format sbom` stays on CycloneDX 1.6 purely as a plain component inventory, because
1.6 has wide tooling support (Dependency-Track, grype) and its `application` / `data`
component types map cleanly to MCP servers and rules files. We are **not** growing the
agent-specific surface here — the flexible-property system that made 1.6 convenient for a
first pass is exactly the private-dialect problem Blueprints solve. New work targets 2.0.

### CycloneDX 2.0 Blueprints (Draft — `--format blueprint`) — the direction

CycloneDX 2.0 (milestone due 2026-08-31, 27/89 issues closed) introduces **Blueprints** — a schema that describes *what software does*, not just what it contains. This is the standards-track successor to both our interim `rmg:` property approach and SkillFortify's ASBOM, and it is where all forward agent-posture work lands.

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

Our outputs address several OWASP MCP risk categories:
- **MCP04 (Tool Poisoning)**: Exposure catalog matching detects known-poisoned tools
- **MCP08 (Supply Chain)**: Package identity resolution enables version pinning and vulnerability scanning
- **MCP10 (Logging)**: inventory + Blueprint generation provides auditable evidence

### Package URL (PURL)

We follow the PURL specification for the ecosystems that have one — `pkg:npm/…`,
`pkg:pypi/…`, `pkg:docker/…` for MCP packages. We deliberately do **not** invent custom
`agent-skill` / `claude-plugin` PURL types (an earlier idea): skills and plugins have no
registry to anchor a PURL, and the Blueprint models them as native `tool` assets, so a
bespoke PURL type would be a private dialect for no gain.

## Call to Action

1. **Move the posture model fully onto Blueprints**: The 2.0 Blueprint schema (due 2026-08-31) provides native fields for everything the interim `rmg:` property approach encoded. The plan is to track the draft and deepen `--format blueprint` — **not** to retrofit more agent-specific machinery onto the frozen 1.6 SBOM
2. **Contribute to the spec**: Our practical experience mapping agent capabilities, MCP transports, and rules files to Blueprints could inform the CycloneDX 2.0 design. The `agent` and `tool` asset types exist because of use cases like ours
3. **Registry integration**: MCP registries should publish package metadata in a format consumable by SBOM generators
4. **Signing**: Both SBOMs and the components they describe need cryptographic provenance — Sigstore/Cosign for SBOMs, registry-level signing for MCP servers and skills
5. **Benchmark against peers**: Compare output quality with NVIDIA SkillSpector, Bumblebee, mcp-scan, and Snyk Agent Scan to identify coverage gaps

The agent supply chain is the least-governed software surface in modern development. A
standards-track Blueprint doesn't solve the governance problem, but it makes the problem
visible in a language other tools can read — and visibility is the prerequisite for every
other defense.

## Acknowledgments

Our capability taxonomy, dangerous pattern detection, and trust-level classification are informed by the SkillFortify project and its companion paper:

- **SkillFortify** (Varun Pratap Bhardwaj / Qualixar, 2026) — the first formal analysis framework for agent skill supply chains. SkillFortify introduced the Agent Skill Bill of Materials (ASBOM) concept, the DY-Skill attacker model, and a capability-based sandboxing system with formal proofs. Licensed under Elastic License 2.0. https://github.com/qualixar/skillfortify
- **"Formal Analysis and Supply Chain Security for Agentic AI Skills"** (Bhardwaj, 2026) — arXiv:2603.00195. Defines the 8-resource capability taxonomy ({filesystem, network, environment, shell, skill_invoke, clipboard, browser, database} × {NONE, READ, WRITE, ADMIN}), the five-phase skill lifecycle, and the trust score algebra we adapt here.

Our implementation is an independent Rust reimplementation. We do not use or redistribute SkillFortify code. The concepts we adopt from the paper — capability categories, trust levels, and dangerous pattern classes — are academic contributions in the public domain. We credit this work because good ideas deserve attribution.

- **CycloneDX 2.0 Blueprint Schema** (OWASP Foundation / Ecma International, 2026) — the draft specification for behavioral modeling of software systems, including native `agent` and `tool` asset types designed for AI agent use cases. Our `--format blueprint` output implements a subset of this draft schema. Licensed under Apache 2.0. https://github.com/CycloneDX/specification (PR #951, milestone 2.0 due 2026-08-31)
