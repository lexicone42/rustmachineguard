# A field-by-field walkthrough of an rmguard Blueprint

**New to Blueprints? Start here.** This walks through a real `rmguard --format blueprint`
document, one construct at a time, in plain language. For the visual mental model (assets
in trust zones, flows crossing boundaries), see the companion explainer artifact; this is
the detailed reference.

## The one-sentence version

A CycloneDX **SBOM** lists *what is installed*. A CycloneDX 2.0 **Blueprint** describes
*what the software does* — which pieces exist (**assets**), what they do (**behaviors**),
how they connect (**flows**), which trust groups they sit in (**zones**), and the danger
layered on top (**threats**, **risks**, **controls**). rmguard emits both:
`--format sbom` (1.6, frozen inventory) and `--format blueprint` (2.0, the posture model).

Everything below is real output from a machine with a couple of MCP servers, a hook, a
skill, and a known-vulnerable package.

---

## 1. The envelope

```json
{ "specFormat": "CycloneDX", "specVersion": "2.0", "version": 1, … }
```

- **`specFormat`** — 2.0 renamed the root key from `bomFormat` → `specFormat`. (Emitting
  the old key is the #1 way to fail schema validation; our CI gate specifically checks this.)
- **`specVersion`** `"2.0"`, **`version`** = the document revision (bump it when you
  re-issue the same logical BOM).

## 2. `metadata` — who/what/when

```json
"metadata": {
  "timestamp": "2026-07-02T23:22:37Z",
  "tools": { "components": [ { "type": "application", "name": "rmguard", "group": "rustmachineguard", "version": "0.1.0" } ] },
  "component": { "type": "device", "name": "bertie", "version": "Gentoo Linux 2.18" }
}
```

- **`tools`** — who generated this. Note it's an **object** `{ components, services }` in
  2.0, not an array like 1.6. (Another common validation trip-up.)
- **`component`** — the *subject* of the BOM: here, the scanned machine (a `device`).

## 3. `components` — the flat inventory

The same "what's installed" list the SBOM carries: MCP servers, tools, extensions, rules
files. In 2.0 a component has **no top-level `purl`**, so we carry it as a property:

```json
{ "type": "application", "bom-ref": "mcp:filesystem",
  "name": "@modelcontextprotocol/server-filesystem", "version": "1.0.0",
  "properties": [ { "name": "rmg:purl", "value": "pkg:npm/@modelcontextprotocol/server-filesystem@1.0.0" } ] }
```

`bom-ref` is an **id** other parts of the document point at. Think of it as a primary key.

---

## 4. `blueprints[0]` — the posture model

One blueprint object holds the whole behavioral picture. `modelTypes` says which lenses
it uses:

```json
"modelTypes": ["behavioral", "data-flow"]
```

### 4a. `assets` — the things that exist

An asset is a *typed* thing. The AI-specific types (`agent`, `tool`) were added to the
spec for exactly this use case. Two ways to write one:

**Component-backed** (points at a `components[]` entry, inherits its name/version):

```json
{ "bom-ref": "asset:ai-tool:claude-code", "type": "agent",
  "description": "Claude Code by Anthropic", "zone": "zone:local",
  "componentRef": "ai-tool:claude-code",
  "responsibilities": ["Code generation", "Tool orchestration"] }
```

**Inline** (stands alone with its own `type` + `name`):

```json
{ "bom-ref": "asset:host:bertie", "type": "system", "name": "bertie",
  "description": "The scanned developer machine (Gentoo Linux 2.18)", "zone": "zone:local" }
```

> **Gotcha we hit:** the asset schema is a `oneOf` — an asset is *either* component-backed
> (`componentRef`, no `type`/`name`) *or* inline (`type` + `name`, no `componentRef`).
> Carry both and it's "valid under more than one schema" → rejected. So component-backed
> assets omit `name`.

Assets can also carry **`interfaces`** — how you reach them. An MCP server over HTTP:

```json
{ "bom-ref": "asset:mcp:analytics", "type": "tool", "zone": "zone:remote",
  "interfaces": [ { "name": "analytics-interface", "type": "api", "protocol": "mcp", "dataFormat": "JSON-RPC" } ] }
```

Interface `type` is from an enum: MCP `stdio` → `cli`, `sse` → `stream`, `http` → `api`.

### 4b. `behaviors` — what assets *do*

```json
"behaviors": { "instances": [
  { "bom-ref": "behavior:0", "behavior": "file", "acknowledgment": ["declared"], "actors": ["asset:skill:claude-code:deploy"] }
] }
```

- **`behavior`** must be a value from a **closed 740-value taxonomy** (`file`,
  `ai:agent:invokesTool`, `application:codeExecution:executesNativeCommand`, …). You can't
  invent one — that's the point, it's a shared vocabulary. Human-readable specifics live on
  the related asset (which *can* take free-form properties); the behavior itself is a code.
- **`acknowledgment`** — `declared` (we inferred it from config) vs `observed` (we saw it
  live, e.g. via `--probe-mcp`). This is how static analysis and runtime evidence combine.
- **`actors`** = who does it; **`targets`** = what it acts on. Both are asset `bom-ref`s.

### 4c. `zones` + `boundaries` — the trust model

```json
"zones": [
  { "bom-ref": "zone:local",  "name": "Local Machine",   "type": "trust", … },
  { "bom-ref": "zone:remote", "name": "Remote Services", "type": "trust", … }
],
"boundaries": [ { "bom-ref": "boundary:local-remote", "type": "trust", "zones": ["zone:local", "zone:remote"] } ]
```

Every asset names its `zone`. The **boundary** is the edge between two zones — the place
where trust changes and where a crossing flow deserves scrutiny.

### 4d. `flows` — how assets connect

```json
{ "bom-ref": "flow:claude-code->analytics", "name": "Claude Code → analytics",
  "type": "control", "source": "asset:ai-tool:claude-code", "destination": "asset:mcp:analytics",
  "description": "MCP tool invocation via http transport" }
```

- **`type`** `control` (commands/invocations) vs `data` (information moving).
- **`encrypted`** — a flow to a remote MCP server over `http://` carries `encrypted: false`,
  which is how a plaintext hop becomes visible *in the model* (a local stdio pipe omits the
  field — transport encryption doesn't apply):

  ```json
  { "name": "Claude Code → analytics", "type": "control",
    "source": "asset:ai-tool:claude-code", "destination": "asset:mcp:analytics",
    "encrypted": false, "description": "MCP tool invocation via http transport" }
  ```
- `source`/`destination` are asset `bom-ref`s. **Invariant we enforce in tests:** every
  flow, behavior, threat, risk, and control reference must resolve to an emitted asset —
  no dangling links.

---

## 5. The risk layer (top-level)

This is what turns an inventory into a *security* document. It reuses the exact analysis
the terminal and HTML reports lead with — so a detection is defined once and shows up in
all three outputs.

### 5a. `threats` — each finding, as a danger against assets

```json
"threats": {
  "threats": [
    { "bom-ref": "threat:0",
      "name": "Known-bad npm package: mcp-remote 0.1.10",
      "description": "critical severity · Exposure · at …/.mcp.json",
      "affectedAssets": ["asset:mcp:proxy"],
      "relatedVulnerabilities": ["vuln:cve-2025-6514"],
      "attackPatterns": ["attack:capec-437"] }
  ],
  "attackPatterns": [
    { "bom-ref": "attack:capec-437", "capecId": 437, "name": "Supply Chain",
      "description": "Compromise introduced through a dependency the victim trusts." }
  ]
}
```

`threats` is an **object** (`{ threats, attackPatterns }`), not a bare array. Each rmguard
finding becomes one threat:

- **`affectedAssets`** points at the **specific asset it concerns** — a plaintext-transport
  threat links to that MCP server (`asset:mcp:…`), a rules-file finding to `asset:rules:…`,
  a hostile-gateway finding to `asset:gateway:…`; findings without a precise target fall back
  to the machine `system` asset.
- **`relatedVulnerabilities`** references top-level `vulnerabilities[]` entries — CVEs parsed
  from the threat-catalog advisory (e.g. `CVE-2025-6514`), and the EAA-007 gateway CVE.
- **`attackPatterns`** references **CAPEC** (MITRE's Common Attack Pattern Enumeration &
  Classification) entries carried in `threats.attackPatterns[]`, each with the native
  integer **`capecId`**. The mapping is category-based and deliberately
  conservative (e.g. plaintext transport → CAPEC-157 *Sniffing*, hostile gateway → CAPEC-94
  *Adversary in the Middle*, known-bad package → CAPEC-437 *Supply Chain*); categories with
  no clean CAPEC get none rather than a forced fit.

The CVEs themselves live in a **top-level `vulnerabilities[]`** array:

```json
"vulnerabilities": [
  { "bom-ref": "vuln:cve-2025-6514", "id": "CVE-2025-6514",
    "description": "CVE-2025-6514 (CVSS 9.6): OS command injection via crafted OAuth URL." }
]
```

### 5b. `risks` — a scored, composite judgment

```json
"risks": { "risks": [ {
  "bom-ref": "risk:toxic-flow", "name": "Toxic flow (lethal trifecta)",
  "statement": "The connected agent surface combines a sensitive-data source (filesystem) with an exfiltration sink (network) …",
  "affects": ["asset:host:bertie"],
  "inherentRisk": { "likelihood": { "level": "high" }, "impact": { "level": "major" } },
  "responses": [ { "bom-ref": "response:toxic-flow", "strategy": "reduce",
                   "description": "Separate the source and sink …", "priority": "high" } ],
  "status": "identified"
} ] }
```

Where a threat is "this thing is dangerous," a **risk** is the *judgment*: a
**`likelihood` × `impact`** rating plus a **`response`** (strategy from a fixed set:
`avoid`/`reduce`/`transfer`/`accept`/…). The toxic-flow "lethal trifecta" — a sensitive
source and an exfiltration sink on the same agent — is exactly the composition that
belongs here rather than as a plain finding: no single MCP client sees it.

### 5c. `controls` — mitigations, mapped to coverage

```json
"controls": [ {
  "bom-ref": "control:audit-servers", "name": "AUDIT-SERVERS — Audit MCP servers for malicious behavior",
  "description": "Threat-catalog matching + tool/parameter poisoning + rug-pull detection …",
  "status": "in-progress", "appliesTo": ["asset:host:bertie"],
  "effectiveness": { "rating": "marginal" }
} ]
```

rmguard's compliance mapping (NSA/CISA, OWASP, EAA, …) becomes native `control` objects:
a **`status`** (`implemented` for a Covered control, `in-progress` for Partial) and an
**`effectiveness`** rating. We emit only the controls this machine's findings actually
exercise, so the section reflects real posture rather than the full catalog on every scan.

---

## 6. How we know it's valid

The Blueprint is validated in CI (`tests/blueprint_schema.rs`) against the **vendored
CycloneDX 2.0 draft schema** using the `jsonschema` crate. Two guards back it:

1. **Schema conformance** — drift in the generator (or a re-vendored schema) fails the build.
2. **No dangling refs** — a property test asserts every behavior/flow/threat/risk/control
   reference resolves to an emitted asset.

Because 2.0 is a **draft** (milestone 2026-08-31), the schema is pinned; on each bump we
re-vendor the fixtures and re-run the gate, so a shape change surfaces loudly instead of
producing silently-wrong output.

## 7. What's next

- **`observed` acknowledgments** — as `--probe-mcp` coverage grows, promote inferred
  behaviors from `declared` to `observed`.
- **CVSS ratings on vulnerabilities** — the advisory text carries the score; surface it as
  a structured `ratings` entry rather than only in the description.
- **Track the draft to 2.0 final (2026-08-31)** — re-vendor the schema and re-run the
  conformance gate on each bump; this walkthrough tracks the shape.

See [AGENT-SBOM-PROPOSAL.md](AGENT-SBOM-PROPOSAL.md) for the strategic framing (why
Blueprints, not more CycloneDX 1.6).
