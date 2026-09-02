# Built-in Threat Catalog

rustmachineguard ships a built-in catalog of known-malicious and known-vulnerable packages
that is automatically checked during every scan. The catalog currently contains 99 entries
covering malicious npm/PyPI packages, CVEs in MCP infrastructure, compromised VS Code
extensions, malicious browser extensions, and — in the `agent-runtime` ecosystem — CVEs
in the agent CLIs themselves (Claude Code, Copilot CLI, Gemini CLI), matched against the
installed tool's own `--version`.

### A note on legitimate-but-compromised packages

Some entries pin a **specific version** (e.g. `litellm@1.82.7`, `durabletask@1.4.1-1.4.3`,
`telnyx@4.87.1`). These are otherwise-legitimate, widely-used packages that were briefly
compromised via a stolen publisher token or supply-chain attack. We match the exact
affected versions so we do **not** false-positive on the clean releases.

For "vulnerable below version X" cases — legitimate, ubiquitous packages with a CVE fixed
in a known release — entries carry a **`version_range`** (semver) instead: e.g.
`@modelcontextprotocol/server-filesystem` (`<2025.7.1`, the EscapeRoute CVEs),
`mcp-remote` (`>=0.0.5, <0.1.16`), `@modelcontextprotocol/inspector` (`<0.14.1`), the MCP
Python SDK `mcp` (`<1.23.0`) and TypeScript SDK `@modelcontextprotocol/sdk` (`<1.26.0`),
`mcp-server-git` (`<2025.9.25`), and `@cyanheads/git-mcp-server` (`<2.1.5`). A
patched install isn't flagged — and because a range treats an *unknown* version as a
conservative non-match, an unpinned `npx -y …` (which fetches the latest, patched release)
isn't flagged either, while a pinned vulnerable version still is.

A test (`cve_citing_catalog_entries_must_be_version_bounded`) enforces the rule that any
entry citing a CVE must carry a version bound — an unbounded CVE entry flags every
install, including patched ones.

Use `--no-builtin-catalog` to disable it, or `--threat-catalog <file>` to add your own
entries (merged with the built-in catalog by default).

## How It Works

The catalog is compiled into the binary at build time from
`src/catalogs/builtin_catalog.json`. Each entry specifies an ecosystem, package name,
optional version constraint, and an advisory string citing the source.

During scanning, every discovered MCP server, IDE extension, and browser extension is
checked against the catalog. Matches appear as exposure findings in all output formats.

## Sources and Attribution

This catalog is compiled from public security advisories, CVE databases, and researcher
disclosures. We credit the organizations and individuals whose work makes this possible:

### Security Research Organizations

| Organization | Contribution | License/Terms |
|---|---|---|
| **JFrog Security Research** | Discovered mcp-runcmd-server reverse shell campaign (XRAY-734538/39/40), CVE-2025-6514 in mcp-remote | Public advisories |
| **Socket.dev** | Discovered SANDWORM_MODE npm typosquatting campaign (19 packages targeting AI toolchains) | Public blog post |
| **Snyk** | First public disclosure of postmark-mcp malicious package | Public advisory |
| **ReversingLabs** | Extended postmark-mcp analysis and timeline | Public blog post |
| **Oligo Security** | Discovered CVE-2025-49596 in MCP Inspector | Public advisory, GHSA-7f8r-222p-6f5g |
| **Cymulate** | Discovered CVE-2025-53109 + CVE-2025-53110 (EscapeRoute) in MCP filesystem server | Public advisory |
| **Koi Security** | Discovered ClawHavoc campaign (341+ malicious skills) and MaliciousCorgi VS Code extensions | Public blog posts |
| **Datadog Security Labs** | Discovered Clawsights malicious Claude Code skill | Public blog post |
| **Kaspersky GERT** | Published devtools-assistant PoC demonstrating MCP credential harvesting | Public advisory (Securelist) |
| **Invariant Labs** | Coined "Tool Poisoning Attacks", disclosed github-mcp-server prompt injection | Public blog posts |
| **Trail of Bits** | Identified Line Jumping, Conversation History Theft, ANSI Terminal Deception attacks | Public blog post |
| **Endor Labs** | Analyzed 2,614 MCP servers: 82% prone to path traversal, 67% code injection | Public blog post |
| **Cloud Security Alliance** | "MCP Security Crisis" report (May 2026) with aggregate statistics | Public research note |
| **Wiz** | Discovered 550+ leaked secrets across 500+ VS Code extensions | Public blog post |
| **Cyata** | Discovered CVE-2025-68143/68144/68145 triple chain in mcp-server-git | Public advisories |
| **Check Point** | Discovered CVE-2025-54136 (MCPoison) in Cursor IDE | Public advisory |
| **Aikido** | Detailed Nx Console supply chain compromise analysis | Public blog post |
| **ExtensionTotal** | MaliciousCorgi campaign analysis, VS Code extension security research | Public blog posts |
| **Cyberhaven** | Disclosure of compromised Cyberhaven Chrome extension incident (2024-12) | Public disclosure |
| **Guardio Labs** | Discovered trojanized ChatGPT browser extensions stealing session cookies | Public blog posts |
| **Sekoia.io TDR** | Enumerated the December 2024 Chrome extension supply-chain campaign, including the compromised Cyberhaven extension ID | Public blog posts |
| **eSentire TRU** | Independent confirmation of the compromised Cyberhaven extension ID and affected versions | Public security advisories |
| **JetBrains Marketplace team** | Identified and removed 15 malicious AI-themed plugins (2026-06) and published their IDs | Public security update |
| **StepSecurity** | Independent analysis of the 15 malicious JetBrains plugins: vendors, install counts, exfiltration endpoint | Public blog posts |
| **SafeDep** | Discovered the `durabletask` PyPI hijack (Microsoft SDK, multi-cloud cred stealer) | Public blog post |
| **StepSecurity** | Discovered the `easy-day-js` typosquat across 140+ @mastra AI-framework packages | Public blog post |
| **Datadog Security Labs** | Discovered the TeamPCP `litellm`/`telnyx` PyPI compromises | Public blog post |
| **Tenable** | Mini Shai-Hulud worm (CVE-2026-45321) analysis and FAQ | Public blog post |
| **OX Security** | SANDWORM_MODE 19-package re-analysis; AI-chat Chrome extension stealers | Public blog posts |
| **OSV.dev / PyPA Advisory DB** | MAL-/PYSEC records for the 2026 MCP-named PyPI typosquat wave (`openai-mcp`, `langchain-core-mcp`, `instructor-mcp`, `tiktoken-mcp`, `ray-mcp-server`) | OSV (CC-BY-4.0) |
| **GitHub Advisory Database** | GHSA records for `@mcpjam/inspector` (CVE-2026-23744), `@cyanheads/git-mcp-server` (CVE-2025-53107) | GHSA (CC-BY-4.0) |

### Individual Researchers

| Researcher | Contribution |
|---|---|
| **Or Peles** (JFrog) | CVE-2025-6514 (mcp-remote command injection) |
| **Oren Yomtov** (Koi Security) | ClawHavoc campaign discovery |
| **RyotaK** | Claude Code GitHub Action bot trust bypass |
| **Inga Cherny** (Cato CTRL) | GIF Creator skill weaponization PoC |

### Databases and Trackers

| Resource | URL | Use |
|---|---|---|
| **vulnerablemcp.info** | https://vulnerablemcp.info/ | Comprehensive MCP vulnerability database (50+ CVEs) |
| **OWASP MCP Top 10** | https://owasp.org/www-project-mcp-top-10/ | Risk taxonomy |
| **NVD** | https://nvd.nist.gov/ | CVE details and CVSS scores |
| **GitHub Advisory Database** | https://github.com/advisories | GHSA identifiers |
| **Endpoint AI Agent Abuse (EAA)** | https://github.com/0x4D31/endpoint-ai-agent-abuse | Technique taxonomy (EAA-001…016) for local-agent abuse; informs our detection coverage mapping. Licensed CC0-1.0 (0x4D31). Inspired the EAA-007 hostile-gateway-routing, EAA-005 agent-transcript-collection, and EAA-009 remote-plugin-marketplace detections. |

### Academic Papers

| Paper | ID | Relevance |
|---|---|---|
| SkillFortify | arXiv:2603.00195 | 8-resource capability taxonomy, trust score algebra |
| MCPTox | arXiv:2508.14925 | 72.8% attack success rate across 45 MCP servers |
| MCP-ITP | arXiv:2601.07395 | Implicit tool poisoning, 84.2% ASR |
| ETDI | arXiv:2506.01333 | Tool squatting and rug pull attack models |
| MCP-38 | arXiv:2603.18063 | 38 threat categories mapped to STRIDE/OWASP |

## Updating the Catalog

To add entries, edit `src/catalogs/builtin_catalog.json`. Each entry is:

```json
{
  "ecosystem": "npm",
  "name": "package-name",
  "version": "1.0.0",
  "advisory": "Short description with source attribution"
}
```

- Omit both `version` and `version_range` to match all versions — **only** for fully
  malicious packages, where every release is bad
- Include `version` for exact matching (a single compromised release, e.g. Nx Console
  `18.95.0`)
- Include `version_range` (semver, e.g. `<1.23.0` or `>=0.0.5, <0.1.16`) for a
  legitimate package with a CVE fixed in a known release
- **Any entry citing a CVE must carry a bound** — an unbounded CVE entry flags every
  install including patched ones. This is enforced by a test
- Always include the source in the advisory string

To contribute additional entries, please open a PR with:
1. The JSON entry in `builtin_catalog.json`
2. A link to the public advisory or CVE in the PR description
3. A test in `tests/property_tests.rs` verifying the match

## License

The catalog data (advisory descriptions, CVE identifiers, package names) is compiled from
publicly available security advisories. CVE identifiers are public domain. Advisory
descriptions are original text summarizing public disclosures. The catalog itself is
distributed under Apache 2.0 as part of rustmachineguard.
