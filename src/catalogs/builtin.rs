/// Built-in threat catalog of known-malicious and known-vulnerable MCP packages,
/// IDE extensions, and agent skills.
///
/// Sources are credited per-entry in the advisory field, and comprehensively
/// in docs/THREAT-CATALOG.md. This catalog is compiled from public security
/// advisories, CVE databases, and researcher disclosures.
///
/// Researchers and organizations whose work informs this catalog:
///   Snyk, JFrog Security Research, Socket.dev, Invariant Labs, Oligo Security,
///   Cymulate, Koi Security, Datadog Security Labs, Kaspersky GERT, Wiz,
///   Endor Labs, Cloud Security Alliance, Trail of Bits, Cisco, OWASP,
///   Check Point, Cato Networks, ReverseC Labs, Anthropic Security.

pub const BUILTIN_CATALOG: &str = include_str!("builtin_catalog.json");
