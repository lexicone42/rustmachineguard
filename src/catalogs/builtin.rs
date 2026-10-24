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
///   Check Point, Cato Networks, ReverseC Labs, Anthropic Security,
///   Guardio Labs, Sekoia.io TDR, eSentire TRU, JetBrains Marketplace team, StepSecurity,
///   LayerX Security / Akamai, Air Security, Manifold Security, Pluto Research,
///   Yeeth Security, Aikido Security, SafeDep, Elastic Security Labs, CloudSEK,
///   codelake Research, Pillar Security, Cycode, Compass Security, Redguard AG,
///   Cyera Research, NVIDIA AI Red Team, HiddenLayer SAI, Checkmarx Zero, pkgwarden,
///   Upwind Security, Wiz Research, OX Security, Amazon Inspector, OpenSSF
///   malicious-packages (Kamil Mańkowski / kam193), the Eclipse Foundation Open VSX and
///   Microsoft VS Marketplace registry teams, and the vendor security teams at
///   Anthropic, OpenAI, Google, Block, Ollama, Anomaly, PrefectHQ and the MCP project.
pub const BUILTIN_CATALOG: &str = include_str!("builtin_catalog.json");
