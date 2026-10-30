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

/// The built-in catalog's version: the date (UTC, `YYYY-MM-DD`) of its last change, with
/// a `.N` suffix for a second change on the same day. A literal, so `--version` can
/// `concat!` it; use [`BUILTIN_CATALOG_VERSION`] everywhere else.
///
/// Bump it in the same commit as any edit to `builtin_catalog.json`: the
/// `catalog_version_is_bumped_with_the_catalog` test pins the file's hash to this
/// version and fails until both are updated.
#[macro_export]
macro_rules! builtin_catalog_version {
    () => {
        "2026-10-30"
    };
}

/// The built-in catalog's version (see [`builtin_catalog_version!`]). rmguard's own data,
/// compiled into the binary: reported in `--version`, the JSON report's `catalog` block,
/// and, under `--otel`, as `rmguard.catalog.version`, so a fleet can tell a catalog
/// update from a change on the machine.
pub const BUILTIN_CATALOG_VERSION: &str = builtin_catalog_version!();

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    /// The catalog file's sha256 at [`BUILTIN_CATALOG_VERSION`]. A catalog edit without a
    /// version bump fails here; update both together.
    const PINNED: (&str, &str) = (
        "2026-10-30",
        "e5b729c73580b1d3260205bed334bbaee5c237a5550a693a7539a882de044d41",
    );

    #[test]
    fn catalog_version_is_bumped_with_the_catalog() {
        let hash: String = Sha256::digest(BUILTIN_CATALOG.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(
            (BUILTIN_CATALOG_VERSION, hash.as_str()),
            PINNED,
            "builtin_catalog.json changed: set builtin_catalog_version!() to today's date \
             (YYYY-MM-DD, `.N` for a second change that day) and PINNED to (that, {hash})"
        );
    }

    /// docs/THREAT-CATALOG.md states the catalog's version and entry count in its intro
    /// ("The catalog (version `V`) currently contains N entries"). Both are pinned here to
    /// [`BUILTIN_CATALOG_VERSION`] and the built-in catalog's length, so a catalog bump
    /// without the doc update fails the tests. Whitespace is normalized, so the sentence
    /// may be reflowed across lines.
    #[test]
    fn catalog_doc_states_the_current_version_and_count() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/docs/THREAT-CATALOG.md");
        let doc = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{path}: {e}"));
        let text = doc.split_whitespace().collect::<Vec<_>>().join(" ");
        const LEAD: &str = "The catalog (version `";
        assert_eq!(
            text.matches(LEAD).count(),
            1,
            "{path}: the intro must state the version once, as {LEAD}V`) currently contains N entries"
        );
        let rest = &text[text.find(LEAD).unwrap() + LEAD.len()..];
        let (version, rest) = rest.split_once('`').expect("closing backtick");
        let count: String = rest
            .strip_prefix(") currently contains ")
            .unwrap_or_else(|| panic!("{path}: expected \") currently contains N entries\" after the version"))
            .chars()
            .take_while(char::is_ascii_digit)
            .collect();
        let entries = crate::scanners::exposure::ExposureCatalog::load_from_str(BUILTIN_CATALOG)
            .unwrap()
            .len();
        assert_eq!(
            (version, count.parse::<usize>().ok()),
            (BUILTIN_CATALOG_VERSION, Some(entries)),
            "{path}: update the intro to version `{BUILTIN_CATALOG_VERSION}` and {entries} entries"
        );
    }

    #[test]
    fn catalog_version_is_a_date() {
        let v = BUILTIN_CATALOG_VERSION;
        let (date, suffix) = v.split_once('.').map_or((v, None), |(d, s)| (d, Some(s)));
        assert!(
            chrono::NaiveDate::parse_from_str(date, "%Y-%m-%d").is_ok() && date.len() == 10,
            "{v}"
        );
        assert!(suffix.is_none_or(|s| s.parse::<u32>().is_ok_and(|n| n >= 2)), "{v}");
    }
}
