# Vendored test fixtures

These JSON Schema files are **vendored from the OWASP CycloneDX specification** and
used only by `tests/blueprint_schema.rs` to validate our `--format blueprint` output.

| File | Source | License |
|------|--------|---------|
| `cyclonedx-2.0-bundled.schema.json` | [CycloneDX/specification](https://github.com/CycloneDX/specification) `schema/2.0/cyclonedx-2.0-bundled.schema.json` | Apache-2.0 |
| `behavior-taxonomy.schema.json` | [CycloneDX/specification](https://github.com/CycloneDX/specification) `schema/behavior-taxonomy.schema.json` | Apache-2.0 |

**Pinned to:** branch `2.0-dev-threatmodeling`, commit `03a8eaa78147` (fetched 2026-06-30).

CycloneDX 2.0 is a draft (milestone due 2026-08-31) and the schema is still changing.
When bumping the pin, re-fetch both files from the same commit and re-run
`cargo test --test blueprint_schema`; update `src/output/blueprint.rs` if the gate fails.

Copyright belongs to the OWASP Foundation and the CycloneDX contributors. We include
these files unmodified under the terms of the Apache License 2.0 solely to validate
interoperability. See the upstream `LICENSE` for full terms.
