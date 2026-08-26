# Vendored test fixtures

These JSON Schema files are **vendored from the OWASP CycloneDX specification** and
used only by `tests/blueprint_schema.rs` to validate our `--format blueprint` output.

| File | Source | License |
|------|--------|---------|
| `cyclonedx-2.0-bundled.schema.json` | [CycloneDX/specification](https://github.com/CycloneDX/specification) `schema/2.0/cyclonedx-2.0-bundled.schema.json` | Apache-2.0 |
| `behavior-taxonomy.schema.json` | [CycloneDX/specification](https://github.com/CycloneDX/specification) `schema/behavior-taxonomy.schema.json` | Apache-2.0 |

**Pinned to:** branch `2.0-dev`, commit `72b37340404d` (fetched 2026-08-26).

> **Pin history / gotcha.** We originally pinned branch `2.0-dev-threatmodeling`
> (commit `03a8eaa78147`). That branch was merged into `2.0-dev` by upstream PR #678 on
> 2026-08-20 and then **deleted**, so the old refresh instructions 404'd. The commit is
> still reachable by SHA, but track `2.0-dev` from now on. The bundled schema also moved
> its per-module files into `schema/2.0/model/`, and `behavior-taxonomy.schema.json`
> lives at `schema/behavior-taxonomy.schema.json` (repo root `schema/`, not under `2.0/`).

CycloneDX 2.0 is still a draft and the schema is still changing. The 2.0 milestone was
due 2026-08-31 but has slipped — upstream now targets a fall 2026 release with Ecma
ratification expected in December, and a 2.1 milestone (due 2027-04-16) has appeared.

To bump the pin: re-fetch both files from the same commit on `2.0-dev` and re-run
`cargo test --test blueprint_schema`; update `src/output/blueprint.rs` if the gate fails.

```bash
B=https://raw.githubusercontent.com/CycloneDX/specification/2.0-dev
curl -sL -o tests/fixtures/cyclonedx-2.0-bundled.schema.json $B/schema/2.0/cyclonedx-2.0-bundled.schema.json
curl -sL -o tests/fixtures/behavior-taxonomy.schema.json    $B/schema/behavior-taxonomy.schema.json
cargo test --test blueprint_schema
```

Copyright belongs to the OWASP Foundation and the CycloneDX contributors. We include
these files unmodified under the terms of the Apache License 2.0 solely to validate
interoperability. See the upstream `LICENSE` for full terms.
