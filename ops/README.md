# SOTH ops

Local-driven release flows for the artifacts that don't ride on the backend
service CI: CLI binaries (Phase 1, this PR), classify bundle (Phase 2 — TBD),
and tool catalog (Phase 3 — TBD). All driven by the top-level `Makefile`.

## Quick start

```bash
cp ops/.env.example ops/.env.staging   # or ops/.env.prod
$EDITOR ops/.env.staging                # populate from your secret store
make help                               # see all targets
make release-cli ENV=staging            # build + publish + verify
```

## Why this exists

Until now, releasing a CLI binary meant: hand-running `cargo build` for five
targets in a row, copy-pasting `wrangler r2 object put` for prod, and
`scp + ssh sudo mc cp` for staging — three different mechanisms, no sha
verification, no cache-bust verification, easy to skip a target. The Makefile
collapses all that into `make release-cli ENV=…` with the same shape per env.

## Three envs

| Env | CLI binary destination | Tool used |
|---|---|---|
| `local` | `./dist/` only | none |
| `staging` | MinIO bucket `release` at `storage.staging.soth.xyz` | `aws s3 cp --endpoint-url …` |
| `prod` | Cloudflare R2 bucket `storage` prefix `release/` | `wrangler r2 object put --remote` |

## Env vars (per-env file)

`ops/.env.<env>` is loaded by the Makefile at parse time. Shell env wins. CI
can ignore the file and pass everything as env directly. See
`ops/.env.example` for the contract.

## Phase 2 — classify bundle

```bash
make release-classify ENV=staging                          # auto VERSION
make release-classify ENV=prod VERSION=v1-2026-04-29-hotfix
```

Source: `~/labterminal/soth/data/classify/` (manifest.json + 5 model
files). The build step packs the directory into a gzip-compressed tar
at `dist/classify-$VERSION.tar.gz` — exactly the format the admin upload
handler expects (`crates/soth-api/src/handlers/bundles.rs:72`). Publish
POSTs the tarball to `$ADMIN_API/v1/admin/classify/upload?version=…`
with `Authorization: Bearer $PLATFORM_ADMIN_TOKEN`. Verification matches
the sha256 in the upload response against the local sha — server stores
bytes as-is, so a match proves what we sent landed intact.

`VERSION` defaults to `v1-$(date +%Y-%m-%d)`. Override on the command
line for hotfixes or to force a re-publish under a new label.

## Phase 3 — tool catalog

```bash
# refresh server source-of-truth (staging only — prod requires soth-cloud commit)
make import-catalog ENV=staging

# compile from current admin DB state, capture compilation_id
make compile-catalog ENV=staging

# publish the captured compilation as live
make publish-catalog ENV=staging

# composite: compile + publish
make release-catalog ENV=staging
make release-catalog ENV=prod
```

Three sub-verbs because each has different cross-env behavior:

- **`import-catalog`** — refreshes the server's `raw_bundle.json`
  source-of-truth (read by `POST /admin/registry/import/current` from
  a server-side path, NOT request body). On staging, this scp's
  `~/labterminal/soth/data/raw_bundle.json` → `/opt/soth/soth-cloud/data/runtime/local-bundle/registry/raw_bundle.json`
  via the ubuntu user, then `sudo -u soth cp` into the deploy tree, then
  POSTs `/import/current`. **On prod, this is not directly supported**:
  Railway containers don't expose a writable filesystem from outside, so
  the file must be committed to the soth-cloud repo and shipped via CI.
  `make import-catalog ENV=prod` prints the soth-cloud commit
  instructions and aborts.
- **`compile-catalog`** — POSTs `/admin/registry/compile` with a
  `version` (auto-defaulted) and `notes` (timestamp). Captures
  `compilation_id` to `dist/catalog-compilation-id.<env>.txt`.
- **`publish-catalog`** — POSTs
  `/admin/registry/compilations/{id}/publish` with `bundle_type=cloud`
  using the saved `compilation_id`.

`release-catalog` is the composite of compile + publish (import is
separate because it has very different mechanics across envs and
shouldn't run unprompted).

Parsers (the second half of the registry seed —
`SOTH_Complete_Governance_Dataset.json`) are out of scope for this
phase: the file's top-level shape is `{metadata, tools}` but the
admin endpoint expects `{parsers: {...}}`. The mapping needs its own
exploration.

## Next phases

- **Phase 4 — `make status` / `make diff` cross-env.** Drift detection
  across envs.
- **Phase 5 — GHA wrappers.** One workflow per artifact-env combo,
  calling the same `make` targets so CI and the laptop use the same
  code path.
