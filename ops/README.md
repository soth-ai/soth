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

## Next phases

- **Phase 3 — tool catalog.** `make release-catalog ENV=…`. Imports
  `raw_bundle.json` + parsers from `~/labterminal/soth/data/`, calls
  `compile`, then `publish` against the admin API.
- **Phase 4 — `make status` / `make diff`.** Drift detection across envs.
- **Phase 5 — GHA wrapper.** One workflow per artifact-env combo, calling
  the same `make` targets so CI and the laptop use the same code path.
