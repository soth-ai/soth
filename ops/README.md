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

## Next phases (not in this PR)

- **Phase 2 — classify bundle.** `make release-classify ENV=…`. Builds
  `dist/classify-v<auto>.tar.gz` from `~/labterminal/soth/data/classify/`,
  POSTs to `$(ADMIN_API)/v1/admin/classify/upload?version=…`. Replaces today's
  Railway-shell-and-curl flow.
- **Phase 3 — tool catalog.** `make release-catalog ENV=…`. Imports
  `raw_bundle.json` + parsers from `~/labterminal/soth/data/`, calls
  `compile`, then `publish` against the admin API.
- **Phase 4 — `make status` / `make diff`.** Drift detection across envs.
- **Phase 5 — GHA wrapper.** One workflow per artifact-env combo, calling
  the same `make` targets so CI and the laptop use the same code path.
