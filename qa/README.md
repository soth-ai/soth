# Corpus Suite (Workspace Level)

This `qa/` folder hosts a reusable corpus suite that runs outside production crates.

Goals:
- Reuse corpus execution across targets (`proxy_e2e`, `classify`, `policy`)
- Keep orchestration out of crate source trees
- Support profile-based runs (`smoke`, `standard`, `full`)

## Runner

Use:

```bash
python3 qa/corpus_suite.py --profile smoke
python3 qa/corpus_suite.py --profile standard --target proxy_e2e
python3 qa/corpus_suite.py --profile full --output-json /tmp/soth-corpus-suite.json
```

List profiles:

```bash
python3 qa/corpus_suite.py --list
```

## Profiles

Profiles live under `qa/profiles/*.json` and declare steps with:
- `target`: logical bucket (`proxy_e2e`, `classify`, `policy`, `detect`)
- `cmd`: command argv list
- `env`: optional env vars
- `result_kind`: parser type (`proxy_ndjson`, `cargo_test`)

## Reusable Corpus Contract

Shared schema and seed cases are staged under:
- `qa/corpus/schema/case.schema.json`
- `qa/corpus/cases/*.jsonl`

Current proxy E2E uses `scripts/gating_trace_corpus.py` as the live adapter.
Next phase is wiring `classify` and `policy` adapters to load shared case files directly.
