# Contributing to Soth

Thanks for your interest in Soth. We welcome bug reports, fixes, and
improvements from the community.

## Ways to contribute

- **Report bugs** — open a [GitHub issue](https://github.com/soth-ai/soth/issues)
  with steps to reproduce, expected vs actual behavior, your OS, and `soth --version`.
- **Propose features** — file an issue first so we can align on direction
  before you spend time on a PR.
- **Send patches** — small fixes can go straight to a PR; for anything that
  touches public APIs or the proxy/classify/policy core, please discuss first.

## Development setup

You need:

- **Rust 1.75+** with `cargo`. Install via [rustup](https://rustup.rs/).
- **Node.js 20+** (only if you build the Node.js bindings at `bindings/soth-node/`).
- **Python 3.11+** (only if you touch `bindings/soth-py/`).

Clone and build:

```bash
git clone https://github.com/soth-ai/soth
cd soth
cargo build --workspace
```

Run the full test suite:

```bash
make test                   # cargo test + fmt --check + clippy -D warnings
# or run the steps individually:
cargo test --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
```

## Submitting a PR

1. Fork the repo and create a topic branch off `staging`:
   `git checkout -b fix/<short-description>` or `feat/<short-description>`.
2. Make focused commits. We prefer
   [Conventional Commits](https://www.conventionalcommits.org/) — e.g.
   `fix(proxy): handle empty stream prelude`.
3. Add or update tests. New features need tests; bug fixes need a regression test.
4. Ensure `make test` passes locally.
5. Open the PR against `staging`. Describe the **why**, not just the what.

### Sign your work (DCO)

This project uses the [Developer Certificate of Origin](https://developercertificate.org/).
Every commit must be signed off with `git commit -s` (or
`git commit --signoff`). This appends a `Signed-off-by: Your Name <email>` line
that asserts you have the right to submit the change under the project's license.

We do **not** require a separate CLA — DCO is sufficient.

## Code style

- `cargo fmt` and `cargo clippy -- -D warnings` must pass.
- No `unwrap()` / `expect()` on user-controlled input; prefer `?` with
  `anyhow::Context` or proper `thiserror` variants.
- Use `tracing` for logs, never `println!`/`eprintln!` from library code.
- Public API additions need a doc comment.
- Keep changes scoped — refactors and feature work in separate PRs where possible.

## Adding source files

Soth is licensed under the Mozilla Public License 2.0. New source files
should include the standard MPL-2.0 header (Exhibit A):

```rust
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
```

Or for languages with single-line comments only, the equivalent.

## Reporting security issues

Please **do not** open a public issue for security vulnerabilities. See
[SECURITY.md](SECURITY.md) for the disclosure process.

## Code of Conduct

Participation in this project is governed by the
[Contributor Covenant](CODE_OF_CONDUCT.md). By contributing, you agree to
abide by its terms.
