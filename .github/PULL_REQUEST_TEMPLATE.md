<!--
Thanks for sending a PR! Please fill out the sections below.
Small typo fixes can drop everything except a one-line description.
-->

## What & why

<!-- What does this change do, and why is it needed? Link any related issue with `Fixes #N` or `Refs #N`. -->

## How

<!-- One paragraph on the approach. Mention any tradeoffs or alternatives you considered. -->

## Testing

<!-- How did you verify this works? `cargo test`, manual reproduction, new tests added, etc. -->

- [ ] `make test` passes locally
- [ ] Added or updated tests covering the change
- [ ] Updated documentation if behavior or public API changed

## Checklist

- [ ] Commits are signed off (`git commit -s`) per [DCO](../CONTRIBUTING.md#sign-your-work-dco)
- [ ] No `unwrap()`/`expect()` on user-controlled input
- [ ] `cargo fmt` and `cargo clippy -- -D warnings` clean
- [ ] No `println!`/`eprintln!` left in library code (use `tracing`)
