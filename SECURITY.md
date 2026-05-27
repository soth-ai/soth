# Security Policy

## Supported versions

Soth is in active development. Security fixes are applied to the latest
released version on the `stable` channel. We do not backport fixes to older
releases at this stage.

| Version | Supported |
|---|---|
| Latest `stable` | Yes |
| Latest `canary` | Yes |
| Older releases  | No  |

## Reporting a vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Soth intercepts and inspects TLS traffic and operates a local MITM CA. A
disclosed-before-patched vulnerability could expose user credentials,
session tokens, or model API keys. We take this seriously.

Two ways to report privately:

1. **Preferred** — open a
   [GitHub Security Advisory](https://github.com/soth-ai/soth/security/advisories/new)
   in this repository. This creates a private discussion thread visible
   only to maintainers.
2. **Email** — `security@soth.ai`. Include a clear description, steps to
   reproduce, affected versions, and any proof-of-concept. PGP encryption
   is available on request.

## What to expect

- We will acknowledge your report within **2 business days**.
- We will provide a preliminary assessment within **7 days**, including
  whether we accept the issue and an expected timeline.
- We will keep you updated as we work on a fix.
- We will credit you in the advisory (unless you prefer to remain
  anonymous).

## Scope

In scope:

- The `soth` CLI and binaries it produces.
- All crates in this repository.
- The MITM CA generation and trust flow.
- The local ops/dashboard HTTP server.

Out of scope (please report to the relevant project):

- Vulnerabilities in upstream dependencies (rustls, tokio, etc.) — report
  to those projects; we will pick up the fix on their release.
- Misconfigurations of policies a user wrote themselves.
- Anything requiring physical access to the user's machine.

## Disclosure

We follow **coordinated disclosure**: we will work with the reporter to
ship a fix on the stable channel before any public details are released.
Once a fix is available, we will publish a GitHub Security Advisory with
CVE, affected versions, and credit.
