# Release signing keys

This directory holds the **public** ed25519 keys used to verify release
manifests on client machines (`soth update --check` / `--apply`).

## Layout

| File | Status | Purpose |
|------|--------|---------|
| `stable.public.pem` | committed | verifies `manifest/stable.json.sig` |
| `canary.public.pem` | committed | verifies `manifest/canary.json.sig` and `manifest/staging.json.sig` |
| `*.private.pem` | **never committed** | signs manifests during `ops/release.sh` |

`.gitignore` in this directory blocks `*.private.pem` as a defensive
guard — but the source of truth is operator discipline.

## Where private keys live

- **Source of truth:** 1Password vault `soth-release-signing`, items
  `release-key-stable` and `release-key-canary`.
- **Operator machine (signing host only):** `~/.soth/keys/release/{stable,canary}.private.pem`,
  mode `0600`. Pulled from 1Password before `make release-cli`, deleted
  after if the host isn't a dedicated release box.

The signing path in `ops/release.sh` reads the private key from
`SOTH_RELEASE_KEY_PATH` (default `~/.soth/keys/release/<channel>.private.pem`).

## Rotating a key

1. Generate the new keypair offline (see "Generation" below).
2. Add the new public key alongside the old one in this directory:
   `stable.public.pem` and `stable.public.next.pem`.
3. Ship a release in which the verifier accepts either key (transition
   build).
4. After fleet adoption ≥95%, sign the next release with the new private
   key, swap `stable.public.next.pem` → `stable.public.pem`, delete the
   old `.next` file, retire the old private key in 1Password.

## Generation (one-time, already done for `0.1.1`)

```bash
mkdir -p ~/.soth/keys/release && chmod 700 ~/.soth/keys ~/.soth/keys/release
for ch in stable canary; do
  openssl genpkey -algorithm ED25519 -out ~/.soth/keys/release/${ch}.private.pem
  chmod 600 ~/.soth/keys/release/${ch}.private.pem
  openssl pkey -in ~/.soth/keys/release/${ch}.private.pem -pubout \
    -out ops/keys/${ch}.public.pem
done
```

Public-key fingerprints (SHA-256 of DER-encoded SubjectPublicKeyInfo)
are published in each release's notes so customers can independently
verify the bundled key matches.

## Threat model

- Key compromise of `stable.private.pem`: an attacker can sign a
  malicious manifest and serve it from a hijacked storage URL. Mitigation:
  manifest-fetch over TLS to a vendor-controlled domain; key rotation
  procedure above; `release_seq` anti-rollback. Detection: signature
  verification failures emit `update.signature.verification.failed`
  telemetry which alerts on-call.
- Key compromise of `canary.private.pem`: same blast radius, but only
  customers on the canary channel. Used as a softer rotation target.
- Loss of *private* key without compromise: rotate via the procedure
  above; published binaries remain verifiable until next release.
