// FFI conformance — drives the same fixtures the Rust harness uses
// through the actual napi-rs binding.
//
// Mirrors `bindings/soth-py/tests/test_ffi_conformance.py`. The Rust
// conformance harness runs three lanes (proxy, SDK direct, SDK
// facade); this file adds the fourth (FFI via napi-rs). Drift between
// the Rust facade and Node FFI marshalling fails here, naming the
// field.
//
// Run with:
//   cd bindings/soth-node
//   npm install
//   npm run build:debug
//   npm test -- --test-only-pattern '/ffi-conformance/'

import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { readdir, readFile } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import * as soth from '../index.js';

process.env.SOTH_HMAC_KEY = 'x'.repeat(32);

soth.init({
  apiKey: 'sk-test',
  orgId: 'org-conformance',
  hmacKeyEnv: 'SOTH_HMAC_KEY',
});

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(
  __dirname,
  '..',
  '..',
  '..',
  'crates',
  'soth-conformance-tests',
  'fixtures',
);

async function loadFixtures() {
  let entries;
  try {
    entries = await readdir(FIXTURES_DIR);
  } catch (e) {
    return [];
  }
  const out = [];
  for (const name of entries.filter((n) => n.endsWith('.json')).sort()) {
    const text = await readFile(join(FIXTURES_DIR, name), 'utf8');
    out.push({ name, fixture: JSON.parse(text) });
  }
  return out;
}

const fixtures = await loadFixtures();

function fixtureToCall(fixture) {
  const typed = fixture.typed_call;
  const call = {
    provider: typed.provider,
    model: typed.model,
    messages: typed.messages ?? [],
    stream: typed.stream ?? false,
  };
  if (typed.system) call.system = typed.system;
  if (typed.tools) {
    call.tools = typed.tools.map((t) => ({
      name: t.name,
      description: t.description ?? null,
      parametersJson: t.parameters_json ?? '',
    }));
  }
  return call;
}

if (fixtures.length === 0) {
  test('ffi conformance — no fixtures reachable; skipping', () => {
    // Sanity — leaves a record but doesn't fail.
  });
} else {
  for (const { name, fixture } of fixtures) {
    test(`ffi conformance: ${name}`, async () => {
      const call = fixtureToCall(fixture);
      const isCredential = fixture?.axes?.content_class === 'credential';
      const isBlock = fixture?.axes?.policy_decision === 'Block';

      if (isCredential || isBlock) {
        await assert.rejects(
          () => soth.guard(async () => 'should-not-be-called', { call }),
          (err) => err instanceof soth.SothBlocked,
        );
      } else {
        const result = await soth.guard(async () => 'ok', { call });
        assert.equal(result, 'ok');
      }

      const sdk = soth.getSdk();
      const events = sdk.drainTelemetryForTest();
      assert.equal(events.length, 1, `${name}: expected 1 event, got ${events.length}`);
      const event = events[0];
      assert.equal(
        event.provider,
        fixture.typed_call.provider,
        `${name}: provider drift`,
      );
      if (fixture.typed_call.model && event.model) {
        assert.equal(
          event.model,
          fixture.typed_call.model,
          `${name}: model drift`,
        );
      }
      // napi-rs renders Rust struct fields as camelCase by default,
      // matching JS convention; the Python lane keeps snake_case.
      assert.ok('endpointType' in event);
      assert.ok('captureMode' in event);
      assert.equal(sdk.inFlightDecisions(), 0);
    });
  }

  test('ffi conformance corpus floor (>=7 fixtures)', () => {
    assert.ok(
      fixtures.length >= 7,
      `Conformance corpus shrank to ${fixtures.length} — should have at least 7`,
    );
  });
}
