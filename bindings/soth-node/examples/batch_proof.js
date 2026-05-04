// Fire 20 cheap Anthropic calls concurrently through the Node SDK
// and watch the shipper's POST lines so we can count how many HTTP
// requests actually leave the box.
//
// Mirrors examples/batch_proof.py from soth-py — both bindings sit
// on the same Rust shipper in soth-sdk-core, so the wire format and
// batching cadence should be identical.

const Anthropic = require('@anthropic-ai/sdk');
const soth = require('..');

if (!process.env.SOTH_ORG_ID || !process.env.SOTH_API_KEY) {
  console.error('SOTH_ORG_ID and SOTH_API_KEY are required (find them in ~/.soth/soth.yaml)');
  process.exit(1);
}
const ORG_ID = process.env.SOTH_ORG_ID;
const SOTH_API_KEY = process.env.SOTH_API_KEY;
const TELEMETRY_ENDPOINT = process.env.SOTH_TELEMETRY_ENDPOINT
  || 'https://ingest.soth.ai/v1/edge/telemetry/batch';
const MODEL = 'claude-haiku-4-5-20251001';
const N_CALLS = 20;

async function main() {
  if (!process.env.ANTHROPIC_API_KEY) {
    console.error('ANTHROPIC_API_KEY not set');
    process.exit(1);
  }

  soth.init({
    apiKey: SOTH_API_KEY,
    orgId: ORG_ID,
    telemetryEndpoint: TELEMETRY_ENDPOINT,
  });
  const state = soth.instrument({ providers: ['anthropic'] });
  console.log('instrumentation:', state);

  const client = new Anthropic.default();

  const fire = async (i) => {
    const msg = await client.messages.create({
      model: MODEL,
      max_tokens: 8,
      messages: [{ role: 'user', content: `Reply with the number ${i}, nothing else.` }],
    });
    return msg.usage.output_tokens;
  };

  const t0 = Date.now();
  const outs = await Promise.all(Array.from({ length: N_CALLS }, (_, i) => fire(i)));
  const dt = (Date.now() - t0) / 1000;
  console.log(`\n>>> fired ${N_CALLS} calls in ${dt.toFixed(2)}s, total output tokens: ${outs.reduce((a, b) => a + b, 0)}`);
  console.log('>>> sleeping 12s to let shipper drain (BATCH_WINDOW=5s)…');
  await new Promise((r) => setTimeout(r, 12_000));
  soth.shutdown();
  console.log('>>> shutdown complete (forces final-drain POST)');
}

main().catch((e) => { console.error(e); process.exit(1); });
