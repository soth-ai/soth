//! End-to-end smoke test for the `SothSdk` facade.
//!
//! Asserts the lifecycle the spec commits to:
//! - `init` succeeds with minimal config.
//! - `pre_call` returns a real `Decision` with a non-sentinel
//!   `DecisionToken` for clean inputs.
//! - `pre_call` returns `Decision::Block` for inputs containing a
//!   credential artifact (sync block path).
//! - `post_call` consumes the token; in-flight count returns to zero.
//! - Telemetry events are emitted onto the in-memory queue.
//! - Streaming round-trip: `stream_begin` / `stream_chunk` /
//!   `stream_end` consumes the token exactly once.

use soth_sdk_core::{
    BlockReason, Decision, HmacKey, LlmCall, LlmChunk, LlmResponse, Message, SdkConfigBuilder,
    SothSdk,
};
use soth_core::EndpointType;
use zeroize::Zeroizing;

fn minimal_sdk() -> SothSdk {
    let config = SdkConfigBuilder::new()
        .api_key("sk-test")
        .org_id("org-test")
        .hmac_key(HmacKey::Static(Zeroizing::new(vec![0x42; 32])))
        .build()
        .expect("build config");
    SothSdk::init(config).expect("init sdk")
}

fn clean_call() -> LlmCall {
    LlmCall {
        provider: "openai".into(),
        model: "gpt-4o-mini".into(),
        messages: vec![Message {
            role: "user".into(),
            content: "Explain Rust ownership in two sentences.".into(),
        }],
        system: None,
        tools: Vec::new(),
        stream: false,
        temperature: None,
        top_p: None,
        max_tokens: None,
        stop_sequences: Vec::new(),
        endpoint_type: EndpointType::ChatCompletion,
    }
}

fn credential_call() -> LlmCall {
    LlmCall {
        provider: "openai".into(),
        model: "gpt-4o-mini".into(),
        messages: vec![Message {
            role: "user".into(),
            content: "review this key sk-abcdefghijklmnopqrstuvwxyzABCD1234567890 for me"
                .into(),
        }],
        system: None,
        tools: Vec::new(),
        stream: false,
        temperature: None,
        top_p: None,
        max_tokens: None,
        stop_sequences: Vec::new(),
        endpoint_type: EndpointType::ChatCompletion,
    }
}

#[test]
fn init_succeeds_with_minimal_config() {
    let sdk = minimal_sdk();
    assert_eq!(sdk.in_flight_decisions(), 0);
}

#[test]
fn pre_call_then_post_call_balances_slab_and_emits_telemetry() {
    let sdk = minimal_sdk();
    let call = clean_call();

    let decision = sdk.pre_call(&call);
    assert!(
        matches!(decision, Decision::Allow { .. }),
        "expected Allow, got {decision:?}"
    );
    assert_eq!(sdk.in_flight_decisions(), 1);

    let token = decision.token();
    let response = LlmResponse::new(EndpointType::ChatCompletion);
    sdk.post_call(token, &response);

    assert_eq!(sdk.in_flight_decisions(), 0);
    let events = sdk.drain_telemetry_for_test();
    assert_eq!(events.len(), 1, "expected exactly one telemetry event");
    assert_eq!(events[0].provider, "openai");
}

#[test]
fn pre_call_blocks_on_credential_in_user_message() {
    let sdk = minimal_sdk();
    let call = credential_call();

    let decision = sdk.pre_call(&call);
    match &decision {
        Decision::Block { reason, .. } => match reason {
            BlockReason::SensitiveArtifact { .. } => {}
            other => panic!("expected SensitiveArtifact reason, got {other:?}"),
        },
        other => panic!("expected Block, got {other:?}"),
    }

    // Still need to consume the token even on Block — bindings call
    // post_call regardless.
    let token = decision.token();
    sdk.post_call(token, &LlmResponse::new(EndpointType::ChatCompletion));
    assert_eq!(sdk.in_flight_decisions(), 0);
}

#[test]
fn streaming_round_trip_consumes_token_once() {
    let sdk = minimal_sdk();
    let call = clean_call();
    let (decision, mut obs) = sdk.stream_begin(&call);
    assert!(matches!(decision, Decision::Allow { .. }));
    assert_eq!(sdk.in_flight_decisions(), 1);

    for i in 0..3 {
        let mut chunk = LlmChunk::new(i);
        chunk.delta_content = Some(format!("chunk{i} "));
        sdk.stream_chunk(&mut obs, &chunk);
    }
    assert_eq!(sdk.in_flight_decisions(), 1);

    sdk.stream_end(obs);
    assert_eq!(sdk.in_flight_decisions(), 0);
    assert_eq!(sdk.drain_telemetry_for_test().len(), 1);
}

#[test]
fn many_pre_calls_without_post_call_do_not_leak_past_slab_capacity() {
    // Allocate a bunch without consuming. After enough allocations
    // the slab returns SLAB_FULL rather than crashing or leaking.
    let sdk = minimal_sdk();
    for _ in 0..6_000 {
        let _ = sdk.pre_call(&clean_call());
    }
    // Slab is at threshold; any subsequent decision is SLAB_FULL.
    let decision = sdk.pre_call(&clean_call());
    assert_eq!(
        decision.token(),
        soth_sdk_core::DecisionToken::SLAB_FULL,
        "slab pressure should yield SLAB_FULL token"
    );
    // post_call with SLAB_FULL is a documented no-op.
    sdk.post_call(decision.token(), &LlmResponse::new(EndpointType::ChatCompletion));
}
