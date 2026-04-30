//! Decision slab — fixed-size storage for in-flight `DecisionToken`s.
//!
//! Each slot holds the partial state needed to enrich + emit telemetry
//! when `post_call` consumes the token. Lifecycle is locked by
//! `SDK_DECISION_API_SPEC.md` §5:
//!
//! - allocate on `pre_call` / `stream_begin`
//! - free on `post_call` / `stream_end`
//! - reuse → panic in debug, log+ignore in release
//! - never consumed → orphan sweeper frees + emits `decision_orphaned`
//! - slab full → return `DecisionToken::SLAB_FULL`, no allocation

use std::sync::Mutex;
use std::time::Instant;

use soth_core::{ArtifactKind, DetectResult};

use crate::decision::DecisionToken;

const SLAB_CAPACITY: usize = 4096;
/// 95% threshold from the spec — past this point new `pre_call`s get
/// `SLAB_FULL` rather than waiting for a free slot.
const SLAB_PRESSURE_THRESHOLD: usize = (SLAB_CAPACITY * 95) / 100;

/// Partial decision state stashed for the async enrichment phase.
/// Several fields are read by Phase-1 (orphan sweeper uses
/// `created_at`; org-rule eval uses `artifacts_summary`; cloud-classify
/// path uses `call_model` + `user_content`); v0 only consumes the
/// minimum to push a telemetry event.
pub(crate) struct DecisionContext {
    #[allow(dead_code)] // Phase-1: orphan sweeper inspects age
    pub created_at: Instant,
    pub generation: u64,
    pub detect: DetectResult,
    #[allow(dead_code)] // Phase-1: org-rule eval branches on artifact summary
    pub artifacts_summary: ArtifactsSummary,
    pub call_provider: String,
    #[allow(dead_code)] // Phase-1: cloud-classify path serializes the model field
    pub call_model: String,
    #[allow(dead_code)] // Phase-1: cloud-classify path serializes user_content
    pub user_content: Option<String>,
}

/// Pre-summarized artifact view so `post_call` doesn't re-walk the
/// `Vec<SensitiveArtifact>` for high-level decisions.
#[derive(Debug, Default, Clone)]
pub(crate) struct ArtifactsSummary {
    pub credential_count: u32,
    pub private_key_count: u32,
    pub code_block_count: u32,
    pub other_count: u32,
}

impl ArtifactsSummary {
    pub fn from_artifacts(arts: &[soth_core::SensitiveArtifact]) -> Self {
        let mut s = Self::default();
        for a in arts {
            match &a.kind {
                ArtifactKind::ApiKey { .. } => s.credential_count += 1,
                ArtifactKind::PrivateKey => s.private_key_count += 1,
                ArtifactKind::CodeBlock { .. } => s.code_block_count += 1,
                _ => s.other_count += 1,
            }
        }
        s
    }

    #[allow(dead_code)] // Phase-1 hook for org-rule evaluation
    pub fn has_credential(&self) -> bool {
        self.credential_count > 0 || self.private_key_count > 0
    }
}

pub(crate) struct DecisionSlab {
    slots: Mutex<Vec<Option<DecisionContext>>>,
    /// Free-list head; `None` when slab is full.
    free_head: Mutex<Vec<usize>>,
    /// Per-slot generation counter — flipped on every alloc/free so
    /// stale tokens (from a freed slot) are detectable.
    generations: Mutex<Vec<u64>>,
    next_generation: std::sync::atomic::AtomicU64,
    in_use: std::sync::atomic::AtomicUsize,
}

impl DecisionSlab {
    pub fn new() -> Self {
        let mut slots = Vec::with_capacity(SLAB_CAPACITY);
        let mut generations = Vec::with_capacity(SLAB_CAPACITY);
        let mut free = Vec::with_capacity(SLAB_CAPACITY);
        for i in (0..SLAB_CAPACITY).rev() {
            slots.push(None);
            generations.push(0);
            free.push(i);
        }
        // slots was filled tail-first; flip back.
        slots.reverse();
        generations.reverse();
        Self {
            slots: Mutex::new(slots),
            free_head: Mutex::new(free),
            generations: Mutex::new(generations),
            next_generation: std::sync::atomic::AtomicU64::new(1),
            in_use: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// Allocate a slot. Returns `DecisionToken::SLAB_FULL` if the slab
    /// is at the configured pressure threshold.
    pub fn allocate(&self, ctx: DecisionContext) -> DecisionToken {
        // Pressure check first — don't even take the lock when full.
        if self.in_use.load(std::sync::atomic::Ordering::Acquire) >= SLAB_PRESSURE_THRESHOLD {
            return DecisionToken::SLAB_FULL;
        }

        let mut free = match self.free_head.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let Some(idx) = free.pop() else {
            return DecisionToken::SLAB_FULL;
        };
        drop(free);

        let mut generations = match self.generations.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let new_gen = self
            .next_generation
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        generations[idx] = new_gen;
        drop(generations);

        let mut slots = match self.slots.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let mut ctx_with_gen = ctx;
        ctx_with_gen.generation = new_gen;
        slots[idx] = Some(ctx_with_gen);
        drop(slots);

        self.in_use
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);

        DecisionToken {
            inner: encode_token(idx as u32, new_gen),
        }
    }

    /// Consume a token and return its context. Returns `None` for:
    /// - sentinel tokens (SLAB_FULL, SENTINEL_FAIL_OPEN)
    /// - tokens whose slot has been freed (reuse case)
    /// - tokens with a stale generation
    ///
    /// In debug builds, reuse panics. In release, `None` + log.
    pub fn consume(&self, token: DecisionToken) -> Option<DecisionContext> {
        if token.is_sentinel() {
            return None;
        }
        let (idx, gen) = decode_token(token.inner);
        if (idx as usize) >= SLAB_CAPACITY {
            on_invalid_token("index out of range", token);
            return None;
        }

        let mut generations = match self.generations.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        if generations[idx as usize] != gen {
            on_invalid_token("stale generation (reuse?)", token);
            return None;
        }
        // Bump generation so this slot's token can never be re-consumed.
        generations[idx as usize] = self
            .next_generation
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        drop(generations);

        let mut slots = match self.slots.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let ctx = slots[idx as usize].take();
        drop(slots);

        if ctx.is_some() {
            let mut free = match self.free_head.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            free.push(idx as usize);
            drop(free);
            self.in_use
                .fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
        }
        ctx
    }

    /// Snapshot of in-flight token count. Used by the orphan sweeper
    /// (Phase 1) and by the smoke tests.
    pub fn in_flight(&self) -> usize {
        self.in_use.load(std::sync::atomic::Ordering::Acquire)
    }
}

/// Encode (slot_index, generation) into a single u64 token.
/// 32 bits for the index, 32 bits for the generation. Both fit
/// comfortably given SLAB_CAPACITY = 4096 and the generation counter
/// rolls every ~4 billion allocations.
fn encode_token(idx: u32, generation: u64) -> u64 {
    ((idx as u64) << 32) | (generation & 0xFFFF_FFFF)
}

fn decode_token(raw: u64) -> (u32, u64) {
    let idx = (raw >> 32) as u32;
    let generation = raw & 0xFFFF_FFFF;
    (idx, generation)
}

fn on_invalid_token(reason: &'static str, token: DecisionToken) {
    #[cfg(debug_assertions)]
    panic!(
        "DecisionToken {:?} invalid: {reason}. This is a binding bug — see SDK_DECISION_API_SPEC.md §5.",
        token.inner
    );
    #[cfg(not(debug_assertions))]
    {
        tracing::warn!(
            target: "soth_sdk_core::slab",
            token = token.inner,
            reason,
            "DecisionToken invalid — this is a binding bug; see SDK_DECISION_API_SPEC.md §5"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_ctx() -> DecisionContext {
        DecisionContext {
            created_at: Instant::now(),
            generation: 0,
            detect: DetectResult::default(),
            artifacts_summary: ArtifactsSummary::default(),
            call_provider: "openai".to_string(),
            call_model: "gpt-4o-mini".to_string(),
            user_content: None,
        }
    }

    #[test]
    fn allocate_then_consume_returns_ctx() {
        let slab = DecisionSlab::new();
        let token = slab.allocate(empty_ctx());
        assert!(!token.is_sentinel());
        assert_eq!(slab.in_flight(), 1);
        let ctx = slab.consume(token);
        assert!(ctx.is_some());
        assert_eq!(slab.in_flight(), 0);
    }

    #[test]
    #[cfg_attr(debug_assertions, should_panic(expected = "stale generation"))]
    fn consume_twice_in_debug_panics() {
        let slab = DecisionSlab::new();
        let token = slab.allocate(empty_ctx());
        let _ = slab.consume(token);
        // Second consume on the same token should panic in debug.
        let second = slab.consume(token);
        // Release-mode fallback: assertion below is what we'd assert in
        // production; debug builds panic before reaching it.
        assert!(second.is_none());
    }

    #[test]
    fn sentinel_consume_returns_none() {
        let slab = DecisionSlab::new();
        assert!(slab.consume(DecisionToken::SLAB_FULL).is_none());
        assert!(slab.consume(DecisionToken::SENTINEL_FAIL_OPEN).is_none());
    }

    #[test]
    fn slab_full_returns_sentinel() {
        let slab = DecisionSlab::new();
        // Fill to threshold.
        for _ in 0..SLAB_PRESSURE_THRESHOLD {
            let t = slab.allocate(empty_ctx());
            assert!(!t.is_sentinel());
        }
        // Next allocation should be SLAB_FULL.
        let t = slab.allocate(empty_ctx());
        assert_eq!(t, DecisionToken::SLAB_FULL);
    }
}
