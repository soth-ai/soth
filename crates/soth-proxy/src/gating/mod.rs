pub mod evaluator;
pub mod stage0_tls;
pub mod stage1_app_origin;
pub mod stage2_whitelist;
pub mod stage3_blacklist;
pub mod stage4_app_type;
pub mod stage5_host_origin;
pub mod types;

pub use evaluator::GateEvaluator;
pub use types::{DecisionReason, GateDecision, GateOutcome};
