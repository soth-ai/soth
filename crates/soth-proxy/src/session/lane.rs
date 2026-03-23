/// Pipeline lane determines how much processing a request receives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lane {
    /// Full pipeline: classify with embedding, policy, telemetry.
    Full,
    /// Agent loop step: classify only the novel tail (no embedding of repeated prefix).
    AgentLoopStep,
    /// Code context repeat: policy only (no classify, no embedding). Metadata-only telemetry.
    CodeContextRepeat,
}

/// Determine the pipeline lane from a detect result.
///
/// Conservative: defaults to Full unless detect signals high-confidence dedup.
pub fn determine_lane(detect_result: &soth_core::DetectResult) -> Lane {
    // Code context repeat: repeated code block with no credential alert
    if detect_result.is_repeated_code_context && !detect_result.session_mutations.credential_alert {
        return Lane::CodeContextRepeat;
    }

    // Agent loop step: prefix repeat with a novel tail identified
    if detect_result.is_prefix_repeat && detect_result.novel_tail_start_idx.is_some() {
        return Lane::AgentLoopStep;
    }

    Lane::Full
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_detect_result_maps_to_full_lane() {
        let detect = soth_core::DetectResult::default();
        assert_eq!(determine_lane(&detect), Lane::Full);
    }

    #[test]
    fn code_context_repeat_without_credential_maps_to_code_repeat_lane() {
        let detect = soth_core::DetectResult {
            is_repeated_code_context: true,
            ..Default::default()
        };
        assert_eq!(determine_lane(&detect), Lane::CodeContextRepeat);
    }

    #[test]
    fn code_context_repeat_with_credential_maps_to_full_lane() {
        let detect = soth_core::DetectResult {
            is_repeated_code_context: true,
            session_mutations: soth_core::SessionMutations {
                credential_alert: true,
                ..Default::default()
            },
            ..Default::default()
        };
        assert_eq!(determine_lane(&detect), Lane::Full);
    }

    #[test]
    fn prefix_repeat_with_novel_tail_maps_to_agent_loop_step() {
        let detect = soth_core::DetectResult {
            is_prefix_repeat: true,
            novel_tail_start_idx: Some(5),
            ..Default::default()
        };
        assert_eq!(determine_lane(&detect), Lane::AgentLoopStep);
    }

    #[test]
    fn prefix_repeat_without_novel_tail_maps_to_full() {
        let detect = soth_core::DetectResult {
            is_prefix_repeat: true,
            ..Default::default()
        };
        assert_eq!(determine_lane(&detect), Lane::Full);
    }
}
