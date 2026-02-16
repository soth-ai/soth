use crate::detection::{
    collect_detection_candidates, compare_detection_candidates, detection_cache_key_hash,
    DetectionCandidate, DetectionRuleGroup,
};
use crate::{DetectionContext, DetectionOutcome, EntryType, OispEngine, ScopedDetectionOutcome};

impl OispEngine {
    pub fn evaluate_detection_for_host(
        &self,
        host: &str,
        context: &DetectionContext,
    ) -> Option<DetectionOutcome> {
        let classification = self.classify(host)?;
        self.evaluate_detection(classification.provider_id.as_str(), context)
    }

    pub fn evaluate_detection(
        &self,
        provider_id: &str,
        context: &DetectionContext,
    ) -> Option<DetectionOutcome> {
        self.evaluate_detection_rules(provider_id, context)
    }

    pub fn evaluate_detection_rules_only(
        &self,
        provider_id: &str,
        context: &DetectionContext,
    ) -> Option<DetectionOutcome> {
        self.evaluate_detection_rules(provider_id, context)
    }

    pub fn evaluate_detection_across_entry_types(
        &self,
        context: &DetectionContext,
        entry_types: &[EntryType],
    ) -> Option<ScopedDetectionOutcome> {
        if entry_types.is_empty() {
            return None;
        }

        let mut provider_ids = self
            .bundle
            .providers
            .keys()
            .cloned()
            .collect::<Vec<String>>();
        provider_ids.sort();

        let mut best: Option<(String, EntryType, DetectionCandidate)> = None;
        for provider_id in provider_ids {
            let Some(provider) = self.resolve_provider(provider_id.as_str()) else {
                continue;
            };
            if !entry_types.contains(&provider.entry_type) {
                continue;
            }
            let mut candidates = Vec::<DetectionCandidate>::new();
            if let Some(detection) = provider.detection.as_ref() {
                collect_detection_candidates(
                    &mut candidates,
                    DetectionRuleGroup::Model,
                    &detection.model_rules,
                    provider,
                    context,
                );
                collect_detection_candidates(
                    &mut candidates,
                    DetectionRuleGroup::Path,
                    &detection.path_rules,
                    provider,
                    context,
                );
                collect_detection_candidates(
                    &mut candidates,
                    DetectionRuleGroup::Ua,
                    &detection.ua_rules,
                    provider,
                    context,
                );
                collect_detection_candidates(
                    &mut candidates,
                    DetectionRuleGroup::Process,
                    &detection.process_rules,
                    provider,
                    context,
                );
                collect_detection_candidates(
                    &mut candidates,
                    DetectionRuleGroup::Env,
                    &detection.env_rules,
                    provider,
                    context,
                );
            }

            let Some(candidate) = candidates.into_iter().max_by(compare_detection_candidates)
            else {
                continue;
            };

            let should_replace = match best.as_ref() {
                None => true,
                Some((best_provider_id, _, best_candidate)) => {
                    compare_detection_candidates(&candidate, best_candidate)
                        .then_with(|| best_provider_id.cmp(&provider_id))
                        .is_gt()
                }
            };

            if should_replace {
                best = Some((provider_id, provider.entry_type.clone(), candidate));
            }
        }

        best.map(
            |(provider_id, entry_type, candidate)| ScopedDetectionOutcome {
                provider_id,
                entry_type,
                outcome: candidate.outcome,
            },
        )
    }

    fn evaluate_detection_rules(
        &self,
        provider_id: &str,
        context: &DetectionContext,
    ) -> Option<DetectionOutcome> {
        let cache_key = detection_cache_key_hash(provider_id, context);
        if let Some(cached) = self
            .detection_cache
            .lock()
            .ok()
            .and_then(|cache| cache.get(&cache_key))
        {
            return cached;
        }

        let provider = self.resolve_provider(provider_id)?;
        let mut candidates = Vec::<DetectionCandidate>::new();

        if let Some(detection) = provider.detection.as_ref() {
            collect_detection_candidates(
                &mut candidates,
                DetectionRuleGroup::Model,
                &detection.model_rules,
                provider,
                context,
            );
            collect_detection_candidates(
                &mut candidates,
                DetectionRuleGroup::Path,
                &detection.path_rules,
                provider,
                context,
            );
            collect_detection_candidates(
                &mut candidates,
                DetectionRuleGroup::Ua,
                &detection.ua_rules,
                provider,
                context,
            );
            collect_detection_candidates(
                &mut candidates,
                DetectionRuleGroup::Process,
                &detection.process_rules,
                provider,
                context,
            );
            collect_detection_candidates(
                &mut candidates,
                DetectionRuleGroup::Env,
                &detection.env_rules,
                provider,
                context,
            );
        }

        let outcome =
            if let Some(best) = candidates.into_iter().max_by(compare_detection_candidates) {
                Some(best.outcome)
            } else {
                None
            };

        if let Ok(mut cache) = self.detection_cache.lock() {
            cache.insert(cache_key, outcome.clone());
        }
        outcome
    }
}
