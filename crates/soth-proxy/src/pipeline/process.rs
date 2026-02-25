use std::time::{Duration, Instant};

use dashmap::DashMap;
use soth_core::{AppType, CaptureMode, ProcessInfo, ProcessMatchKind, ProcessResolution};

use crate::pipeline::registry::Registry;

#[derive(Debug, Clone)]
struct CachedProcess {
    resolution: ProcessResolution,
    cached_at: Instant,
}

#[derive(Debug)]
pub struct ProcessLookup {
    cache: DashMap<u32, CachedProcess>,
    ttl: Duration,
}

impl ProcessLookup {
    pub fn new(ttl: Duration) -> Self {
        Self {
            cache: DashMap::new(),
            ttl,
        }
    }

    pub fn resolve(
        &self,
        process_info: Option<&ProcessInfo>,
        registry: &Registry,
    ) -> ProcessResolution {
        let Some(process_info) = process_info else {
            return unknown_resolution();
        };

        let Some(pid) = process_info.pid else {
            return self.resolve_fresh(process_info, registry);
        };

        if let Some(cached) = self.cache.get(&pid) {
            if cached.cached_at.elapsed() <= self.ttl {
                return cached.resolution.clone();
            }
        }

        let resolution = self.resolve_fresh(process_info, registry);
        self.cache.insert(
            pid,
            CachedProcess {
                resolution: resolution.clone(),
                cached_at: Instant::now(),
            },
        );
        resolution
    }

    fn resolve_fresh(&self, process_info: &ProcessInfo, registry: &Registry) -> ProcessResolution {
        let process_name = process_info.process_name.clone();
        let bundle_id = process_info.bundle_id.clone();

        if let Some(app) = registry.match_application(
            process_info.process_name.as_deref(),
            process_info.bundle_id.as_deref(),
        ) {
            let match_kind = if process_info.bundle_id.as_deref().is_some_and(|bundle| {
                app.bundle_ids
                    .iter()
                    .any(|v| v.eq_ignore_ascii_case(bundle))
            }) {
                ProcessMatchKind::Exact
            } else {
                ProcessMatchKind::Pattern
            };

            return ProcessResolution {
                match_kind,
                app_type: app.app_type,
                capture_mode: None,
                process_name,
                bundle_id,
            };
        }

        ProcessResolution {
            match_kind: ProcessMatchKind::Unknown,
            app_type: infer_from_name(process_info.process_name.as_deref()),
            capture_mode: None,
            process_name,
            bundle_id,
        }
    }

    pub fn clear_expired(&self) {
        let ttl = self.ttl;
        self.cache
            .retain(|_, cached| cached.cached_at.elapsed() <= ttl);
    }

    pub fn clear_all(&self) {
        self.cache.clear();
    }
}

fn unknown_resolution() -> ProcessResolution {
    ProcessResolution {
        match_kind: ProcessMatchKind::Unknown,
        app_type: AppType::Unknown,
        capture_mode: Some(CaptureMode::MetadataOnly),
        process_name: None,
        bundle_id: None,
    }
}

fn infer_from_name(process_name: Option<&str>) -> AppType {
    let Some(name) = process_name else {
        return AppType::Unknown;
    };
    let name = name.to_ascii_lowercase();

    let host_markers = [
        "chrome", "firefox", "safari", "edge", "arc", "browser", "brave",
    ];

    if host_markers.iter().any(|marker| name.contains(marker)) {
        AppType::Host
    } else {
        AppType::NonHost
    }
}
