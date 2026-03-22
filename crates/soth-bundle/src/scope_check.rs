use std::collections::HashSet;

use crate::error::BundleError;
use crate::manifest::{BundleScope, OrgSignedConfig};

pub fn check_scope(
    incoming: &BundleScope,
    org_config: &OrgSignedConfig,
) -> Result<(), BundleError> {
    if incoming.intercept_https && !org_config.allows_https_intercept {
        return Err(BundleError::ScopeExpansionRefused {
            reason: "bundle requests HTTPS intercept not authorized by org config".to_string(),
        });
    }
    if incoming.intercept_http && !org_config.allows_http_intercept {
        return Err(BundleError::ScopeExpansionRefused {
            reason: "bundle requests HTTP intercept not authorized by org config".to_string(),
        });
    }

    let allowed_modes: HashSet<&str> = org_config
        .allowed_capture_modes
        .iter()
        .map(String::as_str)
        .collect();
    for mode in &incoming.capture_modes {
        if !allowed_modes.contains(mode.as_str()) {
            return Err(BundleError::ScopeExpansionRefused {
                reason: format!("bundle requests capture mode '{mode}' not in org config"),
            });
        }
    }

    match (&org_config.process_filter, &incoming.process_filter) {
        (Some(_), None) => {
            return Err(BundleError::ScopeExpansionRefused {
                reason: "bundle removes process filter required by org config".to_string(),
            });
        }
        (Some(org_filter), Some(bundle_filter)) => {
            let org: HashSet<&str> = org_filter.iter().map(String::as_str).collect();
            for process in bundle_filter {
                if !org.contains(process.as_str()) {
                    return Err(BundleError::ScopeExpansionRefused {
                        reason: format!("bundle process filter widens scope with '{process}'"),
                    });
                }
            }
        }
        (None, _) => {}
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_narrower_scope() {
        let org = OrgSignedConfig {
            allows_https_intercept: true,
            allows_http_intercept: true,
            process_filter: Some(vec![
                "com.cursor.app".to_string(),
                "com.openai.chatgpt".to_string(),
            ]),
            allowed_capture_modes: vec![
                "metadata_only".to_string(),
                "sensitive_artifacts".to_string(),
            ],
        };
        let incoming = BundleScope {
            intercept_https: true,
            intercept_http: false,
            process_filter: Some(vec!["com.cursor.app".to_string()]),
            capture_modes: vec!["metadata_only".to_string()],
        };
        check_scope(&incoming, &org).expect("narrowing scope should pass");
    }

    #[test]
    fn rejects_expanded_capture_mode() {
        let org = OrgSignedConfig {
            allowed_capture_modes: vec!["metadata_only".to_string()],
            ..OrgSignedConfig::default()
        };
        let incoming = BundleScope {
            capture_modes: vec!["full_content".to_string()],
            ..BundleScope::default()
        };
        let err = check_scope(&incoming, &org).expect_err("expanded mode should fail");
        assert!(matches!(err, BundleError::ScopeExpansionRefused { .. }));
    }
}
