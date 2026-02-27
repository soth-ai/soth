use rusqlite::{params, Connection};
use uuid::Uuid;

use crate::LoadedBundle;

fn ensure_tables(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS intelligence_bundles (
            bundle_version TEXT PRIMARY KEY,
            installed_at INTEGER NOT NULL,
            classifier_hash TEXT,
            centroids_hash TEXT,
            lsh_matrix_hash TEXT,
            anomaly_model_hash TEXT,
            vendor_sig TEXT NOT NULL,
            status TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS active_policy_config (
            config_id TEXT PRIMARY KEY,
            version TEXT NOT NULL,
            received_at INTEGER NOT NULL,
            vendor_sig TEXT NOT NULL,
            org_approval_sig TEXT,
            config_json TEXT,
            status TEXT NOT NULL
        );
        "#,
    )?;
    Ok(())
}

fn asset_hash<'a>(bundle: &'a LoadedBundle, path: &str) -> Option<&'a str> {
    bundle
        .manifest
        .assets
        .iter()
        .find(|entry| entry.path == path)
        .map(|entry| entry.sha256.as_str())
}

pub fn record_bundle_installed(conn: &Connection, bundle: &LoadedBundle) -> rusqlite::Result<()> {
    ensure_tables(conn)?;
    conn.execute(
        "INSERT OR REPLACE INTO intelligence_bundles
         (bundle_version, installed_at, classifier_hash, centroids_hash, lsh_matrix_hash, anomaly_model_hash, vendor_sig, status)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'ACTIVE')",
        params![
            bundle.version,
            bundle.installed_at,
            asset_hash(bundle, "classify/use_case_mlp.bin"),
            asset_hash(bundle, "classify/centroids.bin"),
            asset_hash(bundle, "classify/lsh_projection.bin"),
            asset_hash(bundle, "classify/embedding.onnx"),
            bundle.manifest.vendor_sig,
        ],
    )?;
    Ok(())
}

pub fn mark_superseded(conn: &Connection, version: &str) -> rusqlite::Result<()> {
    ensure_tables(conn)?;
    conn.execute(
        "UPDATE intelligence_bundles SET status = 'SUPERSEDED' WHERE bundle_version = ?1",
        params![version],
    )?;
    Ok(())
}

pub fn record_policy_config(conn: &Connection, bundle: &LoadedBundle) -> rusqlite::Result<()> {
    ensure_tables(conn)?;
    let policy_assets: Vec<_> = bundle
        .manifest
        .assets
        .iter()
        .filter(|entry| entry.path.starts_with("policy/"))
        .cloned()
        .collect();
    let config_json = serde_json::to_string(&policy_assets).unwrap_or_default();
    conn.execute(
        "INSERT INTO active_policy_config
         (config_id, version, received_at, vendor_sig, org_approval_sig, config_json, status)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'ACTIVE')",
        params![
            Uuid::new_v4().to_string(),
            bundle.version,
            bundle.installed_at,
            bundle.manifest.vendor_sig,
            bundle.manifest.org_approval_sig,
            config_json,
        ],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;

    use super::*;
    use crate::manifest::{AssetEntry, BundleManifest, BundleScope};

    fn fixture_bundle() -> LoadedBundle {
        let manifest = BundleManifest {
            version: "bundle-v1".to_string(),
            created_at: 1,
            vendor_sig: "sig".to_string(),
            org_approval_sig: Some("org-sig".to_string()),
            assets: vec![AssetEntry {
                path: "policy/policy_bundle.json".to_string(),
                sha256: "a".repeat(64),
                size_bytes: 42,
            }],
            scope: BundleScope::default(),
        };

        LoadedBundle {
            version: manifest.version.clone(),
            installed_at: 42,
            classify: soth_classify::ClassifyBundle::fallback(),
            policy: Arc::new(soth_policy::sync_policy::PolicyBundle {
                metadata: soth_policy::sync_policy::PolicyBundleMetadata {
                    bundle_version: "policy-v1".to_string(),
                    schema_version: "1".to_string(),
                    org_id: "demo".to_string(),
                    signed_at: 1,
                },
                system_rules: Arc::new(soth_policy::sync_policy::CompiledRuleSet::default()),
                org_rules: Arc::new(soth_policy::sync_policy::CompiledRuleSet::default()),
                org_patterns: Arc::new(soth_policy::sync_policy::OrgPatterns::default()),
                budget_limits: soth_policy::sync_policy::BudgetLimits::default(),
            }),
            detect: Arc::new(soth_detect::OwnedDetectBundle::default()),
            gating: Arc::new(soth_core::GatingBundle::default()),
            manifest,
        }
    }

    #[test]
    fn writes_bundle_and_policy_rows() {
        let conn = Connection::open_in_memory().expect("in-memory");
        let bundle = fixture_bundle();

        record_bundle_installed(&conn, &bundle).expect("record bundle");
        record_policy_config(&conn, &bundle).expect("record policy");
        mark_superseded(&conn, "bundle-v1").expect("supersede");

        let status: String = conn
            .query_row(
                "SELECT status FROM intelligence_bundles WHERE bundle_version = ?1",
                params!["bundle-v1"],
                |row| row.get(0),
            )
            .expect("query status");
        assert_eq!(status, "SUPERSEDED");

        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM active_policy_config", [], |row| {
                row.get(0)
            })
            .expect("query policy count");
        assert_eq!(count, 1);
    }

    #[allow(dead_code)]
    fn _avoid_warning(_: HashMap<String, String>) {}
}
