use std::path::Path;

use rusqlite::{params, Connection, OptionalExtension};

use crate::error::ExtensionError;

// ---------------------------------------------------------------------------
// MigrationRunner — coordinated SQLite migrations for all extensions
// ---------------------------------------------------------------------------

pub struct MigrationRunner;

impl MigrationRunner {
    /// Apply all pending migrations for all registered extensions.
    ///
    /// Tracks applied migrations in `extension_migrations` table.
    /// Each migration is applied exactly once and tracked by (extension, idx).
    pub fn run_all(
        db_path: &Path,
        all: Vec<(&'static str, &[&'static str])>,
    ) -> Result<(), ExtensionError> {
        let conn = Connection::open(db_path)
            .map_err(|e| ExtensionError::Migration(format!("open db: {e}")))?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS extension_migrations (
                extension  TEXT NOT NULL,
                idx        INTEGER NOT NULL,
                applied_at INTEGER NOT NULL,
                PRIMARY KEY (extension, idx)
            );",
        )
        .map_err(|e| ExtensionError::Migration(format!("create tracking table: {e}")))?;

        for (ext_name, migrations) in all {
            for (idx, sql) in migrations.iter().enumerate() {
                let already: bool = conn
                    .query_row(
                        "SELECT 1 FROM extension_migrations WHERE extension=?1 AND idx=?2",
                        params![ext_name, idx as i64],
                        |_| Ok(true),
                    )
                    .optional()
                    .map_err(|e| ExtensionError::Migration(format!("check migration: {e}")))?
                    .unwrap_or(false);

                if !already {
                    conn.execute_batch(sql).map_err(|e| {
                        ExtensionError::Migration(format!(
                            "{ext_name} migration {idx} failed: {e}"
                        ))
                    })?;
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs() as i64;
                    conn.execute(
                        "INSERT INTO extension_migrations (extension, idx, applied_at)
                         VALUES (?1, ?2, ?3)",
                        params![ext_name, idx as i64, now],
                    )
                    .map_err(|e| {
                        ExtensionError::Migration(format!("record migration: {e}"))
                    })?;
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tempfile::NamedTempFile;

    fn temp_db() -> (NamedTempFile, PathBuf) {
        let f = NamedTempFile::new().unwrap();
        let path = f.path().to_path_buf();
        (f, path)
    }

    #[test]
    fn run_all_creates_table_and_applies_migrations() {
        let (_f, path) = temp_db();
        let migrations: Vec<(&'static str, &[&'static str])> = vec![(
            "test_ext",
            &["CREATE TABLE test_table (id INTEGER PRIMARY KEY);"],
        )];
        MigrationRunner::run_all(&path, migrations).unwrap();

        let conn = Connection::open(&path).unwrap();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM extension_migrations", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(count, 1);

        // Verify the test table was created
        conn.execute("INSERT INTO test_table (id) VALUES (1)", [])
            .unwrap();
    }

    #[test]
    fn run_all_is_idempotent() {
        let (_f, path) = temp_db();
        let migrations: Vec<(&'static str, &[&'static str])> = vec![(
            "test_ext",
            &["CREATE TABLE idempotent_test (id INTEGER PRIMARY KEY);"],
        )];
        MigrationRunner::run_all(&path, migrations.clone()).unwrap();
        // Running again should not fail (migration already applied)
        MigrationRunner::run_all(&path, migrations).unwrap();
    }

    #[test]
    fn run_all_applies_multiple_extensions() {
        let (_f, path) = temp_db();
        let migrations: Vec<(&'static str, &[&'static str])> = vec![
            (
                "ext_a",
                &["CREATE TABLE ext_a_data (id INTEGER PRIMARY KEY);"],
            ),
            (
                "ext_b",
                &["CREATE TABLE ext_b_data (id INTEGER PRIMARY KEY);"],
            ),
        ];
        MigrationRunner::run_all(&path, migrations).unwrap();

        let conn = Connection::open(&path).unwrap();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM extension_migrations", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(count, 2);
    }
}
