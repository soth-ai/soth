//! Shared SQLite helpers for soth-sync.

use rusqlite::{Connection, OpenFlags, OptionalExtension};
use std::path::Path;
use std::time::Duration;

pub const DEFAULT_SQLITE_BUSY_TIMEOUT_MS: u64 = 2_000;
pub const SQLITE_MMAP_SIZE_BYTES: i64 = 268_435_456; // 256 MB
pub const SQLITE_CACHE_SIZE_KIB: i64 = -64_000; // 64 MB

pub const SYNC_KEY_LAST_SYNC_TIMESTAMP: &str = "last_sync_timestamp";
pub const SYNC_KEY_SYNC_ERRORS: &str = "sync_errors";

fn to_io_err(error: rusqlite::Error) -> std::io::Error {
    std::io::Error::other(error.to_string())
}

fn apply_busy_timeout(conn: &Connection, busy_timeout: Duration) -> std::io::Result<()> {
    conn.busy_timeout(busy_timeout).map_err(to_io_err)
}

fn apply_rw_pragmas(conn: &Connection) -> std::io::Result<()> {
    conn.pragma_update(None, "journal_mode", "WAL")
        .map_err(to_io_err)?;
    conn.pragma_update(None, "synchronous", "NORMAL")
        .map_err(to_io_err)?;
    conn.pragma_update(None, "mmap_size", SQLITE_MMAP_SIZE_BYTES)
        .map_err(to_io_err)?;
    conn.pragma_update(None, "page_size", 4096_i64)
        .map_err(to_io_err)?;
    conn.pragma_update(None, "cache_size", SQLITE_CACHE_SIZE_KIB)
        .map_err(to_io_err)?;
    Ok(())
}

pub fn open_sqlite_read_write(path: &Path) -> std::io::Result<Connection> {
    open_sqlite_read_write_with_timeout(path, Duration::from_millis(DEFAULT_SQLITE_BUSY_TIMEOUT_MS))
}

pub fn open_sqlite_read_write_with_timeout(
    path: &Path,
    busy_timeout: Duration,
) -> std::io::Result<Connection> {
    let conn = Connection::open(path).map_err(to_io_err)?;
    apply_busy_timeout(&conn, busy_timeout)?;
    apply_rw_pragmas(&conn)?;
    Ok(conn)
}

pub fn open_sqlite_read_only(path: &Path) -> std::io::Result<Connection> {
    open_sqlite_read_only_with_timeout(path, Duration::from_millis(DEFAULT_SQLITE_BUSY_TIMEOUT_MS))
}

pub fn open_sqlite_read_only_with_timeout(
    path: &Path,
    busy_timeout: Duration,
) -> std::io::Result<Connection> {
    let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI;
    let conn = Connection::open_with_flags(path, flags).map_err(to_io_err)?;
    apply_busy_timeout(&conn, busy_timeout)?;
    Ok(conn)
}

pub fn ensure_sync_state_table(conn: &Connection) -> std::io::Result<()> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS sync_state (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        "#,
    )
    .map_err(to_io_err)?;
    Ok(())
}

pub fn read_sync_state(conn: &Connection, key: &str) -> std::io::Result<Option<String>> {
    ensure_sync_state_table(conn)?;
    conn.query_row(
        "SELECT value FROM sync_state WHERE key = ?1",
        [key],
        |row| row.get(0),
    )
    .optional()
    .map_err(to_io_err)
}

pub fn write_sync_state(conn: &Connection, key: &str, value: &str) -> std::io::Result<()> {
    ensure_sync_state_table(conn)?;
    conn.execute(
        r#"
        INSERT INTO sync_state (key, value, updated_at)
        VALUES (?1, ?2, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
        ON CONFLICT(key) DO UPDATE SET
            value = excluded.value,
            updated_at = excluded.updated_at
        "#,
        [key, value],
    )
    .map_err(to_io_err)?;
    Ok(())
}
