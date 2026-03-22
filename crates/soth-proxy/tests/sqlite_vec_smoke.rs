use std::path::PathBuf;

use rusqlite::params;
use uuid::Uuid;

fn temp_db_path() -> PathBuf {
    std::env::temp_dir().join(format!("soth-proxy-sqlite-vec-smoke-{}.db", Uuid::new_v4()))
}

fn unit_embedding(dim: usize) -> Vec<f32> {
    let mut embedding = vec![0.0f32; 384];
    embedding[dim] = 1.0;
    embedding
}

#[test]
fn sqlite_vec_index_is_available_and_queryable() {
    let db_path = temp_db_path();
    let conn = soth_proxy::db::open(&db_path).expect("open proxy db with sqlite-vec");

    let version: String = conn
        .query_row("SELECT vec_version()", [], |row| row.get(0))
        .expect("sqlite-vec vec_version() should be callable");
    assert!(
        !version.trim().is_empty(),
        "vec_version() returned an empty value"
    );

    let e1 = serde_json::to_string(&unit_embedding(0)).expect("serialize embedding e1");
    let e2 = serde_json::to_string(&unit_embedding(1)).expect("serialize embedding e2");
    let query = serde_json::to_string(&unit_embedding(0)).expect("serialize query embedding");

    conn.execute(
        "INSERT INTO embedding_index(event_id, embedding) VALUES (?1, ?2)",
        params!["event-a", e1],
    )
    .expect("insert first embedding");
    conn.execute(
        "INSERT INTO embedding_index(event_id, embedding) VALUES (?1, ?2)",
        params!["event-b", e2],
    )
    .expect("insert second embedding");

    let (event_id, distance): (String, f32) = conn
        .query_row(
            "
            SELECT event_id, distance
            FROM embedding_index
            WHERE embedding MATCH ?1
              AND k = 1
            ORDER BY distance
            ",
            params![query],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("query nearest neighbor from sqlite-vec index");

    assert_eq!(event_id, "event-a");
    assert!(
        distance <= 0.0001,
        "expected near-zero distance for identical vector, got {distance}"
    );

    drop(conn);
    let _ = std::fs::remove_file(&db_path);
}
