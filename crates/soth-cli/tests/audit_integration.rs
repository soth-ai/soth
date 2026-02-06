//! Audit trail integration tests
//!
//! Tests for Merkle proof generation and verification

use soth_observe::{MerkleTree, TransparencyLog};
use tempfile::tempdir;

#[test]
fn test_merkle_tree_basic_operations() {
    let mut tree = MerkleTree::new();

    // Initially empty
    assert_eq!(tree.len(), 0);
    assert!(tree.root().is_none());

    // Add some data
    tree.append(b"entry 1");
    assert_eq!(tree.len(), 1);

    tree.append(b"entry 2");
    assert_eq!(tree.len(), 2);

    // Root should now exist
    assert!(tree.root().is_some());
}

#[test]
fn test_merkle_tree_determinism() {
    // Two trees with same data should have same root
    let mut tree1 = MerkleTree::new();
    let mut tree2 = MerkleTree::new();

    let entries: Vec<&[u8]> = vec![b"first", b"second", b"third"];

    for entry in &entries {
        tree1.append(*entry);
        tree2.append(*entry);
    }

    assert_eq!(tree1.root(), tree2.root());
    assert_eq!(tree1.root_hex(), tree2.root_hex());
}

#[test]
fn test_merkle_proof_generation_and_verification() {
    let mut tree = MerkleTree::new();

    // Add multiple entries
    let entries: Vec<&[u8]> = vec![
        b"audit event 1",
        b"audit event 2",
        b"audit event 3",
        b"audit event 4",
        b"audit event 5",
    ];

    for entry in &entries {
        tree.append(*entry);
    }

    // Generate proof for each entry
    for i in 0..entries.len() {
        let proof = tree.get_proof(i).expect("proof generation should succeed");

        // Verify the proof using static method
        assert!(
            MerkleTree::verify_proof(&proof, Some(entries[i])),
            "proof verification should succeed for entry {}",
            i
        );
    }
}

#[test]
fn test_merkle_proof_fails_for_wrong_data() {
    let mut tree = MerkleTree::new();

    tree.append(b"entry 1");
    tree.append(b"entry 2");

    let proof = tree.get_proof(0).expect("proof should exist");

    // Proof should not verify with wrong data
    assert!(!MerkleTree::verify_proof(&proof, Some(b"wrong data")));
}

#[test]
fn test_merkle_proof_serialization() {
    let mut tree = MerkleTree::new();

    tree.append(b"data 1");
    tree.append(b"data 2");

    let proof = tree.get_proof(0).expect("proof should exist");

    // Serialize to JSON
    let json = proof.to_json();

    // Should contain expected fields
    assert!(json.get("leaf_hash").is_some());
    assert!(json.get("siblings").is_some());
    assert!(json.get("leaf_index").is_some());
}

#[test]
fn test_transparency_log() {
    // Create in-memory transparency log
    let mut log = TransparencyLog::new();

    // Append entries
    log.append(b"event 1", "request", None);
    log.append(b"event 2", "response", None);
    log.append(b"event 3", "request", None);

    assert_eq!(log.len(), 3);

    // Get the current root
    let root = log.root_hash();
    assert!(root.is_some());

    // Generate and verify proof
    let proof = log.get_proof(1).expect("proof should exist");
    assert!(log.verify_proof(&proof));
}

#[test]
fn test_transparency_log_json_append() {
    let mut log = TransparencyLog::new();

    // Append JSON values
    log.append_json(&serde_json::json!({"event": "start", "id": 1}), "lifecycle");
    log.append_json(&serde_json::json!({"event": "stop", "id": 1}), "lifecycle");

    assert_eq!(log.len(), 2);
    assert!(log.verify_integrity());
}

#[test]
fn test_transparency_log_persistence() {
    let dir = tempdir().expect("temp dir should work");
    let log_path = dir.path().join("persistent.log");

    // Create and populate log
    {
        let mut log = TransparencyLog::open(&log_path).expect("log creation should succeed");

        log.append(b"entry 1", "test", None);
        log.append(b"entry 2", "test", None);
    }

    // Reopen and verify
    {
        let log = TransparencyLog::open(&log_path).expect("log opening should succeed");

        assert_eq!(log.len(), 2);
        assert!(log.verify_integrity());
    }
}

#[test]
fn test_merkle_tree_with_large_dataset() {
    let mut tree = MerkleTree::new();

    // Add many entries
    for i in 0..100 {
        let entry = format!("entry number {}", i);
        tree.append(entry.as_bytes());
    }

    assert_eq!(tree.len(), 100);

    // Verify we can generate and verify proofs for random entries
    for i in [0, 25, 50, 75, 99] {
        let entry = format!("entry number {}", i);
        let proof = tree.get_proof(i).expect("proof should exist");
        assert!(MerkleTree::verify_proof(&proof, Some(entry.as_bytes())));
    }
}

#[test]
fn test_merkle_tree_root_changes() {
    let mut tree = MerkleTree::new();

    tree.append(b"first");
    let root1 = tree.root_hex();

    tree.append(b"second");
    let root2 = tree.root_hex();

    // Root should change when data is added
    assert_ne!(root1, root2);
}

#[test]
fn test_merkle_tree_odd_number_of_leaves() {
    // Test with odd numbers which require special handling
    for count in [1, 3, 5, 7, 11, 13] {
        let mut tree = MerkleTree::new();

        for i in 0..count {
            tree.append(format!("entry {}", i).as_bytes());
        }

        // Should be able to generate proof for last entry
        let proof = tree.get_proof(count - 1);
        assert!(proof.is_some(), "proof should exist for {} entries", count);
    }
}

#[test]
fn test_transparency_log_integrity() {
    let mut log = TransparencyLog::new();

    for i in 0..10 {
        log.append(format!("event {}", i).as_bytes(), "test", None);
    }

    // Log should maintain integrity
    assert!(log.verify_integrity());

    // All entries should have sequential sequence numbers
    for (i, entry) in log.entries().iter().enumerate() {
        assert_eq!(entry.sequence, i as u64);
    }
}

#[test]
fn test_transparency_log_get_entry() {
    let mut log = TransparencyLog::new();

    log.append(b"first", "type1", None);
    log.append(b"second", "type2", None);
    log.append(b"third", "type1", None);

    // Get specific entry
    let entry = log.get_entry(1).expect("entry should exist");
    assert_eq!(entry.sequence, 1);
    assert_eq!(entry.entry_type, "type2");

    // Non-existent entry
    assert!(log.get_entry(100).is_none());
}

#[test]
fn test_consistency_proof() {
    let mut log = TransparencyLog::new();

    // Add initial entries
    for i in 0..5 {
        log.append(format!("entry {}", i).as_bytes(), "test", None);
    }

    let old_root = log.root_hash();

    // Add more entries
    for i in 5..10 {
        log.append(format!("entry {}", i).as_bytes(), "test", None);
    }

    let new_root = log.root_hash();

    // Get consistency proof
    let consistency = log
        .get_consistency_proof(5, 10)
        .expect("consistency proof should exist");

    assert_eq!(consistency.old_size, 5);
    assert_eq!(consistency.new_size, 10);
    assert_eq!(Some(consistency.old_root), old_root);
    assert_eq!(Some(consistency.new_root), new_root);
}
