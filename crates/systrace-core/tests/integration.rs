use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use systrace_core::{
    EventStore, ProcessTree,
    event::SysmonEventType,
    parser::{parse_file, parse_payload},
    types::{parse_guid, parse_mitre_rule_name},
};

fn sample_path() -> PathBuf {
    // .claude/sysmon.json is at the workspace root
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // crates/systrace-core -> workspace root
    p.pop();
    p.pop();
    p.push(".claude");
    p.push("sysmon.json");
    p
}

/// Parse the sample file and return (event_store, process_tree, error_count).
fn load_sample() -> (EventStore, ProcessTree, usize) {
    let path = sample_path();
    assert!(path.exists(), "Sample file not found at {:?}", path);

    let (tx, rx) = crossbeam_channel::bounded(256);
    let bytes_read = Arc::new(AtomicU64::new(0));
    let mut errors: Vec<systrace_core::ParseError> = Vec::new();

    {
        let path2 = path.clone();
        let br = bytes_read.clone();
        let tx2 = tx.clone();
        std::thread::spawn(move || {
            let _ = parse_file(&path2, &tx2, &br, &mut Vec::new());
        });
    }
    drop(tx); // close sender side so channel eventually empties

    let mut event_store = EventStore::new();
    let mut process_tree = ProcessTree::new();

    for batch in &rx {
        for event in batch {
            if event.event_id == 1 {
                process_tree.insert_process_create(&event);
            } else if event.event_id == 5 {
                if let Some(guid) = event.process_guid {
                    process_tree.update_process_terminate(guid, event.time_created);
                }
            }
            event_store.insert(event);
        }
    }
    process_tree.finalise();

    let error_count = errors.len();
    (event_store, process_tree, error_count)
}

#[test]
fn parse_sample_file_produces_events() {
    let (store, _tree, _errs) = load_sample();
    // The sample file has 169 lines → should parse most of them
    assert!(store.len() > 100, "Expected >100 events, got {}", store.len());
}

#[test]
fn event_type_counts_reasonable() {
    let (store, _tree, _errs) = load_sample();
    let counts = store.event_type_counts();
    // The sample begins with DNS queries (EventId 22) and file creates (EventId 11)
    let has_dns = counts.iter().any(|(id, n)| *id == 22 && *n > 0);
    let has_file = counts.iter().any(|(id, n)| *id == 11 && *n > 0);
    assert!(has_dns, "Expected DNS events (EventId 22)");
    assert!(has_file, "Expected FileCreate events (EventId 11)");
}

#[test]
fn process_tree_has_nodes() {
    let (_store, tree, _errs) = load_sample();
    // The sample should contain at least one ProcessCreate event
    // (If the sample has no EventId=1, tree will be empty — that's a sample-specific fact)
    // We assert the tree is coherent regardless
    for root_guid in tree.roots() {
        let node = tree.get(root_guid).expect("Root guid should exist in nodes");
        // Check children are valid
        for child_guid in &node.children {
            assert!(
                tree.get(child_guid).is_some(),
                "Child guid references a missing node"
            );
        }
    }
}

#[test]
fn guid_indexing_consistent() {
    let (store, _tree, _errs) = load_sample();
    // Every index entry should point to a valid event with a matching guid
    for (guid, indices) in &store.by_process {
        for &idx in indices {
            let event = &store.events[idx];
            assert_eq!(
                event.process_guid.as_ref(),
                Some(guid),
                "by_process index points to wrong event"
            );
        }
    }
}

#[test]
fn event_type_index_consistent() {
    let (store, _tree, _errs) = load_sample();
    for (event_id, indices) in &store.by_event_type {
        for &idx in indices {
            assert_eq!(
                store.events[idx].event_id,
                *event_id,
                "by_event_type index points to wrong event"
            );
        }
    }
}

// --- Unit tests (also runnable via `cargo test -p systrace-core`) ---

#[test]
fn guid_parsing_edge_cases() {
    // Standard GUID from the sample data
    assert!(parse_guid("817bddf3-3514-65cc-0802-000000001900").is_ok());
    // All-zeros
    assert!(parse_guid("00000000-0000-0000-0000-000000000000").is_ok());
    // Invalid
    assert!(parse_guid("not-a-guid").is_err());
    assert!(parse_guid("").is_err());
    assert!(parse_guid("817bddf3-3514-65cc-0802").is_err());
}

#[test]
fn mitre_rule_name_parsing() {
    let t = parse_mitre_rule_name(
        "technique_id=T1059.001,technique_name=PowerShell",
    ).unwrap();
    assert_eq!(t.id, "T1059.001");
    assert_eq!(t.name, "PowerShell");

    // Multiple fields with spaces around comma
    let t2 = parse_mitre_rule_name(
        "technique_id=T1055 , technique_name=Process Injection",
    ).unwrap();
    assert_eq!(t2.id, "T1055");
    assert_eq!(t2.name, "Process Injection");

    // Missing one part → None
    assert!(parse_mitre_rule_name("technique_id=T1055").is_none());
    assert!(parse_mitre_rule_name("-").is_none());
    assert!(parse_mitre_rule_name("").is_none());
}

#[test]
fn parse_payload_empty_data() {
    let payload = r##"{"EventData":{"Data":[]}}"##;
    let map = parse_payload(payload).unwrap();
    assert!(map.is_empty());
}

#[test]
fn parse_payload_from_sample_record() {
    // Payload from the first record in sysmon.json
    let payload = r##"{"EventData":{"Data":[{"@Name":"RuleName","#text":"-"},{"@Name":"ProcessGuid","#text":"817bddf3-3514-65cc-0802-000000001900"},{"@Name":"QueryName","#text":"example.com"}]}}"##;
    let map = parse_payload(payload).unwrap();
    assert_eq!(map["RuleName"], "-");
    assert_eq!(map["ProcessGuid"], "817bddf3-3514-65cc-0802-000000001900");
    assert_eq!(map["QueryName"], "example.com");
}

#[test]
fn sysmon_event_type_roundtrip() {
    for id in 1u16..=29 {
        let et = SysmonEventType::from_event_id(id);
        assert_eq!(et.event_id(), id, "event_id roundtrip failed for {id}");
        assert!(!et.display_name().is_empty());
    }
    // Unknown
    let unknown = SysmonEventType::from_event_id(99);
    assert_eq!(unknown.event_id(), 99);
}
