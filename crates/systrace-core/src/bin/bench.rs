//! Benchmark harness for systrace-core.
//!
//! Usage:  cargo run -p systrace-core --bin bench -- <path-to-sysmon.json>
//!
//! Prints: parse time, event count, process count, unique computers,
//!         interned string count, and estimated heap savings from interning.

use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Instant;

fn main() {
    let path: PathBuf = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            eprintln!("Usage: bench <path-to-sysmon-ndjson>");
            std::process::exit(1);
        });

    println!("Parsing: {}", path.display());
    println!("{}", "-".repeat(60));

    // ── Parse ────────────────────────────────────────────────────────────────
    let rodeo = systrace_core::new_rodeo();
    let (tx, rx) = crossbeam_channel::bounded::<Vec<systrace_core::SysmonEvent>>(64);
    let bytes_read = Arc::new(AtomicU64::new(0));

    let path_clone = path.clone();
    let br_clone = bytes_read.clone();
    let rodeo_clone = rodeo.clone();

    let parse_handle = std::thread::spawn(move || {
        let mut errors = Vec::new();
        let _ = systrace_core::parse_file(&path_clone, &tx, &br_clone, &mut errors, &rodeo_clone);
        errors.len()
    });

    let t0 = Instant::now();

    let mut event_store = systrace_core::EventStore::new();
    let mut process_tree = systrace_core::ProcessTree::new();

    for batch in rx {
        for event in batch {
            if event.event_id == 1 {
                process_tree.insert_process_create(&event, &rodeo);
            } else if event.event_id == 5 {
                if let Some(guid) = event.process_guid {
                    process_tree.update_process_terminate(guid, event.time_created);
                }
            }
            event_store.insert(event);
        }
    }

    let error_count = parse_handle.join().unwrap_or(0);
    process_tree.finalise();

    let elapsed = t0.elapsed();

    // ── Stats ────────────────────────────────────────────────────────────────
    let total_events = event_store.len();
    let total_processes = process_tree.len();

    // Count unique interned strings
    let interned_count = rodeo.len();

    // Estimated memory saved by interning:
    //   Without interning: each computer + image + user string → ~40 bytes avg per event
    //   With interning   : Spur (4 bytes) × 3 fields per event
    let unininterned_estimate = total_events * 40; // rough average 40 bytes per String slot
    let interned_estimate = total_events * 12 + interned_count * 64; // spurs + rodeo storage
    let saved = unininterned_estimate.saturating_sub(interned_estimate);

    let file_size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
    let parse_rate = if elapsed.as_secs_f64() > 0.0 {
        total_events as f64 / elapsed.as_secs_f64()
    } else {
        f64::INFINITY
    };

    println!("Parse time        : {:.3}s", elapsed.as_secs_f64());
    println!("Events            : {}", fmt_count(total_events));
    println!("Processes         : {}", fmt_count(total_processes));
    println!("Parse errors      : {}", fmt_count(error_count));
    println!("File size         : {}", fmt_bytes(file_size));
    println!("Parse rate        : {:.0} events/s", parse_rate);
    println!("{}", "-".repeat(60));
    println!("Interned strings  : {} unique values", fmt_count(interned_count));
    println!("Est. heap saved   : {} (vs raw String)", fmt_bytes(saved as u64));
    println!("{}", "-".repeat(60));

    // Validate against architecture targets
    let mut ok = true;
    let target_secs = 10.0;
    if elapsed.as_secs_f64() > target_secs {
        println!("⚠  SLOW: {:.3}s > {target_secs}s target for this file size", elapsed.as_secs_f64());
        ok = false;
    }
    if ok {
        println!("✓  All targets met");
    }
}

fn fmt_count(n: usize) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 { out.push(','); }
        out.push(c);
    }
    out.chars().rev().collect()
}

fn fmt_bytes(b: u64) -> String {
    if b >= 1_000_000 { format!("{:.1} MB", b as f64 / 1_000_000.0) }
    else if b >= 1_000 { format!("{:.1} KB", b as f64 / 1_000.0) }
    else { format!("{b} B") }
}
