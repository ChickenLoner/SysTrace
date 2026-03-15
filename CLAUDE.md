# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

SysTrace is a Rust GUI forensic analysis tool for DFIR investigators. It ingests Sysmon operational logs — either raw `.evtx` binary files (parsed natively) or EVTXECmd NDJSON exports — constructs a process tree, and provides process-centric telemetry browsing across all 29 Sysmon event types.

## Architecture

Full architecture document: `.claude/architecture.md`

**Workspace layout:** Cargo workspace with two crates:
- `crates/systrace-core/` — parsing, data structures, process tree, event indexing (library crate)
- `crates/systrace-gui/` — egui/eframe GUI application (binary crate)

**Key design decisions:**
- GUI: egui (immediate mode) via eframe — chosen for virtual scrolling performance at 1M+ events
- Input: `parse_file_auto()` auto-detects format by magic bytes — EVTX binary (`ElfFile\0`) → native parser in `evtx/mod.rs`; anything else → NDJSON parser in `parser.rs`
- EVTX parser: pure Rust, no external tools — BinXml opcodes, template instances, substitution arrays; handles new vs old template format in sub blobs
- Parsing (NDJSON): two-phase — first deserialize top-level EVTXECmd fields, then parse the inner `Payload` JSON string to extract `EventData.Data[]` fields
- Indexing: Events indexed by ProcessGuid, EventId, and time at ingestion — no on-demand scanning
- Threading: Background thread for file ingestion, crossbeam-channel to main/UI thread; batches of 500 events, ≤20 batches drained per UI frame
- Process tree: Built from EventId=1 (ProcessCreate) using ProcessGuid/ParentProcessGuid. Handles out-of-order events via pending_children map

**Critical caveat:** The top-level `ProcessId` field in EVTXECmd JSON is the Sysmon service PID, NOT the monitored process. The actual process PID is inside `Payload.EventData.Data` where `@Name = "ProcessId"`.

## Build & Run

```bash
cargo build                          # build all crates
cargo build --release                # release build
cargo run -p systrace-gui            # run the GUI app
cargo run -p systrace-gui -- <file>  # run with a file argument
cargo test                           # run all tests
cargo test -p systrace-core          # test core library only
```

## Sample Data

- `.claude/sysmon.json` — real EVTXECmd NDJSON export for testing (smaller)
- `.claude/sysmon2.json` — EVTXECmd NDJSON reference, 3759 records (used to verify EVTX parser field output)
- `evtx/Microsoft-Windows-Sysmon%4Operational.evtx` — raw EVTX test file (3738 records)

## Sysmon Event Types

29 event IDs. Key ones: 1 (ProcessCreate), 3 (NetworkConnect), 5 (ProcessTerminate), 11 (FileCreate), 12-14 (Registry), 17-18 (Pipes), 22 (DNS), 23/26 (FileDelete), 8/10 (Injection).

## Conventions

- Use ProcessGuid (not PID) as the primary process identifier — PIDs can be reused
- Parse GUID strings into `[u8; 16]` for compact storage and fast hashing
- Use `FxHashMap` (rustc-hash) for all ProcessGuid-keyed maps
- Intern repeated strings (Image paths, Computer names) with `lasso`
- All telemetry queries go through EventStore indices, never linear scan

## App Icons

- App Icon is located at the root folder of this project with the filename `icon.png`
- This icon must be used to to create binary for Windows

## Plans

- Make plans extremely concise. Sacrifice grammar for concision.
- At the end of each plan, list any unresolved questions.
- Write tasks to `tasks.md` in the root directory; mark completed tasks in real time.