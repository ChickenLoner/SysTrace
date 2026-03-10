# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

SysTrace is a Rust GUI forensic analysis tool that parses Sysmon logs exported by EVTXECmd (NDJSON format) and displays them as an interactive process tree with process-centric telemetry browsing. Built for DFIR investigators.

## Architecture

Full architecture document: `.claude/architecture.md`

**Workspace layout:** Cargo workspace with two crates:
- `crates/systrace-core/` — parsing, data structures, process tree, event indexing (library crate)
- `crates/systrace-gui/` — egui/eframe GUI application (binary crate)

**Key design decisions:**
- GUI: egui (immediate mode) via eframe — chosen for virtual scrolling performance at 1M+ events
- Parsing: Two-phase — first deserialize top-level EVTXECmd fields, then parse the inner `Payload` JSON string to extract `EventData.Data[]` fields
- Indexing: Events indexed by ProcessGuid, EventId, and time at ingestion — no on-demand scanning
- Threading: Background thread for file ingestion, crossbeam-channel to main/UI thread
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

`.claude/sysmon.json` contains a real EVTXECmd Sysmon export for testing. Each line is a self-contained JSON object with fields like EventId, TimeCreated, Payload (nested JSON string), PayloadData1-6, MapDescription, etc.

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

- If you have to make plan, Make the plan extremely concise. Sacrifice grammar for the sake of concision.
- At the end of each plan, give me a list of unresolved questions to answer, if any.
- Write what need to be done in `tasks.md` in root directory of this project
- Always mark what done in `tasks.md` in real time and suggest change to user if needs