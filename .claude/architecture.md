# SysTrace Architecture Document

## 1. System Architecture

### Overview

SysTrace is a Rust-based GUI forensic analysis tool for DFIR investigators. It ingests Sysmon operational logs — either raw `.evtx` binary files (parsed natively) or EVTXECmd NDJSON exports — constructs a process tree, and provides process-centric telemetry browsing across all 29 Sysmon event types.

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                       GUI Layer (egui)                       │
│  ┌──────────┐  ┌───────────────────────┐  ┌──────────────┐  │
│  │ Process   │  │  Telemetry Panels     │  │  Timeline    │  │
│  │ Tree      │  │  (Network/File/Reg/…) │  │  View        │  │
│  │ Panel     │  │                       │  │              │  │
│  └────┬─────┘  └──────────┬────────────┘  └──────┬───────┘  │
│       │                   │                      │           │
├───────┴───────────────────┴──────────────────────┴───────────┤
│                    Application State Layer                    │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────────────┐ │
│  │ ProcessTree   │  │ EventStore   │  │ SelectionState     │ │
│  │ (tree struct) │  │ (indexed)    │  │ (UI state)         │ │
│  └──────┬───────┘  └──────┬───────┘  └────────────────────┘ │
├─────────┴──────────────────┴─────────────────────────────────┤
│                    Core Engine Layer                          │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────────────┐ │
│  │ Auto-detect   │  │ Process Tree │  │ Event Store        │ │
│  │ Parser        │  │ Builder      │  │ (multi-key index)  │ │
│  └──────┬───────┘  └──────────────┘  └────────────────────┘ │
│         │                                                     │
│  ┌──────┴──────────────────────────────────────────────────┐ │
│  │         parse_file_auto() — magic-byte dispatch          │ │
│  │   ┌──────────────────┐    ┌──────────────────────────┐  │ │
│  │   │  EVTX Binary     │    │  NDJSON Parser           │  │ │
│  │   │  Parser          │    │  (EVTXECmd JSON)         │  │ │
│  │   │  (evtx/mod.rs)   │    │  (parser.rs)             │  │ │
│  │   └──────────────────┘    └──────────────────────────┘  │ │
│  └─────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────┘
```

### Threading Model

```
Main Thread:   GUI rendering loop (egui)
Background:    File ingestion + parsing (std::thread)
Communication: crossbeam-channel (unbounded) — batches of 500 events
```

Parsed events are sent in batches of 500 via crossbeam-channel. The UI thread drains up to `MAX_BATCHES_PER_FRAME = 20` batches per frame to stay responsive during large loads. A shared `AtomicU64` tracks bytes read for the progress bar.

---

## 2. Data Ingestion Pipeline

### Input Formats

SysTrace accepts two input formats, auto-detected by magic bytes:

| Format | Magic Bytes | Parser |
|--------|-------------|--------|
| EVTX binary | `ElfFile\0` (8 bytes @ offset 0) | `evtx/mod.rs` — native Rust parser |
| NDJSON (EVTXECmd export) | anything else | `parser.rs` — serde_json line parser |

### Auto-Detection

`parse_file_auto()` in `parser.rs`:
1. Reads first 8 bytes of the file.
2. If equal to `b"ElfFile\0"` → calls `parse_evtx_file()` from `evtx/mod.rs`.
3. Otherwise → calls `parse_file()` (NDJSON path).

Both branches produce `SysmonEvent` structs and send them over the same crossbeam-channel interface.

### NDJSON Pipeline (EVTXECmd output)

```
File on Disk
    │
    ▼
BufReader (line-by-line)
    │
    ▼
serde_json::from_str() → RawEvtxRecord (Phase 1 fields)
    │
    ▼
Parse Payload string → EventData.Data[] array
    │
    ▼
HashMap<String, String> field extraction by EventId
    │
    ▼
extract_event() → SysmonEvent
    │
    ▼
Batch 500 → crossbeam-channel → Main thread
    │
    ▼
Insert into EventStore + ProcessTree
```

### EVTX Binary Pipeline (native parser)

```
File on Disk
    │
    ▼
Read file header (4096 bytes) — validate "ElfFile\0" signature
Extract chunk_count (u16 @ 0x2A)
    │
    ▼
For each 65536-byte chunk:
  Parse string table (64 × u32 offsets → UTF-16LE strings)
  Parse template table (32 × u32 offsets → pre-parsed BinXml templates)
    │
    ▼
For each event record in chunk:
  Read record header: magic(4) + size(4) + record_id(8) + timestamp(8)
  Parse BinXml payload via TemplateInstance opcode (0x0C)
  Resolve substitution array against pre-parsed template
  Extract EventFields (event_id, timestamp, computer, data HashMap)
    │
    ▼
extract_event() → SysmonEvent (same function as NDJSON path)
    │
    ▼
Batch 500 → crossbeam-channel → Main thread
```

### BinXml Template Resolution

EVTX records use Binary XML with template instances. Templates are pre-parsed per chunk into `Vec<TNode>`. Substitution arrays map slot indices to typed values.

**Critical: new vs old template format in substitution blobs**

When EventData is embedded as a vtype `0x21` (BinXml) substitution, the blob header format depends on whether the template is being defined for the first time in the chunk:

- **New template** (first occurrence, `template_offset >= record_chunk_offset`): blob contains `0x0C + version(1) + template_id(4) + template_offset(4) + nextTemplateOffset(4) + guid(16) + length(4) + template_bytes(length)` before the substitution count.
- **Old template** (back-reference, `template_offset < record_chunk_offset`): blob contains `0x0C + version(1) + template_id(4) + template_offset(4)` then immediately the substitution count.

Detection: `is_old = (template_offset as usize) < record_chunk_offset`.

---

## 3. Event Parsing Design

### EVTXECmd JSON Structure (NDJSON path)

Each record has two layers:

**Layer 1 — Top-level fields:**
```
EventId, TimeCreated, RecordNumber, Computer, UserName,
MapDescription, PayloadData1..6, ExecutableInfo,
Channel, Provider, UserId, Level
```

**Layer 2 — Payload field (embedded JSON string):**
```json
{
  "EventData": {
    "Data": [
      { "@Name": "ProcessGuid", "#text": "817bddf3-..." },
      { "@Name": "Image", "#text": "C:\\...\\firefox.exe" }
    ]
  }
}
```

**Important:** The top-level `ProcessId` is the Sysmon service PID, NOT the monitored process. Always read PID from the inner `EventData.Data` where `@Name = "ProcessId"`.

### Field Extraction Per Event Type

| EventId | Key Fields |
|---------|-----------|
| 1 (ProcessCreate) | ProcessGuid, ProcessId, Image, CommandLine, ParentProcessGuid, ParentProcessId, ParentImage, ParentCommandLine, Hashes, User, LogonId, IntegrityLevel |
| 3 (NetworkConnect) | ProcessGuid, Image, Protocol, Initiated, SourceIp, SourcePort, DestinationIp, DestinationPort, DestinationHostname |
| 5 (ProcessTerminate) | ProcessGuid, ProcessId, Image |
| 6 (DriverLoad) | ImageLoaded, Hashes, Signature, SignatureStatus |
| 7 (ImageLoad) | ProcessGuid, Image, ImageLoaded, Hashes, Signature, SignatureStatus |
| 8 (CreateRemoteThread) | SourceProcessGuid, SourceImage, TargetProcessGuid, TargetImage, StartAddress |
| 9 (RawAccessRead) | ProcessGuid, Image, Device |
| 10 (ProcessAccess) | SourceProcessGuid, SourceImage, TargetProcessGuid, TargetImage, GrantedAccess, CallTrace |
| 11 (FileCreate) | ProcessGuid, Image, TargetFilename, CreationUtcTime |
| 12 (RegistryCreate/Delete) | ProcessGuid, Image, EventType, TargetObject |
| 13 (RegistryValueSet) | ProcessGuid, Image, EventType, TargetObject, Details |
| 14 (RegistryRename) | ProcessGuid, Image, EventType, TargetObject, NewName |
| 15 (FileCreateStreamHash) | ProcessGuid, Image, TargetFilename, Hash, Contents |
| 16 (SysmonConfigChange) | Configuration, ConfigurationFileHash |
| 17 (PipeCreated) | ProcessGuid, Image, PipeName |
| 18 (PipeConnected) | ProcessGuid, Image, PipeName |
| 22 (DNSQuery) | ProcessGuid, Image, QueryName, QueryStatus, QueryResults |
| 23 (FileDelete) | ProcessGuid, Image, TargetFilename, Hashes, IsExecutable |
| 24 (ClipboardChange) | ProcessGuid, Image, Hashes |
| 25 (ProcessTampering) | ProcessGuid, Image, Type |
| 26 (FileDeleteDetected) | ProcessGuid, Image, TargetFilename, Hashes |
| 27 (FileBlockExecutable) | ProcessGuid, Image, TargetFilename, Hashes |
| 28 (FileBlockShredding) | ProcessGuid, Image, TargetFilename, Hashes |
| 29 (FileExecutableDetected) | ProcessGuid, Image, TargetFilename, Hashes |

---

## 4. Process Tree Construction Algorithm

Built exclusively from **EventId 1 (ProcessCreate)** records.

```
For each EventId=1 record:
  a. Create ProcessNode { guid, pid, image, command_line, parent_guid, ... }
  b. Insert into HashMap<ProcessGuid, ProcessNode>
  c. If parent exists in map → append child to parent.children
     Else → add to pending_children: HashMap<ParentGuid, Vec<ChildGuid>>
  d. Check if any pending_children match this new guid → attach them

After all records:
  - Remaining pending_children = orphan processes
  - Create synthetic "Unknown Parent" nodes for these

Roots = nodes whose parent_guid is absent from the node map
Sort roots and children by start_time
```

**Key invariants:**
- Always use `ProcessGuid` as the primary key — PIDs are reused.
- `pending_children` handles out-of-order events naturally.
- Synthetic nodes (from child's `ParentImage` / `ParentProcessId`) have `is_synthetic = true`.
- `end_time` is set when a matching EventId=5 (ProcessTerminate) is received.

---

## 5. Telemetry Correlation Model

### EventStore Design

```rust
EventStore {
    events: Vec<SysmonEvent>,                           // primary storage
    by_process: FxHashMap<ProcessGuid, Vec<usize>>,     // ProcessGuid → indices
    by_event_type: FxHashMap<u16, Vec<usize>>,          // EventId → indices
    by_target_process: FxHashMap<ProcessGuid, Vec<usize>>, // for EventId 8, 10
}
```

Cross-process events (EventId 8 CreateRemoteThread, 10 ProcessAccess) are indexed under both `by_process` (source) and `by_target_process` (target).

### Telemetry Categories

| Tab | Event IDs |
|-----|-----------|
| Overview | metadata + event counts |
| Network | 3, 22 |
| File Activity | 11, 15, 23, 26, 27, 28, 29 |
| Registry | 12, 13, 14 |
| Pipes | 17, 18 |
| Injection | 8, 10, 25 |
| Drivers/Modules | 6, 7 |
| Timeline | all |

---

## 6. Rust Data Structures

```rust
type ProcessGuid = [u8; 16];   // parsed from GUID string — compact, hashable
type Timestamp = chrono::DateTime<chrono::Utc>;

struct ProcessNode {
    guid: ProcessGuid,
    pid: u32,
    image: Spur,                      // interned with lasso
    image_name: Spur,
    command_line: Option<Spur>,
    parent_guid: Option<ProcessGuid>,
    parent_pid: Option<u32>,
    parent_image: Option<Spur>,
    parent_command_line: Option<Spur>,
    children: Vec<ProcessGuid>,
    start_time: Timestamp,
    end_time: Option<Timestamp>,
    user: Option<Spur>,
    hashes: Option<Spur>,
    integrity_level: Option<Spur>,
    logon_id: Option<String>,
    is_synthetic: bool,
    computer: Spur,
}

struct SysmonEvent {
    event_id: u16,
    event_type: SysmonEventType,
    time_created: Timestamp,
    record_number: u64,
    computer: Spur,
    process_guid: Option<ProcessGuid>,
    process_id: Option<u32>,
    image: Option<Spur>,
    user: Option<Spur>,
    rule_name: Option<String>,
    mitre_technique: Option<MitreTechnique>,
    detail: EventDetail,
}

enum EventDetail {
    ProcessCreate { command_line, hashes, parent_process_guid, parent_process_id,
                    parent_image, parent_command_line, parent_user, logon_id,
                    terminal_session_id, integrity_level, ... }
    NetworkConnect { protocol, initiated, source_ip, source_port, source_hostname,
                     destination_ip, destination_port, destination_hostname }
    FileCreate { target_filename, creation_utc_time }
    RegistryEvent { event_type, target_object, details, new_name }
    DnsQuery { query_name, query_status, query_results }
    PipeEvent { event_type, pipe_name }
    ProcessTerminate
    CreateRemoteThread { source_process_guid, source_image, target_process_guid,
                         target_image, start_address }
    ProcessAccess { source_process_guid, source_image, target_process_guid,
                    target_image, granted_access, call_trace }
    FileDeleteEvent { target_filename, hashes, is_executable }
    DriverLoad { image_loaded, hashes, signature, signature_status }
    ImageLoad { image_loaded, hashes, signature, signature_status }
    FileCreateStreamHash { target_filename, hash, contents }
    ProcessTampering { tampering_type }
    ClipboardChange { hashes }
    RawAccessRead { device }
    SysmonConfigChange { configuration, configuration_file_hash }
    Generic { fields: HashMap<String, String> }
}

struct MitreTechnique { id: String, name: String }
```

---

## 7. GUI Architecture

### Framework: egui via eframe

Immediate-mode GUI chosen for:
- Virtual scrolling performance at 1M+ events (no DOM overhead)
- Simple threading model (no separate UI thread)
- `egui_extras::TableBuilder` for virtual-scrolled columnar tables

### Layout

```
┌──────────────────────────────────────────────────────────────┐
│  Menu Bar (File | Help)                                      │
├──────────────┬───────────────────────────────────────────────┤
│              │  Tab Bar: Overview | Network | Files | Reg... │
│  Process     │ ┌───────────────────────────────────────────┐ │
│  Tree        │ │  Telemetry Detail Panel                   │ │
│  Panel       │ │  Virtual-scrolled table (event-specific)  │ │
│  (left)      │ └───────────────────────────────────────────┘ │
│              ├───────────────────────────────────────────────┤
│              │  Timeline Panel (bottom, collapsible)         │
├──────────────┴───────────────────────────────────────────────┤
│  Status Bar: filename | records | processes | progress bar   │
└──────────────────────────────────────────────────────────────┘
```

### Process Tree Features

- Expand/collapse with `egui::CollapsingState`
- Color coding: red = suspended/suspicious, yellow = terminated, green = normal
- Text filter at top (matches image name, PID, command line)
- Right-click context menu per node
- Selection drives all telemetry panels

### Telemetry Panel Pattern

All panels in `crates/systrace-gui/src/panels/` share a common pattern:

```rust
pub fn render_XXXX(
    ui: &mut egui::Ui,
    event_store: &EventStore,
    guid: ProcessGuid,
    tab: &mut TabState,
)
```

- Build row Vec → sort by `tab.sort_state` → render with `egui_extras::TableBuilder`
- `TableBuilder::sense(egui::Sense::click())` for row selection
- `row.set_selected(tab.selected_row == Some(i))` for highlight
- Apply `next_sort` / `next_selected` after table render (not during)

### Windows Platform

- Console window suppressed via `#![windows_subsystem = "windows"]`
- App icon (`icon.png`) embedded into `.exe` via `build.rs` (Windows-only, gated with `#[cfg(target_os = "windows")]`)

---

## 8. Performance Strategy

### Targets

- Load 1M events in < 10 seconds
- UI stays responsive during loading (< 16ms frame time)
- Tab switching for 100K-event process: < 100ms

### Key Optimizations

- **String interning** via `lasso::ThreadedRodeo` — Image paths, Computer names, UserNames deduplicated
- **ProcessGuid as `[u8; 16]`** — saves 20+ bytes per GUID vs String; used as FxHashMap key
- **FxHashMap** (`rustc-hash`) for all ProcessGuid-keyed maps
- **Batch channel sends** — 500 events per send; UI drains ≤ 20 batches/frame
- **All indices built at ingestion** — no on-demand scanning at query time
- **Virtual scrolling** everywhere — only visible rows rendered

---

## 9. Memory Management

For 1M events:
- Raw JSON line average: ~800 bytes
- Parsed SysmonEvent with interning: ~300–500 bytes
- Index overhead: ~50 bytes/event
- **Estimate: 400–550 MB for 1M events**

Optimizations applied:
1. **String interning** (lasso) — 30–50% savings on repeated strings
2. **ProcessGuid as `[u8; 16]`** — compact binary storage
3. **Raw payload dropped** after parsing — Payload JSON string not retained
4. **PayloadData1–6 dropped** — redundant with parsed fields

---

## 10. Crate Dependency Reference

| Category | Crate | Purpose |
|----------|-------|---------|
| GUI | `eframe` + `egui` | Application framework + immediate-mode GUI |
| GUI extras | `egui_extras` | Table widget with virtual scrolling |
| Serialization | `serde`, `serde_json` | JSON parsing for NDJSON path |
| DateTime | `chrono` | Timestamp parsing and formatting |
| Hashing | `rustc-hash` (FxHashMap) | Fast HashMap for ProcessGuid keys |
| String interning | `lasso` (ThreadedRodeo) | Deduplicate repeated strings |
| Logging | `tracing` | Structured logging |
| Error handling | `anyhow` + `thiserror` | App + library errors |
| File dialog | `rfd` | Native open-file dialog |
| CLI args | `clap` | Initial file path argument |
| Channels | `crossbeam-channel` | Parser → UI thread event streaming |
| GUID / UUID | `uuid` | UUID formatting in EVTX parser |

---

## 11. File Structure

```
SysTrace/
├── Cargo.toml                    (workspace root)
├── icon.png                      (app icon embedded in Windows .exe)
├── build.rs                      (Windows icon embedding, cfg-gated)
├── evtx/                         (test EVTX files)
│   └── Microsoft-Windows-Sysmon%4Operational.evtx
├── .claude/
│   ├── architecture.md           (this file)
│   ├── sysmon.json               (EVTXECmd NDJSON sample — smaller)
│   └── sysmon2.json              (EVTXECmd NDJSON reference — 3759 records)
├── crates/
│   ├── systrace-core/
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs            (public API re-exports)
│   │       ├── types.rs          (ProcessGuid, Timestamp, ParseError, parse_guid)
│   │       ├── event.rs          (SysmonEventType, SysmonEvent, EventDetail)
│   │       ├── parser.rs         (parse_file_auto, parse_file NDJSON, extract_event)
│   │       ├── process_tree.rs   (ProcessTree, ProcessNode, pending_children)
│   │       ├── event_store.rs    (EventStore, multi-key indices)
│   │       └── evtx/
│   │           └── mod.rs        (native EVTX binary parser, ~1100 lines)
│   └── systrace-gui/
│       ├── Cargo.toml
│       └── src/
│           ├── main.rs           (eframe entry point, clap CLI arg)
│           ├── app.rs            (SysTraceApp, eframe::App impl, loading pipeline)
│           ├── state.rs          (AppState, TelemetryTab, FileMetadata, tab states)
│           └── panels/
│               ├── mod.rs        (SortState, TabState, shared helpers)
│               ├── network.rs    (EventId 3, 22)
│               ├── file_activity.rs (EventId 11, 15, 23, 26–29)
│               ├── registry.rs   (EventId 12, 13, 14)
│               ├── pipes.rs      (EventId 17, 18)
│               ├── injection.rs  (EventId 8, 10, 25)
│               ├── drivers.rs    (EventId 6, 7)
│               ├── detection.rs  (MITRE/rule detections)
│               └── timeline.rs   (visual timeline)
```

---

## 12. Implementation Status

### Phase 1 — Core Engine ✅ Complete
- All data structures implemented and tested
- NDJSON streaming parser with two-phase payload parsing
- ProcessTree with out-of-order event handling
- EventStore with multi-key indexing
- 22+ unit + integration tests pass

### Phase 2 — Basic GUI ✅ Complete
- eframe application with file open dialog (rfd)
- Process tree panel: expand/collapse, filter, color coding
- Overview tab: full process metadata + event summary grid
- Background loading pipeline with progress bar
- Status bar: filename, record count, process count, progress
- Windows: console suppressed, icon embedded in exe

### Phase 3 — Telemetry Panels ✅ Complete
- Network, File Activity, Registry, Pipes, Injection, Drivers/Modules panels
- All panels: sortable columns, row selection, virtual scrolling
- Cross-process indexing for EventId 8/10

### Phase 4 — Native EVTX Parser ✅ Complete
- Pure Rust EVTX binary parser (no EVTXECmd dependency)
- Handles BinXml opcodes, template instances, substitution arrays
- Auto-detection by magic bytes (`parse_file_auto`)
- Verified: 3738 records from test EVTX, field values match EVTXECmd output exactly
- 30 tests pass (19 unit + 11 integration)

### Phase 5 — Advanced Features (Future)
- [ ] Timeline visualization (panel stub exists)
- [ ] Sigma rule detection
- [ ] Threat hunting query DSL
- [ ] Multi-host support (Computer field already indexed)
- [ ] Export to CSV/JSON/DOT
- [ ] MITRE ATT&CK annotations
- [ ] Process tree search highlighting
- [ ] Keyboard navigation
