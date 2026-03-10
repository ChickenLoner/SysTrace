# SysTrace Architecture Document

## 1. System Architecture

### Overview

SysTrace is a Rust-based GUI forensic analysis tool that ingests EVTXECmd JSON exports of Sysmon operational logs, constructs a process tree, and provides process-centric telemetry browsing for DFIR investigators.

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
│  │ Parser       │  │ Correlation  │  │ Index Engine       │ │
│  │ (streaming)  │  │ Engine       │  │ (multi-key)        │ │
│  └──────────────┘  └──────────────┘  └────────────────────┘ │
├──────────────────────────────────────────────────────────────┤
│                    Data Ingestion Layer                       │
│  ┌──────────────────────────────────────────────────────────┐│
│  │  Streaming NDJSON Reader (line-by-line, memory-bounded)  ││
│  └──────────────────────────────────────────────────────────┘│
└──────────────────────────────────────────────────────────────┘
```

### Layered Architecture

- **Data Ingestion Layer**: Reads NDJSON files line-by-line, yields raw JSON values.
- **Core Engine Layer**: Parses each JSON line into typed `SysmonEvent`, builds the process tree, indexes events.
- **Application State Layer**: Owns the `ProcessTree`, `EventStore`, and UI selection state. Provides query APIs.
- **GUI Layer**: Renders the process tree, telemetry panels, and timeline. Reads from application state, never mutates core data.

### Threading Model

```
Main Thread:   GUI rendering loop (egui)
Background:    File ingestion + parsing (spawned via std::thread or rayon)
Communication: crossbeam-channel or std::sync::mpsc for streaming parsed events to main thread
```

Ingestion runs on a background thread. Parsed events are sent via a bounded channel to the main thread, which inserts them into the `EventStore` and `ProcessTree` incrementally. This keeps the UI responsive during large file loads.

---

## 2. Data Ingestion Pipeline

### Input Format

EVTXECmd outputs **NDJSON** (Newline-Delimited JSON) where each line is a self-contained JSON object. The file can be gigabytes in size.

### Pipeline Stages

```
File on Disk
    │
    ▼
BufReader (8KB–64KB buffer)
    │
    ▼
Line Iterator (.lines())
    │
    ▼
serde_json::from_str() per line → RawEvtxRecord
    │
    ▼
Payload extraction: parse Payload string → EventData
    │
    ▼
Field extraction from EventData.Data[] array
    │
    ▼
Typed SysmonEvent construction
    │
    ▼
Send over channel → Main thread
    │
    ▼
Insert into EventStore + ProcessTree
```

### Streaming Design

- Use `std::io::BufReader` wrapping `std::fs::File`.
- Read line-by-line — never load the whole file.
- Batch parsed events (e.g., 1000 at a time) before sending over the channel to reduce synchronization overhead.
- Report progress via an atomic counter (total bytes read / file size).

### Error Handling

- Malformed lines are logged and skipped (with line number).
- Missing fields within a record produce a partial event with `Option<T>` fields.
- A separate `Vec<ParseError>` collects issues for the user to review.

---

## 3. Event Parsing Design

### EVTXECmd JSON Structure

Each record has two layers of useful data:

**Layer 1 — Top-level fields (from EVTXECmd):**
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
      { "@Name": "Image", "#text": "C:\\...\\firefox.exe" },
      ...
    ]
  }
}
```

### Two-Phase Parse Strategy

**Phase 1: Deserialize top-level record**

```rust
struct RawEvtxRecord {
    #[serde(rename = "EventId")]
    event_id: u16,
    #[serde(rename = "TimeCreated")]
    time_created: String,
    #[serde(rename = "RecordNumber")]
    record_number: u64,
    #[serde(rename = "Payload")]
    payload: String,               // raw JSON string — parsed in phase 2
    #[serde(rename = "Computer")]
    computer: String,
    #[serde(rename = "UserName")]
    user_name: Option<String>,
    #[serde(rename = "MapDescription")]
    map_description: Option<String>,
    #[serde(rename = "ExecutableInfo")]
    executable_info: Option<String>,
    // PayloadData1..6 as Option<String>
}
```

**Phase 2: Parse the Payload string**

The Payload field is a JSON string that must be parsed separately. The inner `EventData.Data` is an array of `{@Name, #text}` objects.

```rust
struct PayloadWrapper {
    #[serde(rename = "EventData")]
    event_data: EventDataWrapper,
}

struct EventDataWrapper {
    #[serde(rename = "Data")]
    data: Vec<DataField>,
}

struct DataField {
    #[serde(rename = "@Name")]
    name: String,
    #[serde(rename = "#text")]
    text: Option<String>,
}
```

Convert `Vec<DataField>` into a `HashMap<String, String>` for O(1) field access by name.

**Phase 3: Extract typed fields based on EventId**

Use the EventId to determine which fields to extract from the HashMap. For example, EventId 1 (ProcessCreate) requires: ProcessGuid, ParentProcessGuid, ParentProcessId, Image, CommandLine, Hashes, User, etc.

### Field Extraction Per Event Type

| EventId | Key Fields to Extract |
|---------|----------------------|
| 1  (ProcessCreate) | ProcessGuid, ProcessId, Image, CommandLine, ParentProcessGuid, ParentProcessId, ParentImage, ParentCommandLine, Hashes, User, LogonId, IntegrityLevel |
| 3  (NetworkConnect) | ProcessGuid, ProcessId, Image, Protocol, Initiated, SourceIp, SourcePort, DestinationIp, DestinationPort, DestinationHostname |
| 5  (ProcessTerminate) | ProcessGuid, ProcessId, Image |
| 6  (DriverLoad) | ProcessGuid, ImageLoaded, Hashes, Signature, SignatureStatus |
| 7  (ImageLoad) | ProcessGuid, ProcessId, Image, ImageLoaded, Hashes, Signature, SignatureStatus |
| 8  (CreateRemoteThread) | SourceProcessGuid, SourceProcessId, SourceImage, TargetProcessGuid, TargetProcessId, TargetImage, StartAddress |
| 9  (RawAccessRead) | ProcessGuid, ProcessId, Image, Device |
| 10 (ProcessAccess) | SourceProcessGuid, SourceProcessId, SourceImage, TargetProcessGuid, TargetProcessId, TargetImage, GrantedAccess, CallTrace |
| 11 (FileCreate) | ProcessGuid, ProcessId, Image, TargetFilename, CreationUtcTime |
| 12 (RegistryCreate/Delete) | ProcessGuid, ProcessId, Image, EventType, TargetObject |
| 13 (RegistryValueSet) | ProcessGuid, ProcessId, Image, EventType, TargetObject, Details |
| 14 (RegistryRename) | ProcessGuid, ProcessId, Image, EventType, TargetObject, NewName |
| 15 (FileCreateStreamHash) | ProcessGuid, ProcessId, Image, TargetFilename, Hash, Contents |
| 16 (SysmonConfigChange) | Configuration, ConfigurationFileHash |
| 17 (PipeCreated) | ProcessGuid, ProcessId, PipeName, Image |
| 18 (PipeConnected) | ProcessGuid, ProcessId, PipeName, Image |
| 22 (DNSQuery) | ProcessGuid, ProcessId, Image, QueryName, QueryStatus, QueryResults |
| 23 (FileDelete) | ProcessGuid, ProcessId, Image, TargetFilename, Hashes, IsExecutable |
| 24 (ClipboardChange) | ProcessGuid, ProcessId, Image, Hashes |
| 25 (ProcessTampering) | ProcessGuid, ProcessId, Image, Type |
| 26 (FileDeleteDetected) | ProcessGuid, ProcessId, Image, TargetFilename, Hashes |
| 27 (FileBlockExecutable) | ProcessGuid, ProcessId, Image, TargetFilename, Hashes |
| 28 (FileBlockShredding) | ProcessGuid, ProcessId, Image, TargetFilename, Hashes |
| 29 (FileExecutableDetected) | ProcessGuid, ProcessId, Image, TargetFilename, Hashes |

### RuleName Parsing

The `RuleName` field sometimes contains MITRE ATT&CK technique references:
```
technique_id=T1189,technique_name=Drive-by Compromise
```

Parse this into an optional `MitreTechnique { id: String, name: String }` struct when present.

---

## 4. Process Tree Construction Algorithm

### Data Sources

The process tree is built exclusively from **Event ID 1 (ProcessCreate)** records. Other events reference processes but don't define parent-child relationships.

### Algorithm

```
1. For each EventId=1 record:
   a. Extract ProcessGuid, ProcessId, Image, CommandLine,
      ParentProcessGuid, ParentProcessId, ParentImage, ParentCommandLine
   b. Create ProcessNode {
        guid: ProcessGuid,
        pid: ProcessId,
        image: Image,
        command_line: CommandLine,
        parent_guid: ParentProcessGuid,
        parent_pid: ParentProcessId,
        parent_image: ParentImage,
        children: Vec<ProcessGuid>,
        start_time: TimeCreated,
        end_time: Option (filled by EventId=5),
        user: User,
        hashes: Hashes,
        integrity_level: IntegrityLevel,
      }
   c. Insert into HashMap<ProcessGuid, ProcessNode>
   d. If ParentProcessGuid exists in the map:
        → append this node's guid to parent's children
      Else:
        → add to pending_children: HashMap<ParentGuid, Vec<ChildGuid>>
   e. Check if any pending_children entries match this new node's guid
        → if so, attach them

2. After all EventId=1 records are processed:
   - Any remaining entries in pending_children represent orphan processes
     whose parents were not observed in the logs.
   - Create synthetic "Unknown Parent" placeholder nodes for these,
     or attach them to a virtual root.

3. Build display roots:
   - Roots = nodes whose ParentProcessGuid is not in the node map
   - Sort roots and children by start_time
```

### Handling Edge Cases

**Out-of-order events:** The pending_children map handles children arriving before parents. When the parent eventually appears, pending children are re-parented.

**Reused PIDs:** ProcessGuid is globally unique per Sysmon session (includes machine GUID + timestamp), so PID reuse is not ambiguous. Always use ProcessGuid as the primary key, never bare PID.

**Missing parent events:** If a parent process started before Sysmon began logging, we'll see child ProcessCreate events referencing a ParentProcessGuid that never appears. Create a synthetic node using ParentImage + ParentProcessId from the child's record.

**ProcessTerminate (EventId=5):** When received, set `end_time` on the matching ProcessNode. This allows the UI to show process lifetime.

### Incremental Construction

The tree must support incremental insertion as events stream in during file loading. The `HashMap<ProcessGuid, ProcessNode>` + `pending_children` approach supports this naturally — no need to rebuild the tree.

---

## 5. Telemetry Correlation Model

### Core Principle

Every Sysmon event (except EventId 4 and 16) contains a `ProcessGuid` field. This is the primary correlation key.

### EventStore Design

```
EventStore {
    // Primary storage: all events in insertion order
    events: Vec<SysmonEvent>,

    // Index: ProcessGuid → list of event indices
    by_process: HashMap<String, Vec<usize>>,

    // Index: EventId → list of event indices
    by_event_type: HashMap<u16, Vec<usize>>,

    // Index: Time-sorted index (for timeline)
    by_time: BTreeMap<DateTime, Vec<usize>>,
}
```

### Query Patterns

When user selects a process node:

1. **Get all events for process:** `by_process.get(guid)` → yields indices into `events` Vec.
2. **Filter by event type:** Intersect `by_process[guid]` with `by_event_type[event_id]`.
3. **Timeline view:** Iterate `by_process[guid]` indices, they're already time-sorted if inserted in file order (which is generally chronological).

### Cross-Process Correlation

Some events reference two processes:

- **EventId 8 (CreateRemoteThread):** SourceProcessGuid → TargetProcessGuid
- **EventId 10 (ProcessAccess):** SourceProcessGuid → TargetProcessGuid

These must be indexed under BOTH process GUIDs. Add a `secondary_process_guid` field and index it.

### Telemetry Categories

Group events into forensic categories for the tabbed UI:

| Category | Event IDs |
|----------|-----------|
| Process Lifecycle | 1, 5 |
| Network | 3, 22 |
| File Activity | 11, 15, 23, 26, 27, 28, 29 |
| Registry | 12, 13, 14 |
| Process Injection | 8, 10, 25 |
| Named Pipes | 17, 18 |
| Drivers/Modules | 6, 7 |
| Other | 9, 16, 24 |

---

## 6. Rust Data Structures

### Core Types

```rust
/// Unique process identifier from Sysmon
type ProcessGuid = String; // e.g., "817bddf3-3514-65cc-0802-000000001900"

/// Parsed timestamp
type Timestamp = chrono::DateTime<chrono::Utc>;

/// A node in the process tree
struct ProcessNode {
    guid: ProcessGuid,
    pid: u32,
    image: String,                    // full path e.g. "C:\Windows\system32\svchost.exe"
    image_name: String,               // just filename e.g. "svchost.exe"
    command_line: Option<String>,
    parent_guid: Option<ProcessGuid>,
    parent_pid: Option<u32>,
    parent_image: Option<String>,
    parent_command_line: Option<String>,
    children: Vec<ProcessGuid>,       // ordered by start_time
    start_time: Timestamp,
    end_time: Option<Timestamp>,      // set by EventId 5
    user: Option<String>,
    hashes: Option<String>,           // raw hash string
    integrity_level: Option<String>,
    logon_id: Option<String>,
    is_synthetic: bool,               // true if created from child's parent info
    computer: String,
}

/// The full process tree
struct ProcessTree {
    nodes: HashMap<ProcessGuid, ProcessNode>,
    roots: Vec<ProcessGuid>,          // top-level processes (no observed parent)
    pending_children: HashMap<ProcessGuid, Vec<ProcessGuid>>,
}

/// Sysmon event types (all 29)
enum SysmonEventType {
    ProcessCreate,         // 1
    FileCreateTime,        // 2
    NetworkConnect,        // 3
    SysmonServiceState,    // 4
    ProcessTerminate,      // 5
    DriverLoad,            // 6
    ImageLoad,             // 7
    CreateRemoteThread,    // 8
    RawAccessRead,         // 9
    ProcessAccess,         // 10
    FileCreate,            // 11
    RegistryCreateDelete,  // 12
    RegistryValueSet,      // 13
    RegistryRename,        // 14
    FileCreateStreamHash,  // 15
    SysmonConfigChange,    // 16
    PipeCreated,           // 17
    PipeConnected,         // 18
    WmiFilter,             // 19
    WmiConsumer,           // 20
    WmiBinding,            // 21
    DnsQuery,              // 22
    FileDelete,            // 23
    ClipboardChange,       // 24
    ProcessTampering,      // 25
    FileDeleteDetected,    // 26
    FileBlockExecutable,   // 27
    FileBlockShredding,    // 28
    FileExecutableDetected,// 29
}

/// A parsed Sysmon event with common + type-specific fields
struct SysmonEvent {
    // Common fields (present in all events)
    event_id: u16,
    event_type: SysmonEventType,
    time_created: Timestamp,
    record_number: u64,
    computer: String,
    process_guid: Option<ProcessGuid>,
    process_id: Option<u32>,
    image: Option<String>,
    user: Option<String>,
    rule_name: Option<String>,
    mitre_technique: Option<MitreTechnique>,

    // Type-specific fields stored as an enum variant
    detail: EventDetail,
}

/// Type-specific event details
enum EventDetail {
    ProcessCreate {
        command_line: String,
        current_directory: Option<String>,
        hashes: Option<String>,
        parent_process_guid: Option<ProcessGuid>,
        parent_process_id: Option<u32>,
        parent_image: Option<String>,
        parent_command_line: Option<String>,
        parent_user: Option<String>,
        logon_guid: Option<String>,
        logon_id: Option<String>,
        terminal_session_id: Option<u32>,
        integrity_level: Option<String>,
        file_version: Option<String>,
        description: Option<String>,
        product: Option<String>,
        company: Option<String>,
        original_file_name: Option<String>,
    },
    NetworkConnect {
        protocol: String,
        initiated: bool,
        source_ip: String,
        source_port: u16,
        source_hostname: Option<String>,
        destination_ip: String,
        destination_port: u16,
        destination_hostname: Option<String>,
    },
    FileCreate {
        target_filename: String,
        creation_utc_time: Option<String>,
    },
    RegistryEvent {
        event_type: String,      // SetValue, CreateKey, DeleteKey, RenameKey
        target_object: String,
        details: Option<String>,
        new_name: Option<String>,
    },
    DnsQuery {
        query_name: String,
        query_status: Option<String>,
        query_results: Option<String>,
    },
    PipeEvent {
        event_type: String,      // CreatePipe, ConnectPipe
        pipe_name: String,
    },
    ProcessTerminate,
    CreateRemoteThread {
        source_process_guid: Option<ProcessGuid>,
        source_process_id: Option<u32>,
        source_image: Option<String>,
        target_process_guid: Option<ProcessGuid>,
        target_process_id: Option<u32>,
        target_image: Option<String>,
        start_address: Option<String>,
    },
    ProcessAccess {
        source_process_guid: Option<ProcessGuid>,
        source_process_id: Option<u32>,
        source_image: Option<String>,
        target_process_guid: Option<ProcessGuid>,
        target_process_id: Option<u32>,
        target_image: Option<String>,
        granted_access: Option<String>,
        call_trace: Option<String>,
    },
    FileDeleteEvent {
        target_filename: String,
        hashes: Option<String>,
        is_executable: Option<bool>,
    },
    DriverLoad {
        image_loaded: Option<String>,
        hashes: Option<String>,
        signature: Option<String>,
        signature_status: Option<String>,
    },
    ImageLoad {
        image_loaded: Option<String>,
        hashes: Option<String>,
        signature: Option<String>,
        signature_status: Option<String>,
    },
    FileCreateStreamHash {
        target_filename: String,
        hash: Option<String>,
        contents: Option<String>,
    },
    ProcessTampering {
        tampering_type: Option<String>,
    },
    ClipboardChange {
        hashes: Option<String>,
    },
    RawAccessRead {
        device: Option<String>,
    },
    SysmonConfigChange {
        configuration: Option<String>,
        configuration_file_hash: Option<String>,
    },
    /// Fallback for unrecognized or rare event types
    Generic {
        fields: HashMap<String, String>,
    },
}

struct MitreTechnique {
    id: String,       // e.g. "T1189"
    name: String,     // e.g. "Drive-by Compromise"
}

/// Multi-index event store
struct EventStore {
    events: Vec<SysmonEvent>,
    by_process: HashMap<ProcessGuid, Vec<usize>>,
    by_event_type: HashMap<u16, Vec<usize>>,
    // For cross-process events (EventId 8, 10): secondary process index
    by_target_process: HashMap<ProcessGuid, Vec<usize>>,
}

/// Application state
struct AppState {
    process_tree: ProcessTree,
    event_store: EventStore,
    selected_process: Option<ProcessGuid>,
    active_tab: TelemetryTab,
    search_filter: String,
    loading_progress: Option<f32>,   // 0.0 to 1.0 during file load
    parse_errors: Vec<ParseError>,
    file_metadata: Option<FileMetadata>,
}

struct FileMetadata {
    path: String,
    total_records: u64,
    unique_processes: usize,
    event_type_counts: HashMap<u16, usize>,
    time_range: Option<(Timestamp, Timestamp)>,
    computer_names: HashSet<String>,
}

enum TelemetryTab {
    Overview,
    Network,
    FileActivity,
    Registry,
    Pipes,
    Injection,
    DriversModules,
    Timeline,
}
```

---

## 7. GUI Architecture

### Framework Decision: egui (via eframe)

**Recommendation: egui** with `eframe` backend.

**Rationale:**

| Criterion | egui | iced | slint | tauri |
|-----------|------|------|-------|-------|
| Pure Rust | Yes | Yes | Partial (DSL) | No (web UI) |
| Immediate mode | Yes | No (Elm) | No (declarative) | No |
| GPU accelerated | Yes (wgpu/glow) | Yes | Yes | Depends |
| Tree widget | egui_extras / custom | Manual | Manual | Easy (HTML) |
| Large dataset perf | Excellent (virtual scroll) | Good | Good | DOM overhead |
| Learning curve | Low | Medium | Medium | High (two stacks) |
| Cross-platform | Win/Mac/Linux | Win/Mac/Linux | Win/Mac/Linux | Win/Mac/Linux |
| Ecosystem maturity | Strong | Growing | Growing | Strong |

egui wins because:
1. **Immediate mode** is ideal for data-driven UIs where content changes based on selection — no need to manage widget state.
2. **Virtual scrolling** is natural — only render visible rows. Critical for millions of events.
3. **No separate UI thread** — simplifies the architecture.
4. **`egui_extras::TableBuilder`** provides efficient columnar display with virtual scrolling built-in.
5. **Strong community** with extensive examples for tree views and data tables.

**Alternatives considered:**
- **tauri + web UI**: Better for polish/aesthetics, but DOM overhead is a problem at 1M+ events. Two-language stack adds complexity. Could be a future option if a web-based version is wanted.
- **iced**: Elm architecture is elegant but requires more boilerplate for this use case. Tree widget would need to be built from scratch.

### Layout Design

```
┌──────────────────────────────────────────────────────────────┐
│  Menu Bar: File | View | Filter | Tools | Help               │
├──────────────┬───────────────────────────────────────────────┤
│              │  Tab Bar: Overview | Network | Files | Reg... │
│  Process     │ ┌───────────────────────────────────────────┐ │
│  Tree        │ │                                           │ │
│  Panel       │ │  Telemetry Detail Panel                   │ │
│              │ │  (table/list of events for selected tab)  │ │
│  [Scrollable │ │                                           │ │
│   tree with  │ │  Virtual-scrolled table with columns      │ │
│   expand/    │ │  appropriate to the event type            │ │
│   collapse]  │ │                                           │ │
│              │ └───────────────────────────────────────────┘ │
│              ├───────────────────────────────────────────────┤
│              │  Timeline Panel (bottom)                      │
│              │  ┌───────────────────────────────────────┐    │
│              │  │ ──●──●────●──●●●──────●──●──────●──── │    │
│              │  │  t0                              tN   │    │
│              │  └───────────────────────────────────────┘    │
├──────────────┴───────────────────────────────────────────────┤
│  Status Bar: Records: 245,000 | Processes: 1,234 | Loaded   │
└──────────────────────────────────────────────────────────────┘
```

### Panel Widths

- Process Tree: ~25-30% of window width, resizable via drag handle
- Telemetry Panel: remaining width
- Timeline: ~15-20% of window height, collapsible
- All panels use `egui::SidePanel`, `egui::CentralPanel`, `egui::TopBottomPanel`

### Process Tree Rendering

Use a recursive function with indentation:

```
fn render_tree_node(ui, tree, guid, depth):
    let node = tree.nodes[guid]
    let response = ui.collapsing_header(format_node_label(node)):
        for child_guid in node.children:
            render_tree_node(ui, tree, child_guid, depth + 1)
    if response.clicked():
        select_process(guid)
```

For large trees (10,000+ processes), use virtual scrolling by pre-computing a flattened visible node list:

1. Walk the tree respecting expand/collapse state → produce `Vec<(depth, guid)>` of visible nodes.
2. Use `egui_extras::TableBuilder` with row height and scroll offset to only render visible rows.
3. Cache the flattened list; invalidate only when expand/collapse state changes.

### Telemetry Panel Rendering

Each tab renders a filtered view of events:

- **Overview tab:** Process metadata (image, command line, hashes, user, integrity, start/end time, parent info). Plus summary counts per event type.
- **Network tab:** Table with columns: Time, Direction, Protocol, Source IP:Port, Dest IP:Port, Hostname. Covers EventId 3 + 22.
- **File Activity tab:** Table with columns: Time, Action (Create/Delete/Stream), Target Filename, Hashes. Covers EventId 11, 15, 23, 26, 27, 28, 29.
- **Registry tab:** Table with columns: Time, Action (Create/Set/Delete/Rename), Target Object, Details. Covers EventId 12, 13, 14.
- **Pipes tab:** Table with columns: Time, Action (Create/Connect), Pipe Name. Covers EventId 17, 18.
- **Injection tab:** Table with columns: Time, Type, Source Process, Target Process, Details. Covers EventId 8, 10, 25.
- **Drivers/Modules tab:** Table with columns: Time, Image Loaded, Signature, Status. Covers EventId 6, 7.
- **Timeline tab:** Visual timeline (described in section 9).

---

## 8. Performance Strategy

### Target Performance

- Load 1M events in < 10 seconds
- UI stays responsive during loading (< 16ms frame time)
- Process tree expand/collapse: instant
- Tab switching with 100K events for a process: < 100ms

### Parsing Performance

- **serde_json** for initial deserialization — well-optimized for this use case.
- **simd-json** as optional drop-in for 2-4x faster parsing on x86_64. Benchmark both during development. `simd-json` is a serde-compatible drop-in, so switching is trivial.
- **Pre-allocate** the `events` Vec with estimated capacity (file_size / avg_line_size).
- **String interning** for repeated values: Image paths, Computer names, UserNames. Use a `StringInterner` (lasso crate) to deduplicate. Many events share the same Image path — this can save 30-50% memory on string data.

### Rendering Performance

- **Virtual scrolling** everywhere — never render off-screen rows.
- **Pre-computed flattened tree** for the process tree panel.
- **Lazy event filtering** — when switching tabs, filter `by_process[guid]` indices by event type. This is a Vec intersection, not a full scan.
- **Frame budget** — if filtering takes > 5ms, paginate results and load incrementally.

### Indexing Performance

- All indices are built during ingestion, not on-demand.
- `HashMap` with `FxHashMap` (from `rustc-hash`) for faster hashing on short string keys like ProcessGuid.

---

## 9. Memory Management Strategy

### Memory Budget Estimation

For 1M events:
- Average raw JSON line: ~800 bytes
- Parsed SysmonEvent: ~300-500 bytes (with string interning)
- Indices overhead: ~50 bytes per event
- **Total estimate: ~400-550 MB for 1M events**

### Optimization Strategies

1. **String Interning (lasso crate)**
   - Intern: Image paths, Computer names, UserName, common TargetObject prefixes
   - Don't intern: unique values like ProcessGuid, timestamps, full file paths in TargetFilename
   - Expected savings: 30-50% on string allocations

2. **Compact String Representations**
   - Use `compact_str` or `SmolStr` for short strings (< 24 bytes stored inline, no heap allocation)
   - ProcessGuid is 36 chars — store as `[u8; 16]` by parsing the GUID hex, saving 20 bytes per GUID field

3. **Drop Raw Data**
   - Don't store the raw Payload JSON string after parsing
   - Don't store PayloadData1-6 (redundant with parsed fields)
   - Don't store fields unused by the UI (ExtraDataOffset, HiddenRecord, ChunkNumber, etc.)

4. **Arena Allocation**
   - Consider `bumpalo` for batch-allocating event structs during parsing
   - Events are append-only (never deleted individually), making arena allocation ideal

5. **Memory-Mapped Files (Future)**
   - For extremely large datasets (10M+ events), consider memory-mapping the source file and lazily parsing on demand.
   - Store only indices and process tree in memory; re-parse event details when accessed.
   - This is a Phase 3 optimization — not needed for MVP.

### ProcessGuid Optimization

ProcessGuid format: `817bddf3-3514-65cc-0802-000000001900` (standard GUID format)

Parse into `[u8; 16]` (128 bits) instead of storing as 36-char String:
- Saves 20+ bytes per occurrence
- Each event has 1-2 GUIDs → saves 20-40 bytes × 1M events = 20-40 MB
- Use as HashMap key via the 128-bit representation

---

## 10. Visualization Design

### Process Tree

**Visual Design:**
- Each node shows: icon (based on image name) + image_name + PID
- Expanded node tooltip: full path, command line, user, start time
- Color coding:
  - Red: processes with suspicious indicators (high event count, injection targets)
  - Yellow: terminated processes
  - Green: system processes (svchost.exe, etc.)
  - White/Default: normal processes
- Expand/collapse triangles with click
- Right-click context menu: Copy GUID, Copy command line, Expand all children

**Search/Filter:**
- Text filter at top of tree panel
- Filters by image name, PID, command line, user
- Matching nodes highlighted; non-matching branches collapsed

### Timeline View

**Visual Design:**
- Horizontal time axis spanning the time range of the selected process
- Event dots/markers plotted on the timeline
- Color-coded by event type category (network=blue, file=green, registry=orange, injection=red)
- Hover on dot shows event summary tooltip
- Click on dot scrolls to that event in the detail panel
- Zoom via mouse wheel; pan via click-drag
- Mini-map showing full time range with viewport indicator

**Implementation:**
- Use egui's `Painter` API for custom drawing
- Pre-compute pixel positions from timestamps
- Bucket events into visible pixel columns to avoid overdraw (if 1000 events map to same pixel, show a single tall marker with count tooltip)

### Event Detail Tables

- Use `egui_extras::TableBuilder` with:
  - Sortable columns (click header to sort)
  - Resizable columns
  - Virtual scrolling (only render visible rows)
  - Row selection with highlight
  - Copy cell/row to clipboard on right-click

### Filtering

- Global text search across all visible fields
- Per-column filters (dropdown or text)
- Time range filter (slider or date picker)
- Event type checkboxes to include/exclude

---

## 11. Extensibility Design

### Plugin Architecture (Future)

Design core interfaces as traits to allow future extension:

```rust
trait EventAnalyzer {
    fn name(&self) -> &str;
    fn analyze(&self, event: &SysmonEvent, context: &AnalysisContext) -> Vec<Finding>;
}

trait EventFilter {
    fn name(&self) -> &str;
    fn matches(&self, event: &SysmonEvent) -> bool;
}

struct Finding {
    severity: Severity,
    title: String,
    description: String,
    mitre_id: Option<String>,
    related_events: Vec<usize>,
}
```

### Sigma Rule Detection (Future Phase)

- Parse Sigma YAML rules into `EventFilter` implementations
- Run filters against EventStore during/after ingestion
- Display findings as annotations on process tree and timeline
- Crate: parse Sigma YAML with `serde_yaml`

### Threat Hunting Queries (Future Phase)

- Simple query DSL: `image contains "powershell" AND event_type = NetworkConnect AND destination_port = 443`
- Parse with `pest` or `nom`
- Execute against EventStore indices

### Multi-Host Support (Future Phase)

- `Computer` field already parsed on every event
- Group process trees by Computer name
- Tab or dropdown to switch between hosts
- Cross-host timeline correlation

### Export (Future Phase)

- Timeline export to CSV/JSON
- Process tree export to DOT (Graphviz)
- Selected events export to STIX/OpenIOC
- Report generation (HTML)

---

## 12. Suggested Rust Crates

| Category | Crate | Purpose |
|----------|-------|---------|
| GUI | `eframe` + `egui` | Application framework + immediate-mode GUI |
| GUI extras | `egui_extras` | Table widget with virtual scrolling |
| Serialization | `serde`, `serde_json` | JSON parsing |
| Fast JSON (opt) | `simd-json` | SIMD-accelerated JSON parsing |
| DateTime | `chrono` | Timestamp parsing and formatting |
| Hashing | `rustc-hash` (FxHashMap) | Fast HashMap for string keys |
| String interning | `lasso` | Deduplicate repeated strings |
| Compact strings | `compact_str` or `smol_str` | Small-string optimization |
| Logging | `tracing` | Structured logging for debugging |
| Error handling | `anyhow` + `thiserror` | Application + library errors |
| File dialog | `rfd` (Rusty File Dialogs) | Native open-file dialog |
| CLI args | `clap` | Optional CLI argument parsing |
| Async channels | `crossbeam-channel` | Communication between parser and UI threads |
| GUID parsing | `uuid` | Parse ProcessGuid into 128-bit representation |

---

## 13. Development Phases

### Phase 1: Core Engine (Foundation)

**Goal:** Parse EVTXECmd JSON, build process tree, store indexed events.

- [ ] Project setup: Cargo workspace, dependencies
- [ ] Define all data structures (ProcessNode, SysmonEvent, EventDetail, EventStore, ProcessTree)
- [ ] Implement NDJSON streaming parser
- [ ] Implement Payload (inner JSON) parser with field extraction per EventId
- [ ] Implement ProcessTree construction from EventId=1
- [ ] Implement EventStore with multi-key indexing
- [ ] Unit tests with sample data from `.claude/sysmon.json`
- [ ] Benchmark: parse the sample file, measure time and memory

**Deliverable:** A library crate (`systrace-core`) that can ingest a file and produce a queryable ProcessTree + EventStore.

### Phase 2: Basic GUI

**Goal:** Display process tree and basic telemetry.

- [ ] Set up eframe application scaffold
- [ ] Implement process tree panel with expand/collapse
- [ ] Implement process selection → display Overview tab (metadata)
- [ ] Implement file open dialog
- [ ] Background loading with progress bar
- [ ] Status bar with record/process counts

**Deliverable:** A working GUI that loads a file, shows the process tree, and displays process metadata on click.

### Phase 3: Full Telemetry Panels

**Goal:** All telemetry tabs with virtual-scrolled tables.

- [ ] Network tab (EventId 3, 22)
- [ ] File Activity tab (EventId 11, 15, 23, 26, 27, 28, 29)
- [ ] Registry tab (EventId 12, 13, 14)
- [ ] Pipes tab (EventId 17, 18)
- [ ] Injection tab (EventId 8, 10, 25)
- [ ] Drivers/Modules tab (EventId 6, 7)
- [ ] Column sorting in all tables
- [ ] Copy-to-clipboard support

**Deliverable:** Fully functional telemetry browsing for all Sysmon event types.

### Phase 4: Timeline & Polish

**Goal:** Timeline visualization, filtering, UX polish.

- [ ] Timeline view with custom egui painting
- [ ] Timeline zoom/pan
- [ ] Global search/filter
- [ ] Process tree search
- [ ] Color coding for process tree nodes
- [ ] Keyboard navigation (up/down in tree, tab switching)
- [ ] Performance optimization for 1M+ events (string interning, GUID compaction)

**Deliverable:** A polished, performant forensic analysis tool.

### Phase 5: Advanced Features (Future)

- [ ] Sigma rule detection
- [ ] Threat hunting query DSL
- [ ] Multi-host support
- [ ] Export to CSV/JSON/DOT
- [ ] MITRE ATT&CK annotations on timeline
- [ ] Bookmarking / notes on processes
- [ ] Dark/light theme

---

## Appendix A: EVTXECmd JSON Field Reference

### Top-Level Fields (always present)

| Field | Type | Description |
|-------|------|-------------|
| EventId | u16 | Sysmon event type (1-29) |
| TimeCreated | String (ISO 8601) | When the event was recorded |
| RecordNumber | u64 | Sequential record number |
| Computer | String | Machine hostname |
| Channel | String | Always "Microsoft-Windows-Sysmon/Operational" |
| Provider | String | Always "Microsoft-Windows-Sysmon" |
| Payload | String | Inner JSON containing EventData |
| Level | String | "Info", "Warning", etc. |
| ProcessId | u32 | Sysmon service PID (NOT the monitored process) |
| ThreadId | u32 | Sysmon service thread |

### Top-Level Fields (sometimes present)

| Field | Type | Description |
|-------|------|-------------|
| PayloadData1..6 | String | Pre-extracted summary fields from EVTXECmd |
| UserName | String | User context |
| MapDescription | String | Human-readable event type name |
| ExecutableInfo | String | Image path or command line |
| UserId | String | SID |

### Payload → EventData → Data Array

Each entry is `{ "@Name": "FieldName", "#text": "Value" }`. The available fields depend on EventId (see section 3 field extraction table).

### Important: ProcessId Ambiguity

The top-level `ProcessId` field is the **Sysmon service process ID**, NOT the monitored process. The monitored process PID is inside the Payload under `EventData.Data` where `@Name = "ProcessId"`. Always use the inner field.

---

## Appendix B: Cargo Workspace Structure

```
systrace/
├── Cargo.toml              (workspace root)
├── crates/
│   ├── systrace-core/      (parsing, data structures, indexing)
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── parser.rs        (NDJSON + Payload parsing)
│   │       ├── event.rs         (SysmonEvent, EventDetail)
│   │       ├── process_tree.rs  (ProcessTree, ProcessNode)
│   │       ├── event_store.rs   (EventStore, indexing)
│   │       └── types.rs         (common types, ProcessGuid)
│   └── systrace-gui/       (egui application)
│       ├── Cargo.toml
│       └── src/
│           ├── main.rs
│           ├── app.rs           (eframe::App implementation)
│           ├── panels/
│           │   ├── mod.rs
│           │   ├── process_tree.rs
│           │   ├── overview.rs
│           │   ├── network.rs
│           │   ├── file_activity.rs
│           │   ├── registry.rs
│           │   ├── pipes.rs
│           │   ├── injection.rs
│           │   ├── drivers.rs
│           │   └── timeline.rs
│           └── state.rs         (AppState, UI state)
└── test-data/
    └── sysmon.json          (sample data)
```
