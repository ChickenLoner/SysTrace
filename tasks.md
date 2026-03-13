# SysTrace Implementation Plan

8 tasks: 5 from `bug.md` + 3 from codebase analysis. Ordered by dependency/risk.

---

## Task 1: Add Missing Process Details Fields
**Status:** [x] Done

Overview tab missing: FileVersion, Description, Product, Company, OriginalFileName.
Data IS parsed in `EventDetail::ProcessCreate` (event.rs:162-166) but NOT stored in `ProcessNode`.

**Files:**
- `crates/systrace-core/src/process_tree.rs` — add 5 `Option<String>` fields to `ProcessNode` (after line 31), extract in `insert_process_create()` in both the promote-synthetic path (~line 93) and new-node path (~line 120)
- `crates/systrace-gui/src/app.rs` → `render_overview()` (~line 1399) — add 5 rows to details grid before hashes, each with right-click Copy

**Steps:**
- [x] Add `file_version`, `description`, `product`, `company`, `original_file_name` to `ProcessNode`
- [x] Extract from `EventDetail::ProcessCreate` pattern match (currently using `..` to skip these)
- [x] Add rows in Overview tab details grid
- [x] Add right-click Copy context menu to each new field

---

## Task 2: Fix Timeline Bug
**Status:** [x] Done

Timeline tab shows nothing after clicking "Generate Timeline".

**Files:**
- `crates/systrace-gui/src/app.rs` → `render_timeline_tab()` (lines 557-673) + `render_timeline_tree_node()` (line 675)
- `crates/systrace-gui/src/panels/timeline.rs` → `render_timeline_table()` (line 40)

**Debug points:**
- `app.rs:609-617` — Generate button collects events via `events_for_process(&guid)` from `timeline_checked: HashSet<ProcessGuid>`
- `app.rs:675` — verify checkboxes actually toggle `timeline_checked`
- `panels/timeline.rs:49` — returns early if `event_indices.is_empty()`

**Steps:**
- [ ] Read `render_timeline_tree_node` fully to check checkbox state propagation
- [ ] Trace data flow: checkbox → `timeline_checked` → Generate click → `events_for_process` → `timeline_events`
- [ ] Test with `.claude/sysmon.json` sample data
- [ ] Fix root cause and confirm events populate

---

## Task 3: Detection Tab (Invisible Event Types)
**Status:** [ ] Not started

EventId 2, 4, 9, 16, 19-21, 24 are parsed into `EventDetail` variants but NO panel displays them. Investigators can't see anti-forensics, WMI persistence, or clipboard activity.

**Categories & columns:**
- Anti-Forensics: EventId 2 (FileCreateTime) — Time, File, New Time, Old Time
- Anti-Forensics: EventId 9 (RawAccessRead) — Time, Device
- Defense Evasion: EventId 4 (SysmonState) — Time, State, Version
- Defense Evasion: EventId 16 (SysmonConfigChange) — Time, Config, Hash
- WMI Persistence: EventId 19-21 (WmiActivity) — Time, Type, Operation, User, Namespace, Query, Destination
- Data Access: EventId 24 (ClipboardChange) — Time, Session, Client, Hashes

**Files:**
- `crates/systrace-gui/src/panels/detection.rs` — **new file**, follow pattern from `panels/network.rs`
- `crates/systrace-gui/src/panels/mod.rs` — add `pub mod detection;`
- `crates/systrace-gui/src/state.rs` — add `Detection` to `TelemetryTab` enum, add `tab_detection: TabState`
- `crates/systrace-gui/src/app.rs` — add Detection tab button + render call

**Steps:**
- [ ] Create `detection.rs` with typed row struct and `render_detection_table()`
- [ ] Use `events_for_process_and_types(guid, &[2, 4, 9, 16, 19, 20, 21, 24])`
- [ ] Group events with colored section headers per category
- [ ] Register module, add tab enum variant, add TabState
- [ ] Add tab button and render call in telemetry panel

---

## Task 4: MITRE ATT&CK Filter
**Status:** [ ] Not started

`SysmonEvent.mitre_technique: Vec<String>` is parsed from RuleName (types.rs) but never displayed or used for filtering.

**Part A — MITRE column in telemetry tables:**
- Add `mitre: String` to each panel's row struct, populated from `ev.mitre_technique.join(", ")`
- Add "MITRE" column to Network, Files, Registry, Pipes, Injection, Drivers, Detection tables

**Part B — MITRE tree filter:**
- On file load, collect unique MITRE technique IDs into `BTreeSet<String>` in AppState
- Add collapsing section "MITRE Techniques" in sidebar
- Checkboxes for each detected technique
- Filter tree: show only processes whose events contain checked technique

**Files:**
- `crates/systrace-gui/src/state.rs` — add `mitre_filter: HashSet<String>`, `available_mitre: BTreeSet<String>`
- `crates/systrace-gui/src/app.rs` — MITRE filter UI + integrate into `node_passes_event_filter` (~line 367)
- All `panels/*.rs` files — add MITRE column
- `crates/systrace-core/src/event_store.rs` — optionally add `by_mitre` index

**Steps:**
- [ ] Add MITRE state fields
- [ ] Collect unique techniques on file load
- [ ] Add MITRE column to all panel row structs and tables
- [ ] Add MITRE filter section in sidebar
- [ ] Integrate MITRE filter into `node_passes_event_filter()`

---

## Task 5: Help Window (Tabbed)
**Status:** [ ] Not started

No help system exists. Add "Help" menu button next to "File" → tabbed floating window.

**Tabs:**
1. **Color Guide** — tree colors (gray=synthetic, red=injection, green=SYSTEM, gold=terminated) + event colors (blue=network, green=files, orange=registry, red=injection, purple=pipes, cyan=drivers) + integrity (red=System, orange=High)
2. **Keyboard Shortcuts** — Ctrl+F, arrows, Ctrl+Tab, Ctrl+O, etc.
3. **Feature Guide** — brief explanation of each panel, filters, export, drag-and-drop

**Files:**
- `crates/systrace-gui/src/state.rs` — add `show_help: bool`, `help_tab: HelpTab` enum
- `crates/systrace-gui/src/app.rs` — add Help menu in `render_menu()` (~line 788), implement `render_help_window()`

**Steps:**
- [ ] Add HelpTab enum and state fields
- [ ] Add "Help" menu button in `render_menu()`
- [ ] Implement `render_help_window()` with tab bar
- [ ] Color Guide tab: colored rectangles + labels
- [ ] Keyboard Shortcuts tab: 2-column table
- [ ] Feature Guide tab: text sections per panel

---

## Task 6: Stats Popup (Filter-Aware)
**Status:** [ ] Not started

Add "Stats" button in menu bar → floating popup with statistics that update based on current filters.

**Stats to display:**
- Total events (filtered / total)
- Per-EventID breakdown (table: EventID, Name, Count, %)
- Per-user process count
- Integrity distribution (System / High / Medium / Low)
- Time range (first → last event)
- Host/computer breakdown

**Files:**
- `crates/systrace-gui/src/state.rs` — add `show_stats: bool`
- `crates/systrace-gui/src/app.rs` — add Stats button in `render_menu()`, implement `render_stats_window()`

**Steps:**
- [ ] Add state field
- [ ] Add "Stats" button to menu bar
- [ ] Implement `render_stats_window()` as `egui::Window`
- [ ] Compute stats from EventStore, respect host filter + special filter
- [ ] Display as formatted grid with counts and percentages
- [ ] Reuse `event_label()` from `panels/mod.rs` for event type names

---

## Task 7: Replace Event Type Filter with Special Filter
**Status:** [ ] Not started

Remove current `TreeEventFilter` (6 event type checkboxes). Replace with forensic-focused filters.

**New `SpecialFilter` struct:**
- **Integrity Level** — System, High, Medium, Low (checkboxes, match `ProcessNode.integrity_level`)
- **User** — dynamic checkbox list from all detected users in loaded file
- **Network Connection** — single checkbox, show processes with EventId 3/22
- **Persistence Archive** — single checkbox, show processes touching persistence locations

**Persistence patterns** (match registry events EventId 12-14 `target_object`):
- `*\CurrentVersion\Run\*`, `*\CurrentVersion\RunOnce\*`
- `*\CurrentControlSet\Services\*`
- `*\Schedule\TaskCache\*`
- `*\Microsoft\WBEM\*`
- `*\CurrentVersion\Winlogon\*`
- `*\CurrentVersion\Windows\AppInit_DLLs*`
- `*\CurrentVersion\Explorer\Shell Folders\*`, `*\StartupApproved\*`
- Also: child processes `schtasks.exe`, `at.exe`

**Pre-compute on file load:**
- `available_users: Vec<String>` — unique users from ProcessNode
- `persistence_processes: HashSet<ProcessGuid>` — processes with matching registry events
- `network_processes: HashSet<ProcessGuid>` — processes with EventId 3/22

**Filter logic (AND across active categories):** process must match ALL active filter categories.

**Files:**
- `crates/systrace-gui/src/state.rs` — replace `TreeEventFilter` with `SpecialFilter`, add precomputed sets
- `crates/systrace-gui/src/app.rs` — replace filter UI (~line 935-953), rewrite `node_passes_event_filter()` (~line 367-432), populate precomputed sets on file load

**Steps:**
- [ ] Define `SpecialFilter` struct in state.rs
- [ ] Add precomputed `HashSet<ProcessGuid>` for network/persistence processes
- [ ] Populate sets + user list on file load completion
- [ ] Replace filter UI rendering with 4 collapsing sections
- [ ] Rewrite `node_passes_event_filter()` with new logic
- [ ] Remove old `TreeEventFilter`

---

## Task 8: Bookmark Persistence
**Status:** [ ] Not started

Bookmarks (`bookmarks: HashMap<ProcessGuid, String>`) and `recent_files` are lost on app close.

**Design:**
- Config dir: `~/.config/systrace/` (via `dirs` crate)
- Global config: `config.json` — `{ recent_files: [...], dark_mode: bool }`
- Per-file bookmarks: `bookmarks/<sha256-of-filepath>.json` — `{ "<hex-guid>": "note text" }`
- Load on startup, save on change

**Files:**
- `crates/systrace-gui/Cargo.toml` — add `dirs` dependency
- `crates/systrace-gui/src/app.rs` — load in `SysTraceApp::new()`, save in `open_file()` + bookmark edit + dark mode toggle

**Steps:**
- [ ] Add `dirs` crate dependency
- [ ] Define serializable config structs
- [ ] Implement load/save functions
- [ ] Load config on app startup
- [ ] Save recent_files on file open
- [ ] Save bookmarks on edit
- [ ] Save dark_mode on toggle

---

## Implementation Order

1. **Task 1** (Process Details) — smallest scope, pure additive
2. **Task 2** (Timeline fix) — bug fix, isolated
3. **Task 3** (Detection tab) — new panel, follows existing patterns
4. **Task 4** (MITRE filter) — column additions + new filter
5. **Task 5** (Help window) — new UI, standalone
6. **Task 6** (Stats popup) — new UI, filter integration
7. **Task 7** (Special Filter) — largest scope, replaces existing filter
8. **Task 8** (Bookmark persistence) — touches app lifecycle

## Unresolved Questions

None — all clarifications resolved.
