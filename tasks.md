# SysTrace Implementation Tasks

Complete task list from start to finish based on `CLAUDE.md` and `.claude/architecture.md`.

---

## Phase 1: Core Engine (Foundation) ✅ COMPLETE

**Goal:** Parse EVTXECmd JSON, build process tree, store indexed events.
**Crate:** `crates/systrace-core/`

### 1.1 Project Setup
- [x] Create workspace `Cargo.toml` with members `crates/systrace-core`, `crates/systrace-gui`
- [x] Create `crates/systrace-core/Cargo.toml` with deps: `serde`, `serde_json`, `chrono`, `rustc-hash`, `lasso`, `uuid`, `anyhow`, `thiserror`, `crossbeam-channel`, `tracing`
- [x] Create `crates/systrace-gui/Cargo.toml` with deps: `eframe`, `egui`, `egui_extras`, `rfd`, `systrace-core` (path dep)
- [x] Create module files: `lib.rs`, `types.rs`, `event.rs`, `parser.rs`, `process_tree.rs`, `event_store.rs`

### 1.2 Core Types (`types.rs`)
- [x] `ProcessGuid` as `[u8; 16]` — parse from GUID string via `uuid` crate
- [x] Helper: `parse_guid(s: &str) -> Result<ProcessGuid>`
- [x] `Timestamp` type alias for `chrono::DateTime<chrono::Utc>`
- [x] `MitreTechnique { id: String, name: String }` — parse from RuleName field
- [x] `ParseError` enum with line number context

### 1.3 Event Data Structures (`event.rs`)
- [x] `SysmonEventType` enum (29 variants, map from EventId u16)
- [x] `SysmonEvent` struct with common fields: event_id, event_type, time_created, record_number, computer, process_guid, process_id, image, user, rule_name, mitre_technique
- [x] `EventDetail` enum with variants per event type (see architecture §6):
  - `ProcessCreate` — command_line, hashes, parent fields, logon, integrity, etc.
  - `NetworkConnect` — protocol, initiated, src/dst ip:port, hostname
  - `FileCreate` — target_filename, creation_utc_time
  - `RegistryEvent` — event_type, target_object, details, new_name
  - `DnsQuery` — query_name, query_status, query_results
  - `PipeEvent` — event_type, pipe_name
  - `ProcessTerminate` (unit)
  - `CreateRemoteThread` — source/target process fields, start_address
  - `ProcessAccess` — source/target process fields, granted_access, call_trace
  - `FileDeleteEvent` — target_filename, hashes, is_executable
  - `DriverLoad` — image_loaded, hashes, signature, signature_status
  - `ImageLoad` — image_loaded, hashes, signature, signature_status
  - `FileCreateStreamHash` — target_filename, hash, contents
  - `ProcessTampering` — tampering_type
  - `ClipboardChange` — hashes
  - `RawAccessRead` — device
  - `SysmonConfigChange` — configuration, configuration_file_hash
  - `Generic` — fallback `HashMap<String, String>`

### 1.4 Parser (`parser.rs`)
- [x] Phase 1 struct: `RawEvtxRecord` — top-level EVTXECmd fields (EventId, TimeCreated, Payload, Computer, etc.)
- [x] Phase 2 structs: `PayloadWrapper`, `EventDataWrapper`, `DataField` — parse inner Payload JSON
- [x] `parse_payload(payload: &str) -> Result<HashMap<String, String>>` — converts Data[] array to map
- [x] `extract_event(raw: RawEvtxRecord, fields: &HashMap<String, String>) -> Result<SysmonEvent>` — dispatch by EventId, extract typed fields
- [x] `parse_mitre_rule_name(rule_name: &str) -> Option<MitreTechnique>`
- [x] Streaming NDJSON reader: `parse_file(path, sender)` — BufReader line-by-line, batch send over channel
- [x] Progress reporting via `AtomicU64` (bytes read vs file size)
- [x] Error collection: skip malformed lines, collect `ParseError` with line numbers

### 1.5 Process Tree (`process_tree.rs`)
- [x] `ProcessNode` struct: guid, pid, image, image_name, command_line, parent_guid, parent_pid, parent_image, children, start_time, end_time, user, hashes, integrity_level, logon_id, is_synthetic, computer
- [x] `ProcessTree` struct: nodes (FxHashMap), roots (Vec), pending_children (FxHashMap)
- [x] `ProcessTree::insert_process_create(event: &SysmonEvent)` — handles parent lookup, pending_children resolution
- [x] `ProcessTree::update_process_terminate(guid, end_time)` — sets end_time from EventId=5
- [x] Orphan handling: create synthetic parent nodes from child's ParentImage/ParentProcessId
- [x] `ProcessTree::roots()` — sorted by start_time
- [x] `ProcessTree::children_of(guid)` — sorted by start_time

### 1.6 Event Store (`event_store.rs`)
- [x] `EventStore` struct: events Vec, by_process FxHashMap, by_event_type FxHashMap, by_target_process FxHashMap
- [x] `EventStore::insert(event: SysmonEvent)` — append + update all indices
- [x] Cross-process indexing for EventId 8 (CreateRemoteThread) and 10 (ProcessAccess) — index under both source and target GUIDs
- [x] `events_for_process(guid) -> &[usize]`
- [x] `events_for_process_and_type(guid, event_id) -> Vec<usize>` — intersect indices

### 1.7 Integration & Tests
- [x] `lib.rs` — re-export public API
- [x] Integration test: parse `.claude/sysmon.json`, verify process tree structure
- [x] Integration test: verify event counts per EventId
- [x] Integration test: verify ProcessGuid indexing correctness
- [x] Unit test: GUID parsing edge cases
- [x] Unit test: MITRE RuleName parsing
- [x] Unit test: out-of-order event handling in ProcessTree
- _Benchmark moved to Phase 4C_

---

## Phase 2: Basic GUI ✅ COMPLETE

**Goal:** Display process tree and basic telemetry.
**Crate:** `crates/systrace-gui/`

### 2.1 Application Scaffold
- [x] `main.rs` — eframe::run_native setup, window options, optional CLI file arg (clap)
- [x] `app.rs` — `SysTraceApp` struct implementing `eframe::App`
- [x] `state.rs` — `AppState` struct: process_tree, event_store, selected_process, active_tab, loading_progress, parse_errors, file_metadata

### 2.2 File Loading
- [x] File open dialog via `rfd::FileDialog`
- [x] Background thread: spawn `parse_file()`, receive events via channel
- [x] Main thread: poll channel each frame, insert into ProcessTree + EventStore
- [x] Progress bar during loading (atomic progress counter → UI)
- [x] Loading complete → compute FileMetadata (record count, process count, time range, event type counts)

### 2.3 Process Tree Panel
- [x] Left `SidePanel` with resizable width (~25-30%)
- [x] Recursive tree rendering with `CollapsingHeader` (image_name + PID)
- [x] Expand/collapse state tracking
- [x] Click to select process → update `selected_process`
- [x] Visual highlight on selected node
- _Scroll to keep selected node visible — moved to Phase 4A_

### 2.4 Overview Tab (Telemetry Panel)
- [x] `CentralPanel` with tab bar at top
- [x] Overview tab: display process metadata (image, command line, hashes, user, integrity, start/end time, parent info)
- [x] Summary: event count per type for selected process

### 2.5 Status Bar
- [x] `TopBottomPanel::bottom` — record count, process count, load status
- [x] Show file path when loaded

---

## Phase 3: Full Telemetry Panels

**Goal:** All telemetry tabs with virtual-scrolled tables.
**Status: ✅ COMPLETE**

### 3.1 Table Infrastructure ✅
- [x] Shared table rendering helper using `egui_extras::TableBuilder` with virtual scrolling
- [x] Column sorting (click header → sort by column, toggle asc/desc) — `SortState` + `make_headers()` in `panels/mod.rs`
- [x] Row selection + highlight — `TabState.selected_row` + `row.set_selected()`
- [x] Right-click copy cell/row to clipboard — `row.response().context_menu()`

### 3.2 Network Tab ✅
- [x] Columns: Time, Direction(Initiated), Protocol, Source IP:Port, Dest IP:Port, Hostname
- [x] Data from EventId 3 (NetworkConnect) + EventId 22 (DnsQuery)
- [x] DNS queries shown with QueryName, QueryStatus, QueryResults
- File: `crates/systrace-gui/src/panels/network.rs`

### 3.3 File Activity Tab ✅
- [x] Columns: Time, Action (Create/Delete/Stream/etc.), Target Filename, Hashes
- [x] Data from EventId 11, 15, 23, 26, 27, 28, 29
- File: `crates/systrace-gui/src/panels/file_activity.rs`

### 3.4 Registry Tab ✅
- [x] Columns: Time, Action (Create/Set/Delete/Rename), Target Object, Details
- [x] Data from EventId 12, 13, 14
- File: `crates/systrace-gui/src/panels/registry.rs`

### 3.5 Smoke Test — Wire Network Panel First ✅
- [x] `state.rs`: add all 6 `TabState` fields (`tab_network`, `tab_files`, `tab_registry`, `tab_pipes`, `tab_injection`, `tab_drivers`) + Default entries
- [x] `main.rs`: add `mod panels;`
- [x] `app.rs`: wire Network tab only — extract `guid` (Copy) first, then borrow `&self.state.event_store` + `&mut self.state.tab_network` separately (borrow-split pattern)
- [x] `cargo build` — fix any compile errors from existing panels (network, file_activity, registry)
- [x] Note: `panels/mod.rs` already declares `pub mod pipes/injection/drivers` — must create stub files before build succeeds

### 3.6 Pipes Tab ✅
- [x] Columns: Time, Action (Create/Connect), Pipe Name
- [x] Data from EventId 17, 18
- File: `crates/systrace-gui/src/panels/pipes.rs`

### 3.7 Drivers/Modules Tab ✅
- [x] Columns: Time, Type (Driver/Image), Image Loaded, Signature, Signature Status
- [x] Data from EventId 6, 7
- File: `crates/systrace-gui/src/panels/drivers.rs`

### 3.8 Injection Tab ✅
- [x] Columns: Time, Type, Role (Source/Target), Source Process, Target Process, Details
- [x] Data from EventId 8, 10, 25
- [x] Merge logic: combine `events_for_process_and_types(&[8,10,25])` (Vec<usize>) + `events_targeting_process()` (&[usize]) into single Vec, sort, dedup
- [x] EventId 25 (ProcessTampering) has no source/target — render as simple row with empty Source/Target columns
- File: `crates/systrace-gui/src/panels/injection.rs`

### 3.9 Final Wiring ✅
- [x] `app.rs`: wire remaining tabs (FileActivity, Registry, Pipes, Injection, DriversModules) using same borrow-split pattern
- [x] Reset `TabState.selected_row` to `None` on all tabs when `selected_process` changes (keep sort preferences)
- [x] Build + smoke test with sample data: `cargo run -p systrace-gui -- .claude/sysmon.json`

---

## Phase 4A: UX Polish

**Goal:** Search refinements, tree polish, keyboard navigation.
**Status: 🔄 IN PROGRESS**

### 4A.0 State scaffolding ✅ DONE
- [x] `state.rs`: added `TreeEventFilter` struct (network/files/registry/pipes/injection/drivers bool fields + `any_active()`)
- [x] `state.rs`: added `AppState` fields: `telemetry_filter: String`, `tree_event_filter: TreeEventFilter`, `flat_visible: Vec<ProcessGuid>`, `scroll_to_selected: bool` — all initialised in `Default`

### 4A.1 Search & Filter ⬜ NEXT
- [x] Process tree text filter (search by image name, PID, command line, user)
- [x] **All 6 panel render functions** (`render_network`, `render_file_activity`, `render_registry`, `render_pipes`, `render_injection`, `render_drivers`) now accept `filter: &str` param — `rows.retain(|r| r.copy_text().to_lowercase().contains(&f))` applied after building rows
- [ ] **`app.rs` – exact-match tree filter**: change `render_tree_node` line 354 from `if !matches_self && node.children.is_empty()` → `if !matches_self { return; }` (no subtree fallback)
- [ ] **`app.rs` – event type filter checkboxes**: add `CollapsingHeader("Event Type Filter")` in `render_process_tree_panel` with 6 `ui.checkbox` calls bound to `self.state.tree_event_filter.*`; add clear button when any active; call `self.node_passes_event_filter(guid)` in `render_tree_node` (return early if false)
- [ ] **`app.rs` – global telemetry filter bar**: in `render_telemetry_panel`, show a `TextEdit` bound to `self.state.telemetry_filter` above the tab separator (skip for Overview tab); pass `&self.state.telemetry_filter` to all 6 panel calls (requires clone to avoid borrow conflict)

### 4A.2 Process Tree Polish ⬜ NEXT
- [x] Color coding: yellow (terminated), gray (synthetic)
- [ ] **`app.rs` – stable node IDs**: replace `ui.make_persistent_id(guid)` with free function `fn tree_node_id(guid: ProcessGuid) -> egui::Id { egui::Id::new(("systrace_node", guid)) }` — needed for expand_all_children and flat_visible to work with same IDs as render
- [ ] **`app.rs` – color priority**: add `let is_injection_target = !self.state.event_store.events_targeting_process(&guid).is_empty(); let is_system = user.to_uppercase().contains("SYSTEM");` then: synthetic=DARK_GRAY > injection_target=`Color32::from_rgb(220,60,60)` > system=`Color32::from_rgb(80,180,80)` > terminated=`Color32::from_rgb(180,180,100)` > normal
- [ ] **`app.rs` – node tooltip**: snapshot `image_full`, `cmd`, `user`, `start_str` from node before closures; inside show_header closure: `resp.on_hover_ui(|ui| { ui.label(…) … })`
- [ ] **`app.rs` – context menu**: 3 buttons: "Copy GUID" (format guid as `{:02x?}` hex), "Copy Command Line", "Expand All Children" (sets `do_expand = Cell::new(false)`; after closures: `if do_expand.get() { self.expand_all_children(ui.ctx(), guid); }`)
- [ ] **`app.rs` – scroll to selected**: add `self.state.scroll_to_selected = true;` to `select_process()`; in `render_tree_node` snapshot `let should_scroll = self.state.scroll_to_selected && is_selected;`; call `resp.scroll_to_me(Some(egui::Align::Center))` when true; set `self.state.scroll_to_selected = false` after

### 4A.3 Keyboard Navigation ⬜ NEXT
- [ ] **`app.rs` – flat_visible rebuild**: at end of `render_process_tree_panel` after scroll area: `let ctx = ui.ctx().clone(); self.state.flat_visible = self.compute_flat_visible(&ctx);`
- [ ] **`app.rs` – helper `collect_visible_preorder`**: traverses ProcessTree in pre-order DFS; applies same search filter + `node_passes_event_filter`; for nodes with children, recurses only if `CollapsingState::load_with_default_open(ctx, tree_node_id(guid), false).is_open()`
- [ ] **`app.rs` – helper `compute_flat_visible`**: calls `collect_visible_preorder` for each root; returns `Vec<ProcessGuid>`
- [ ] **`app.rs` – arrow key nav**: in `render_process_tree_panel`, check `ui.ctx().input(|i| …)` for `ArrowDown`/`ArrowUp`; find current index in `self.state.flat_visible`; clamp next index; call `self.select_process(next_guid)` — only when search TextEdit is NOT focused (`ui.ctx().memory(|m| m.has_focus(search_id))`)
- [ ] **`app.rs` – Ctrl+Tab tab switching**: in `render_telemetry_panel`, check `i.modifiers.ctrl && i.key_pressed(Key::Tab)` for next tab, add `&& i.modifiers.shift` for prev; cycle through 7-element tab array with `rem_euclid`
- [ ] **`app.rs` – Ctrl+F search focus**: after rendering the search TextEdit, check `ctrl && Key::F`; call `ui.ctx().memory_mut(|m| m.request_focus(search_id))`

### 4A.4 New helper methods to add to `SysTraceApp` in `app.rs`
```rust
fn node_passes_event_filter(&self, guid: ProcessGuid) -> bool { … } // check tree_event_filter
fn expand_all_children(&self, ctx: &egui::Context, guid: ProcessGuid) { … } // recursive CollapsingState force-open
fn collect_visible_preorder(&self, ctx: &egui::Context, guid: ProcessGuid, out: &mut Vec<ProcessGuid>) { … }
fn compute_flat_visible(&self, ctx: &egui::Context) -> Vec<ProcessGuid> { … }
```

---

## Phase 4B: Timeline View

**Goal:** Interactive timeline visualization for selected process events.

### 4B.1 Timeline Panel
- [ ] `TopBottomPanel::bottom` (collapsible, ~15-20% height)
- [ ] Horizontal time axis for selected process's event range
- [ ] Event dots color-coded by category (network=blue, file=green, registry=orange, injection=red)
- [ ] Custom drawing via egui `Painter` API
- [ ] Hover tooltip showing event summary
- [ ] Click event dot → scroll to event in detail panel
- [ ] Mouse wheel zoom + click-drag pan
- [ ] Bucket events by pixel column to avoid overdraw (count tooltip for dense areas)

---

## Phase 4C: Performance

**Goal:** Benchmarks, string interning, memory optimization.
**Prerequisite:** Benchmark harness must exist before optimizing.

### 4C.1 Benchmark Harness
- [ ] Benchmark: parse sample file, print time + memory stats (from Phase 1)
- [ ] Validate against arch targets: 1M events <10s load, <16ms frame, <100ms tab switch

### 4C.2 String Interning (core data layer refactor)
- [ ] String interning with `lasso` for Image paths, Computer names, UserNames
- [ ] Touches: `SysmonEvent`, `ProcessNode`, parser — this is NOT cosmetic polish
- [x] ProcessGuid stored as `[u8; 16]` (done in Phase 1)

### 4C.3 Virtual Scrolling Optimization
- [ ] Pre-computed flattened tree for virtual scrolling (cache, invalidate on expand/collapse)
- [ ] Lazy event filtering with frame budget (paginate if >5ms)
- [ ] Time range filter (slider or date picker)

---

## Phase 5: Advanced Features (Future)

### 5.1 Detection & Analysis
- [ ] Sigma rule YAML parsing → EventFilter implementations
- [ ] Run filters during/after ingestion, display findings
- [ ] Threat hunting query DSL: `image contains "powershell" AND event_type = NetworkConnect`
- [ ] MITRE ATT&CK annotations on timeline and process tree

### 5.2 Multi-Host Support
- [ ] Group process trees by Computer name
- [ ] Tab/dropdown to switch between hosts
- [ ] Cross-host timeline correlation

### 5.3 Export
- [ ] Timeline export to CSV/JSON
- [ ] Process tree export to DOT (Graphviz)
- [ ] Selected events export to STIX/OpenIOC
- [ ] HTML report generation

### 5.4 UX Extras
- [ ] Dark/light theme toggle
- [ ] Bookmarking / notes on processes
- [ ] Recent files list
- [ ] Drag-and-drop file loading

---

## Quick Reference

| Phase | Scope | Deliverable | Status |
|-------|-------|-------------|--------|
| 1 | Core Engine | `systrace-core` lib: parse → ProcessTree + EventStore | ✅ Done |
| 2 | Basic GUI | Working app: load file, tree, overview panel | ✅ Done |
| 3 | Full Telemetry | All 7 telemetry tabs with virtual-scrolled tables | ✅ Done |
| 4A | UX Polish | Search/filter, tree polish, keyboard nav | ⬜ |
| 4B | Timeline | Interactive timeline visualization | ⬜ |
| 4C | Performance | Benchmarks, string interning, virtual scroll opt | ⬜ |
| 5 | Advanced | Sigma rules, query DSL, multi-host, export | ⬜ |
