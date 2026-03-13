# SysTrace Implementation Plan

Based on findings in `bug.md`. 5 features, ordered by dependency.

---

## Task 1: Fix Timeline Bug
**Status:** [ ] Not started

Timeline tab shows nothing after clicking "Generate Timeline".

**Root cause investigation needed in:**
- `crates/systrace-gui/src/app.rs` → `render_timeline_tab()` (event collection logic)
- `crates/systrace-gui/src/panels/timeline.rs` → `render_timeline_table()` (rendering)

**Steps:**
- [ ] Debug why generated event list is empty after clicking Generate
- [ ] Verify checkbox selection state propagates correctly to event collection
- [ ] Verify events are fetched from EventStore for selected processes
- [ ] Fix the bug and confirm timeline populates with events

---

## Task 2: Add Missing Process Details Fields
**Status:** [ ] Not started

Overview tab missing: FileVersion, Description, Product, Company, OriginalFileName.
These fields ARE already parsed in `EventDetail::ProcessCreate` but NOT stored in `ProcessNode`.

**Files to modify:**
- `crates/systrace-core/src/process_tree.rs` — add 5 fields to `ProcessNode`, populate from EventId=1
- `crates/systrace-gui/src/app.rs` → `render_overview()` — display new fields in details grid

**Steps:**
- [ ] Add `file_version`, `description`, `product`, `company`, `original_file_name` to `ProcessNode`
- [ ] Populate fields in `ProcessTree::add_event()` when processing EventId=1
- [ ] Add rows in Overview tab after existing fields (before hashes section)
- [ ] Add right-click Copy context menu to each new field

---

## Task 3: Replace Event Type Filter with Special Filter
**Status:** [ ] Not started

Remove existing event type checkboxes (Network, Files, Registry, etc.). Replace with:

**New filters (all checkbox-based):**
1. **Process Integrity** — System, High, Medium, Low (filter tree to show only matching)
2. **Process User** — dynamic list of users detected in loaded file
3. **Network Connection** — show only processes that have EventId 3/22 events
4. **Persistence Archive** — show processes touching common persistence locations:
   - Registry Run/RunOnce keys (`SOFTWARE\Microsoft\Windows\CurrentVersion\Run*`)
   - Services (`SYSTEM\CurrentControlSet\Services`)
   - Scheduled Tasks (registry + EventId 1 with `schtasks.exe` or task XML paths)
   - WMI subscriptions (`SOFTWARE\Microsoft\WBEM`)
   - Startup folder paths
   - AppInit_DLLs, Winlogon, Shell extensions, etc.

**Files to modify:**
- `crates/systrace-gui/src/state.rs` — replace `TreeEventFilter` with `SpecialFilter` struct
- `crates/systrace-gui/src/app.rs` — replace filter UI rendering + tree filtering logic
- `crates/systrace-core/src/event_store.rs` — may need helper to query persistence-related events

**Steps:**
- [ ] Define `SpecialFilter` struct in state.rs (integrity levels, user list, network flag, persistence flag)
- [ ] On file load, collect unique users + detect which processes have network/persistence events
- [ ] Build persistence detection: define list of registry path patterns, match against EventId 12-14 registry events
- [ ] Replace filter UI: collapsing sections for each filter category with checkboxes
- [ ] Update `process_matches_filter()` to apply special filter logic to tree visibility
- [ ] Remove old `TreeEventFilter` and all references

---

## Task 4: Add Help Button (Tabbed Help Window)
**Status:** [ ] Not started

Add "Help" menu item in menu bar (next to "File"). Opens a tabbed help window.

**Tabs:**
1. **Color Guide** — process tree colors (Synthetic=gray, Injection=red, SYSTEM=green, Terminated=gold) + event type colors (Network=blue, Files=green, Registry=orange, etc.) + integrity colors (System=red, High=orange)
2. **Keyboard Shortcuts** — Ctrl+F (search), Arrow keys (navigation), Ctrl+Tab (switch tabs), Ctrl+O (open file), etc.
3. **Feature Guide** — brief explanation of each panel/tab, how filters work, export options, drag-and-drop support

**Files to modify:**
- `crates/systrace-gui/src/state.rs` — add `show_help_window: bool`, `help_tab: HelpTab` enum
- `crates/systrace-gui/src/app.rs` — add Help to menu bar, render help window

**Steps:**
- [ ] Add HelpTab enum and state fields
- [ ] Add "Help" menu to menu bar with "User Guide" option
- [ ] Implement `render_help_window()` with 3 tabs
- [ ] Color Guide tab: colored rectangles + descriptions for each color meaning
- [ ] Keyboard Shortcuts tab: table of shortcut → action
- [ ] Feature Guide tab: brief text explaining each panel and workflow

---

## Task 5: Add Stats Button (Filter-Aware Popup)
**Status:** [ ] Not started

Add "Stats" button (in menu bar or toolbar). Opens floating popup showing statistics that update based on current filters/selection.

**Stats to display:**
- Total events (filtered / total)
- Per-EventID breakdown with counts
- Per-user process count
- Integrity level distribution (System / High / Medium / Low)
- Time range of events
- Host/computer breakdown (if multi-host)

**Files to modify:**
- `crates/systrace-gui/src/state.rs` — add `show_stats_window: bool`
- `crates/systrace-gui/src/app.rs` — add Stats button, render stats popup

**Steps:**
- [ ] Add state field for stats window visibility
- [ ] Add "Stats" button to menu bar
- [ ] Implement `render_stats_window()` as egui::Window
- [ ] Compute stats from EventStore, filtered by current tree filter / host filter
- [ ] Display as formatted grid/table with counts and percentages
- [ ] Re-compute on filter change (or compute each frame since egui is immediate mode)

---

## Unresolved Questions

None — all clarifications resolved.

## Implementation Order

1. **Task 2** (Process Details) — smallest scope, pure additive, no risk
2. **Task 1** (Timeline fix) — bug fix, isolated
3. **Task 4** (Help window) — new UI, no existing code changes
4. **Task 5** (Stats popup) — new UI, needs filter integration
5. **Task 3** (Special Filter) — largest scope, replaces existing filter system
