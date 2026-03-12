# SysTrace — Timeline View Revamp

## Phase 7: Timeline View (Hunt Tab Revamp)

**Goal:** Replace Hunt tab with inline Timeline tab — process tree with checkboxes + unified chronological event table.

### 7.1 State Changes (`crates/systrace-gui/src/state.rs`)
- [ ] Rename `TelemetryTab::Detection` → `TelemetryTab::Timeline`
- [ ] Replace hunt_* fields with timeline_filter, timeline_checked, timeline_events, timeline_generated, tab_timeline
- [ ] Update Default impl

### 7.2 Timeline Event Table (`crates/systrace-gui/src/panels/timeline.rs`)
- [ ] Create TimelineRow struct (time, process_name, pid, event_id, event_type, detail)
- [ ] `render_timeline_table()` with TableBuilder, sortable columns, text filter, copy context menu
- [ ] Move `detail_summary()` from detection.rs
- [ ] Register in panels/mod.rs

### 7.3 Timeline Tab Rendering (`crates/systrace-gui/src/app.rs`)
- [ ] Remove render_hunt_tab(), hunt_node_matches(), hunt_collect_preorder(), render_hunt_timeline_popup()
- [ ] Remove render_hunt_timeline_popup() call from update()
- [ ] Add render_timeline_tab() with left/right split layout
- [ ] Left: recursive tree with checkboxes + filter + Select All / Deselect All
- [ ] Right: event table (after Generate Timeline clicked) or placeholder
- [ ] Generate Timeline: collect events from checked processes, sort by time, cache

### 7.4 Tab Bar Updates (`crates/systrace-gui/src/app.rs`)
- [ ] Change tab label "Hunt" → "Timeline"
- [ ] Update Detection → Timeline in tab arrays and match arms
- [ ] Skip global telemetry filter for Timeline tab

### 7.5 Cleanup
- [ ] Delete detection.rs (orphaned)

### 7.6 Verification
- [ ] cargo build — no errors
- [ ] cargo test — all pass
- [ ] Manual test with .claude/sysmon.json
