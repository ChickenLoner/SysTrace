use std::cell::Cell;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crossbeam_channel::{Receiver, TryRecvError};
use eframe::egui::{self, Ui};
use systrace_core::{ProcessGuid, SysmonEvent};

use crate::panels;
use crate::state::{AppState, FileMetadata, TelemetryTab, TreeEventFilter};

/// Maximum event batches processed per UI frame to keep the frame time bounded.
const MAX_BATCHES_PER_FRAME: usize = 20;

// ---------------------------------------------------------------------------
// Background loading message
// ---------------------------------------------------------------------------

enum LoadMsg {
    Batch(Vec<SysmonEvent>),
    Done { error_count: usize },
}

// ---------------------------------------------------------------------------
// Stable tree node ID (independent of UI position)
// ---------------------------------------------------------------------------

fn tree_node_id(guid: ProcessGuid) -> egui::Id {
    egui::Id::new(("systrace_node", guid))
}

// ---------------------------------------------------------------------------
// Application
// ---------------------------------------------------------------------------

pub struct SysTraceApp {
    state: AppState,
    /// Active file path (displayed in status bar).
    file_path: Option<PathBuf>,
    /// Channel receiving parsed event batches from the background thread.
    rx: Option<Receiver<LoadMsg>>,
    /// Atomic bytes-read counter shared with the background thread.
    bytes_read: Arc<AtomicU64>,
}

impl Default for SysTraceApp {
    fn default() -> Self {
        Self {
            state: AppState::default(),
            file_path: None,
            rx: None,
            bytes_read: Arc::new(AtomicU64::new(0)),
        }
    }
}

impl SysTraceApp {
    pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        Self::default()
    }

    /// Called from `main` before the event loop starts to pre-load a file.
    pub fn open_file_on_start(&mut self, path: PathBuf) {
        self.open_file(path);
    }

    /// Select a process and reset per-tab row selection (keep sort preferences).
    fn select_process(&mut self, guid: ProcessGuid) {
        self.state.selected_process = Some(guid);
        self.state.scroll_to_selected = true;
        self.state.tab_network.selected_row = None;
        self.state.tab_files.selected_row = None;
        self.state.tab_registry.selected_row = None;
        self.state.tab_pipes.selected_row = None;
        self.state.tab_injection.selected_row = None;
        self.state.tab_drivers.selected_row = None;
        // Reset timeline zoom/pan for the newly selected process.
        self.state.timeline.reset();
    }

    // -----------------------------------------------------------------------
    // File loading
    // -----------------------------------------------------------------------

    fn open_file(&mut self, path: PathBuf) {
        let file_size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(1);

        // Create a fresh rodeo that will be shared with the parser thread.
        let rodeo = systrace_core::new_rodeo();

        // Reset all state for the new file, then install the new rodeo.
        self.state = AppState::default();
        self.state.rodeo = rodeo.clone();
        self.state.file_size = file_size;
        self.state.loading_progress = Some(0.0);
        self.bytes_read = Arc::new(AtomicU64::new(0));
        self.file_path = Some(path.clone());

        let (tx, rx) = crossbeam_channel::bounded::<LoadMsg>(64);
        self.rx = Some(rx);

        let bytes_read = self.bytes_read.clone();

        std::thread::spawn(move || {
            let (event_tx, event_rx) = crossbeam_channel::bounded::<Vec<SysmonEvent>>(64);
            let error_count = 0usize;

            {
                let path2 = path.clone();
                let br = bytes_read.clone();
                let etx = event_tx.clone();
                let r = rodeo.clone();
                std::thread::spawn(move || {
                    let mut errors = Vec::new();
                    let _ = systrace_core::parse_file(&path2, &etx, &br, &mut errors, &r);
                    let _ = errors.len();
                });
            }
            drop(event_tx);

            for batch in event_rx {
                if tx.send(LoadMsg::Batch(batch)).is_err() {
                    return;
                }
            }
            let _ = tx.send(LoadMsg::Done { error_count });
        });
    }

    /// Poll the loading channel — called once per frame.
    fn poll_loading(&mut self) {
        let file_size = self.state.file_size.max(1);

        let rx = match self.rx.take() {
            Some(r) => r,
            None => return,
        };

        let mut batches_this_frame = 0;

        loop {
            if batches_this_frame >= MAX_BATCHES_PER_FRAME {
                self.rx = Some(rx);
                return;
            }

            match rx.try_recv() {
                Ok(LoadMsg::Batch(batch)) => {
                    batches_this_frame += 1;
                    let rodeo = self.state.rodeo.clone();
                    for event in batch {
                        if event.event_id == 1 {
                            self.state.process_tree.insert_process_create(&event, &rodeo);
                        } else if event.event_id == 5 {
                            if let Some(guid) = event.process_guid {
                                self.state
                                    .process_tree
                                    .update_process_terminate(guid, event.time_created);
                            }
                        }
                        self.state.event_store.insert(event);
                    }
                    let read = self.bytes_read.load(Ordering::Relaxed);
                    self.state.loading_progress =
                        Some((read as f32 / file_size as f32).min(0.99));
                }
                Ok(LoadMsg::Done { error_count }) => {
                    self.state.parse_error_count = error_count;
                    break;
                }
                Err(TryRecvError::Empty) => {
                    self.rx = Some(rx);
                    let read = self.bytes_read.load(Ordering::Relaxed);
                    self.state.loading_progress =
                        Some((read as f32 / file_size as f32).min(0.99));
                    return;
                }
                Err(TryRecvError::Disconnected) => {
                    break;
                }
            }
        }

        self.state.process_tree.finalise();
        self.state.loading_progress = None;
        self.compute_file_metadata();
    }

    fn compute_file_metadata(&mut self) {
        let counts: std::collections::HashMap<u16, usize> = self
            .state
            .event_store
            .event_type_counts()
            .into_iter()
            .collect();

        let mut time_range: Option<(systrace_core::Timestamp, systrace_core::Timestamp)> = None;
        let mut computer_names = std::collections::HashSet::new();

        let rodeo = self.state.rodeo.clone();
        for event in &self.state.event_store.events {
            computer_names.insert(rodeo.resolve(&event.computer).to_owned());
            match &mut time_range {
                None => time_range = Some((event.time_created, event.time_created)),
                Some((min, max)) => {
                    if event.time_created < *min {
                        *min = event.time_created;
                    }
                    if event.time_created > *max {
                        *max = event.time_created;
                    }
                }
            }
        }

        let path_str = self
            .file_path
            .as_ref()
            .and_then(|p| p.to_str())
            .unwrap_or("")
            .to_owned();

        self.state.file_metadata = Some(FileMetadata {
            path: path_str,
            total_records: self.state.event_store.len() as u64,
            unique_processes: self.state.process_tree.len(),
            event_type_counts: counts,
            time_range,
            computer_names,
        });
    }

    // -----------------------------------------------------------------------
    // Helper: event filter predicate for tree nodes
    // -----------------------------------------------------------------------

    fn node_passes_event_filter(&self, guid: &ProcessGuid) -> bool {
        let f = &self.state.tree_event_filter;
        if !f.any_active() {
            return true;
        }
        if f.network
            && !self
                .state
                .event_store
                .events_for_process_and_types(guid, &[3, 22])
                .is_empty()
        {
            return true;
        }
        if f.files
            && !self
                .state
                .event_store
                .events_for_process_and_types(guid, &[11, 15, 23, 26, 27, 28, 29])
                .is_empty()
        {
            return true;
        }
        if f.registry
            && !self
                .state
                .event_store
                .events_for_process_and_types(guid, &[12, 13, 14])
                .is_empty()
        {
            return true;
        }
        if f.pipes
            && !self
                .state
                .event_store
                .events_for_process_and_types(guid, &[17, 18])
                .is_empty()
        {
            return true;
        }
        if f.injection
            && (!self
                .state
                .event_store
                .events_for_process_and_types(guid, &[8, 10, 25])
                .is_empty()
                || !self
                    .state
                    .event_store
                    .events_targeting_process(guid)
                    .is_empty())
        {
            return true;
        }
        if f.drivers
            && !self
                .state
                .event_store
                .events_for_process_and_types(guid, &[6, 7])
                .is_empty()
        {
            return true;
        }
        false
    }

    // -----------------------------------------------------------------------
    // Helper: recursively force-open all children in CollapsingState
    // -----------------------------------------------------------------------

    fn expand_all_children(&self, ctx: &egui::Context, guid: ProcessGuid) {
        let Some(node) = self.state.process_tree.get(&guid) else {
            return;
        };
        let children = node.children.clone();
        for child_guid in children {
            let id = tree_node_id(child_guid);
            let mut cs =
                egui::collapsing_header::CollapsingState::load_with_default_open(ctx, id, false);
            cs.set_open(true);
            cs.store(ctx);
            self.expand_all_children(ctx, child_guid);
        }
    }

    // -----------------------------------------------------------------------
    // Helpers: flat visible list for keyboard navigation
    // -----------------------------------------------------------------------

    fn collect_visible_preorder(
        &self,
        ctx: &egui::Context,
        guid: ProcessGuid,
        out: &mut Vec<ProcessGuid>,
    ) {
        let filter = self.state.search_filter.to_lowercase();
        let Some(node) = self.state.process_tree.get(&guid) else {
            return;
        };

        // Text filter — exact match, no subtree fallback
        if !filter.is_empty() {
            let image_lc = node.image_name.as_deref().unwrap_or("?").to_lowercase();
            let cmd_lc = node.command_line.as_deref().unwrap_or("").to_lowercase();
            let user_lc = node.user.as_deref().unwrap_or("").to_lowercase();
            let pid_lc = node.pid.map(|p| p.to_string()).unwrap_or_default();
            if !image_lc.contains(&filter)
                && !cmd_lc.contains(&filter)
                && !user_lc.contains(&filter)
                && !pid_lc.contains(&filter)
            {
                return;
            }
        }

        // Event type filter
        if !self.node_passes_event_filter(&guid) {
            return;
        }

        out.push(guid);

        // Recurse into open children
        if !node.children.is_empty() {
            let id = tree_node_id(guid);
            if egui::collapsing_header::CollapsingState::load_with_default_open(ctx, id, false)
                .is_open()
            {
                let children = node.children.clone();
                for child in children {
                    self.collect_visible_preorder(ctx, child, out);
                }
            }
        }
    }

    fn compute_flat_visible(&self, ctx: &egui::Context) -> Vec<ProcessGuid> {
        let mut out = Vec::new();
        let roots: Vec<_> = self.state.process_tree.roots().to_vec();
        for root in roots {
            self.collect_visible_preorder(ctx, root, &mut out);
        }
        out
    }

    // -----------------------------------------------------------------------
    // Timeline helpers
    // -----------------------------------------------------------------------

    /// Map an event_id to its timeline colour (category-coded).
    fn timeline_event_color(event_id: u16) -> egui::Color32 {
        match event_id {
            3 | 22 => egui::Color32::from_rgb(100, 160, 255),          // network: blue
            11 | 15 | 23 | 26 | 27 | 28 | 29 => egui::Color32::from_rgb(80, 200, 100), // file: green
            12 | 13 | 14 => egui::Color32::from_rgb(255, 160, 50),     // registry: orange
            8 | 10 | 25 => egui::Color32::from_rgb(220, 60, 60),       // injection: red
            17 | 18 => egui::Color32::from_rgb(180, 100, 220),         // pipes: purple
            6 | 7 => egui::Color32::from_rgb(80, 200, 200),            // drivers: cyan
            _ => egui::Color32::from_gray(160),                        // other: gray
        }
    }

    /// Category label for an event_id (for tooltips).
    fn timeline_event_label(event_id: u16) -> &'static str {
        match event_id {
            1 => "ProcessCreate", 2 => "FileCreateTime", 3 => "NetworkConnect",
            4 => "SysmonState", 5 => "ProcessTerminate", 6 => "DriverLoad",
            7 => "ImageLoad", 8 => "CreateRemoteThread", 9 => "RawAccessRead",
            10 => "ProcessAccess", 11 => "FileCreate", 12 => "RegistryCreate/Delete",
            13 => "RegistryValueSet", 14 => "RegistryRename", 15 => "FileStreamHash",
            16 => "ConfigChange", 17 => "PipeCreated", 18 => "PipeConnected",
            22 => "DnsQuery", 23 => "FileDelete", 25 => "ProcessTampering",
            26 => "FileDeleteDetected", 27 => "FileBlockExecutable",
            28 => "FileBlockShredding", 29 => "FileExecutableDetected",
            n => { let _ = n; "Unknown" }
        }
    }

    /// Pick a "nice" tick interval (in seconds) targeting ~8 ticks in `view_secs`.
    fn nice_tick_interval(view_secs: f64) -> f64 {
        let ideal = view_secs / 8.0;
        let candidates = [
            0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0,
            30.0, 60.0, 300.0, 600.0, 1800.0, 3600.0,
        ];
        candidates
            .iter()
            .copied()
            .min_by(|a, b| (a - ideal).abs().partial_cmp(&(b - ideal).abs()).unwrap())
            .unwrap_or(1.0)
    }

    fn render_timeline_panel(&mut self, ctx: &egui::Context) {
        let panel_height = if self.state.timeline.visible { 160.0_f32 } else { 28.0 };

        egui::TopBottomPanel::bottom("timeline_panel")
            .resizable(self.state.timeline.visible)
            .min_height(panel_height)
            .max_height(400.0)
            .default_height(panel_height)
            .show(ctx, |ui| {
                // Header row: toggle + legend
                ui.horizontal(|ui| {
                    let icon = if self.state.timeline.visible { "▼" } else { "▶" };
                    if ui.small_button(format!("{icon} Timeline")).clicked() {
                        self.state.timeline.visible = !self.state.timeline.visible;
                    }
                    if self.state.timeline.visible {
                        ui.separator();
                        // Colour legend
                        for (color, label) in [
                            (egui::Color32::from_rgb(100, 160, 255), "Network"),
                            (egui::Color32::from_rgb(80, 200, 100), "File"),
                            (egui::Color32::from_rgb(255, 160, 50), "Registry"),
                            (egui::Color32::from_rgb(220, 60, 60), "Injection"),
                            (egui::Color32::from_rgb(180, 100, 220), "Pipes"),
                            (egui::Color32::from_rgb(80, 200, 200), "Drivers"),
                            (egui::Color32::from_gray(160), "Other"),
                        ] {
                            let (rect, _) =
                                ui.allocate_exact_size(egui::vec2(10.0, 10.0), egui::Sense::hover());
                            ui.painter().circle_filled(rect.center(), 5.0, color);
                            ui.label(label);
                        }
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.small_button("Fit").clicked() {
                                self.state.timeline.reset();
                            }
                            let filter_label = if self.state.timeline.filter_active {
                                "🔗 Filtering"
                            } else {
                                "🔗 Filter Tables"
                            };
                            if ui.selectable_label(self.state.timeline.filter_active, filter_label)
                                .on_hover_text("Filter telemetry tables to the visible time window")
                                .clicked()
                            {
                                self.state.timeline.filter_active = !self.state.timeline.filter_active;
                                if !self.state.timeline.filter_active {
                                    self.state.time_range_filter = None;
                                }
                            }
                        });
                    }
                });

                if !self.state.timeline.visible {
                    return;
                }

                ui.separator();
                self.render_timeline_content(ui);
            });
    }

    fn render_timeline_content(&mut self, ui: &mut egui::Ui) {
        let Some(guid) = self.state.selected_process else {
            ui.centered_and_justified(|ui| {
                ui.label("Select a process to view its timeline.");
            });
            return;
        };

        // Collect event indices for this process (sorted by time implicitly from insertion order)
        let indices: Vec<usize> = self
            .state
            .event_store
            .events_for_process(&guid)
            .to_vec();

        if indices.is_empty() {
            ui.centered_and_justified(|ui| {
                ui.label("No events recorded for this process.");
            });
            return;
        }

        // Determine time range: process start → end (or last event)
        let t_start = self
            .state
            .process_tree
            .get(&guid)
            .map(|n| n.start_time)
            .unwrap_or_else(|| self.state.event_store.events[indices[0]].time_created);

        let t_end = self
            .state
            .process_tree
            .get(&guid)
            .and_then(|n| n.end_time)
            .unwrap_or_else(|| {
                indices
                    .iter()
                    .map(|&i| self.state.event_store.events[i].time_created)
                    .max()
                    .unwrap_or(t_start)
            });

        let total_secs = ((t_end - t_start).num_milliseconds() as f64 / 1000.0).max(0.001);

        let available = ui.available_rect_before_wrap();
        let width = available.width().max(1.0);
        let height = available.height().max(60.0);

        // Auto-fit: initialise zoom/pan when zoom == 0
        if self.state.timeline.zoom <= 0.0 {
            self.state.timeline.zoom = (width as f64 / total_secs).max(0.001);
            self.state.timeline.pan_offset = 0.0;
        }

        // Handle mouse-wheel zoom (before allocating the response, using ctx)
        let scroll_y = ui.ctx().input(|i| {
            if i.pointer.hover_pos().map(|p| available.contains(p)).unwrap_or(false) {
                i.smooth_scroll_delta.y
            } else {
                0.0
            }
        });
        if scroll_y.abs() > 0.1 {
            let zoom_factor = (1.0 + scroll_y as f64 * 0.005).clamp(0.1, 10.0);
            let cursor_x = ui
                .ctx()
                .input(|i| i.pointer.hover_pos())
                .map(|p| p.x - available.left())
                .unwrap_or(width / 2.0) as f64;
            let cursor_t = self.state.timeline.pan_offset
                + cursor_x / self.state.timeline.zoom;
            self.state.timeline.zoom *= zoom_factor;
            self.state.timeline.pan_offset =
                cursor_t - cursor_x / self.state.timeline.zoom;
        }

        // Clamp pan: don't let the user scroll past the event range
        let view_secs = width as f64 / self.state.timeline.zoom;
        self.state.timeline.pan_offset = self
            .state
            .timeline
            .pan_offset
            .clamp(-view_secs * 0.1, (total_secs + view_secs * 0.1).max(0.0));

        // Update time range filter for telemetry tables if active
        if self.state.timeline.filter_active {
            use chrono::Duration;
            let vis_start = t_start + Duration::milliseconds(
                (self.state.timeline.pan_offset * 1000.0) as i64
            );
            let vis_end = t_start + Duration::milliseconds(
                ((self.state.timeline.pan_offset + view_secs) * 1000.0) as i64
            );
            self.state.time_range_filter = Some((vis_start, vis_end));
        } else {
            self.state.time_range_filter = None;
        }

        // Allocate drawing area
        let (response, painter) =
            ui.allocate_painter(egui::vec2(width, height), egui::Sense::click_and_drag());
        let rect = response.rect;

        // Handle drag pan
        if response.dragged() {
            let delta = response.drag_delta().x as f64;
            self.state.timeline.pan_offset -= delta / self.state.timeline.zoom;
        }

        // ── Draw background ──────────────────────────────────────────────────
        painter.rect_filled(rect, 0.0, egui::Color32::from_gray(18));

        // ── Time axis line ───────────────────────────────────────────────────
        let axis_y = rect.bottom() - 22.0;
        painter.line_segment(
            [
                egui::pos2(rect.left(), axis_y),
                egui::pos2(rect.right(), axis_y),
            ],
            egui::Stroke::new(1.0, egui::Color32::from_gray(100)),
        );

        // ── Time ticks & labels ──────────────────────────────────────────────
        let view_secs_visible = width as f64 / self.state.timeline.zoom;
        let tick_interval = Self::nice_tick_interval(view_secs_visible);
        let first_tick = (self.state.timeline.pan_offset / tick_interval).ceil() * tick_interval;
        let mut t = first_tick;
        while t <= self.state.timeline.pan_offset + view_secs_visible {
            let x = rect.left()
                + ((t - self.state.timeline.pan_offset) * self.state.timeline.zoom) as f32;
            if x >= rect.left() && x <= rect.right() {
                painter.line_segment(
                    [egui::pos2(x, axis_y), egui::pos2(x, axis_y + 6.0)],
                    egui::Stroke::new(1.0, egui::Color32::from_gray(120)),
                );
                let label = if t < 60.0 {
                    format!("{:.3}s", t)
                } else {
                    let mins = (t as u64) / 60;
                    let secs = t - mins as f64 * 60.0;
                    format!("{mins}m{secs:.1}s")
                };
                painter.text(
                    egui::pos2(x + 2.0, axis_y + 8.0),
                    egui::Align2::LEFT_TOP,
                    label,
                    egui::FontId::proportional(10.0),
                    egui::Color32::from_gray(150),
                );
            }
            t += tick_interval;
        }

        // ── Process start / end markers ──────────────────────────────────────
        {
            let start_x = rect.left()
                + ((0.0_f64 - self.state.timeline.pan_offset) * self.state.timeline.zoom) as f32;
            if start_x >= rect.left() && start_x <= rect.right() {
                painter.line_segment(
                    [egui::pos2(start_x, rect.top()), egui::pos2(start_x, axis_y)],
                    egui::Stroke::new(1.5, egui::Color32::from_rgb(80, 200, 80)),
                );
            }

            let end_x = rect.left()
                + ((total_secs - self.state.timeline.pan_offset) * self.state.timeline.zoom)
                    as f32;
            if end_x >= rect.left() && end_x <= rect.right() {
                painter.line_segment(
                    [egui::pos2(end_x, rect.top()), egui::pos2(end_x, axis_y)],
                    egui::Stroke::new(1.5, egui::Color32::from_rgb(220, 80, 80)),
                );
            }
        }

        // ── Bucket events by pixel column ────────────────────────────────────
        // Key: pixel column (i32), value: (first_event_idx, count, blended color)
        let mut buckets: std::collections::HashMap<i32, (usize, usize, egui::Color32)> =
            std::collections::HashMap::new();

        for &idx in &indices {
            let event = &self.state.event_store.events[idx];
            let t_offset = (event.time_created - t_start).num_milliseconds() as f64 / 1000.0;
            let x = rect.left()
                + ((t_offset - self.state.timeline.pan_offset) * self.state.timeline.zoom) as f32;
            let col = x as i32;
            if x < rect.left() - 10.0 || x > rect.right() + 10.0 {
                continue;
            }
            let color = Self::timeline_event_color(event.event_id);
            buckets
                .entry(col)
                .and_modify(|(_, count, _)| *count += 1)
                .or_insert((idx, 1, color));
        }

        // ── Draw dots ────────────────────────────────────────────────────────
        let dot_y = axis_y - 12.0;
        let hover_pos = response.hover_pos();

        // Track which bucket is hovered for tooltip
        let mut hovered_bucket: Option<(egui::Pos2, usize, usize)> = None; // (pos, first_idx, count)

        for (&col, &(first_idx, count, color)) in &buckets {
            let x = col as f32 + 0.5;
            let pos = egui::pos2(x, dot_y);
            let radius = if count > 1 { 5.5_f32 } else { 4.0 };

            // Outer ring for multi-event buckets
            if count > 1 {
                painter.circle_stroke(
                    pos,
                    radius + 1.5,
                    egui::Stroke::new(1.0, color.linear_multiply(0.5)),
                );
            }
            painter.circle_filled(pos, radius, color);

            // Hover detection
            if let Some(hp) = hover_pos {
                if (hp.x - x).abs() <= radius + 3.0 && (hp.y - dot_y).abs() <= radius + 3.0 {
                    hovered_bucket = Some((pos, first_idx, count));
                    // Highlight ring
                    painter.circle_stroke(
                        pos,
                        radius + 3.0,
                        egui::Stroke::new(1.5, egui::Color32::WHITE),
                    );
                }
            }
        }

        // ── Tooltip ──────────────────────────────────────────────────────────
        if let Some((dot_pos, first_idx, count)) = hovered_bucket {
            let event = &self.state.event_store.events[first_idx];
            let t_offset = (event.time_created - t_start).num_milliseconds() as f64 / 1000.0;
            let ts_str = panels::fmt_time(event.time_created);

            egui::show_tooltip_at(
                ui.ctx(),
                ui.layer_id(),
                egui::Id::new("timeline_tip"),
                egui::pos2(dot_pos.x + 8.0, dot_pos.y - 12.0),
                |ui| {
                    if count > 1 {
                        ui.label(format!("{count} events at +{t_offset:.3}s"));
                        // Show up to 5 event types
                        let visible_indices: Vec<usize> = indices
                            .iter()
                            .copied()
                            .filter(|&i| {
                                let ev = &self.state.event_store.events[i];
                                let t =
                                    (ev.time_created - t_start).num_milliseconds() as f64 / 1000.0;
                                let x = rect.left()
                                    + ((t - self.state.timeline.pan_offset)
                                        * self.state.timeline.zoom)
                                        as f32;
                                x as i32 == dot_pos.x as i32
                            })
                            .take(5)
                            .collect();
                        for i in visible_indices {
                            let ev = &self.state.event_store.events[i];
                            ui.label(format!(
                                "  EventID {}: {}",
                                ev.event_id,
                                Self::timeline_event_label(ev.event_id)
                            ));
                        }
                        if count > 5 {
                            ui.label(format!("  … and {} more", count - 5));
                        }
                    } else {
                        ui.label(format!(
                            "EventID {}: {}",
                            event.event_id,
                            Self::timeline_event_label(event.event_id)
                        ));
                        ui.label(format!("Time: {ts_str} (+{t_offset:.3}s)"));
                        if let Some(img_spur) = event.image {
                            let img = self.state.rodeo.resolve(&img_spur);
                            ui.label(format!("Image: {img}"));
                        }
                    }
                },
            );
        }

        // ── Zoom hint ────────────────────────────────────────────────────────
        if buckets.is_empty() && !indices.is_empty() {
            painter.text(
                rect.center(),
                egui::Align2::CENTER_CENTER,
                "Scroll to zoom · Drag to pan",
                egui::FontId::proportional(11.0),
                egui::Color32::from_gray(100),
            );
        }
    }

    // -----------------------------------------------------------------------
    // Rendering
    // -----------------------------------------------------------------------

    fn render_menu(&mut self, ui: &mut Ui, ctx: &egui::Context) {
        egui::menu::bar(ui, |ui| {
            ui.menu_button("File", |ui| {
                if ui.button("Open…").clicked() {
                    if let Some(path) = rfd::FileDialog::new()
                        .add_filter("NDJSON / JSON", &["json", "ndjson"])
                        .pick_file()
                    {
                        self.open_file(path);
                    }
                    ui.close_menu();
                }
                ui.separator();
                if ui.button("Quit").clicked() {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
            });
        });
    }

    fn render_status_bar(&self, ui: &mut Ui) {
        ui.horizontal(|ui| {
            match &self.state.file_metadata {
                Some(meta) => {
                    ui.label(format!(
                        "{}  |  Records: {}  |  Processes: {}",
                        self.file_path
                            .as_ref()
                            .and_then(|p| p.file_name())
                            .and_then(|n| n.to_str())
                            .unwrap_or("(unknown)"),
                        meta.total_records,
                        meta.unique_processes,
                    ));
                    if self.state.parse_error_count > 0 {
                        ui.separator();
                        ui.colored_label(
                            egui::Color32::YELLOW,
                            format!("⚠ {} parse errors", self.state.parse_error_count),
                        );
                    }
                }
                None => {
                    if let Some(progress) = self.state.loading_progress {
                        ui.label(format!("Loading… {:.0}%", progress * 100.0));
                        ui.add(egui::ProgressBar::new(progress).desired_width(200.0));
                    } else {
                        ui.label(
                            "No file loaded — File › Open to load a Sysmon NDJSON export.",
                        );
                    }
                }
            }
        });
    }

    fn render_process_tree_panel(&mut self, ui: &mut Ui) {
        ui.heading("Processes");
        ui.separator();

        // Stable ID for the search TextEdit (needed for Ctrl+F focus)
        let search_id = egui::Id::new("process_search");

        // Search filter row
        ui.horizontal(|ui| {
            ui.label("🔍");
            egui::TextEdit::singleline(&mut self.state.search_filter)
                .id(search_id)
                .hint_text("Search image, PID, user, cmd…")
                .show(ui);
            if !self.state.search_filter.is_empty() && ui.small_button("✕").clicked() {
                self.state.search_filter.clear();
            }
        });

        // Event type filter checkboxes
        egui::CollapsingHeader::new("Event Type Filter")
            .default_open(false)
            .show(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.checkbox(&mut self.state.tree_event_filter.network, "Network");
                    ui.checkbox(&mut self.state.tree_event_filter.files, "Files");
                    ui.checkbox(&mut self.state.tree_event_filter.registry, "Registry");
                    ui.checkbox(&mut self.state.tree_event_filter.pipes, "Pipes");
                    ui.checkbox(&mut self.state.tree_event_filter.injection, "Injection");
                    ui.checkbox(&mut self.state.tree_event_filter.drivers, "Drivers");
                });
                if self.state.tree_event_filter.any_active()
                    && ui.small_button("Clear All").clicked()
                {
                    self.state.tree_event_filter = TreeEventFilter::default();
                }
            });

        ui.separator();

        // Keyboard navigation — arrow keys (only when search not focused)
        let search_focused = ui.ctx().memory(|m| m.has_focus(search_id));
        if !search_focused {
            let (down, up) = ui.ctx().input(|i| {
                (
                    i.key_pressed(egui::Key::ArrowDown),
                    i.key_pressed(egui::Key::ArrowUp),
                )
            });
            if down || up {
                let flat = self.state.flat_visible.clone();
                if !flat.is_empty() {
                    let current_idx = self
                        .state
                        .selected_process
                        .and_then(|sel| flat.iter().position(|&g| g == sel));
                    let next_idx = match current_idx {
                        None => 0,
                        Some(idx) => {
                            if down {
                                (idx + 1).min(flat.len() - 1)
                            } else {
                                idx.saturating_sub(1)
                            }
                        }
                    };
                    let next_guid = flat[next_idx];
                    if self.state.selected_process != Some(next_guid) {
                        self.select_process(next_guid);
                    }
                }
            }
        }

        // Ctrl+F: focus search box
        let do_focus = ui
            .ctx()
            .input(|i| i.modifiers.ctrl && i.key_pressed(egui::Key::F));
        if do_focus {
            ui.ctx().memory_mut(|m| m.request_focus(search_id));
        }

        if self.state.loading_progress.is_some() {
            ui.label("Loading…");
            return;
        }

        if self.state.process_tree.is_empty() {
            if self.state.file_metadata.is_some() {
                ui.label("No process create events found.");
            } else {
                ui.label("(empty)");
            }
            return;
        }

        let roots: Vec<_> = self.state.process_tree.roots().to_vec();
        let ctx = ui.ctx().clone();
        egui::ScrollArea::vertical()
            .auto_shrink([false; 2])
            .show(ui, |ui| {
                for guid in roots {
                    self.render_tree_node(ui, guid);
                }
            });

        // Rebuild flat visible list for keyboard navigation (post-render so CollapsingState is up to date)
        self.state.flat_visible = self.compute_flat_visible(&ctx);
    }

    fn render_tree_node(&mut self, ui: &mut Ui, guid: ProcessGuid) {
        let node = match self.state.process_tree.get(&guid) {
            Some(n) => n,
            None => return,
        };

        // Snapshot all fields we need before releasing the borrow on process_tree
        let image_name = node
            .image_name
            .clone()
            .unwrap_or_else(|| "?".to_owned());
        let image_full = node.image.clone().unwrap_or_else(|| "?".to_owned());
        let pid_str = node
            .pid
            .map(|p| p.to_string())
            .unwrap_or_else(|| "?".to_owned());
        let is_synthetic = node.is_synthetic;
        let is_terminated = node.end_time.is_some();
        let cmd = node.command_line.clone().unwrap_or_else(|| "-".to_owned());
        let user_str = node.user.clone().unwrap_or_else(|| "-".to_owned());
        let start_str = node.start_time.format("%Y-%m-%d %H:%M:%S UTC").to_string();
        let children: Vec<_> = node.children.clone();
        // node borrow on process_tree ends here

        // Text filter — exact match, no subtree fallback
        let filter = self.state.search_filter.to_lowercase();
        if !filter.is_empty() {
            let image_lc = image_name.to_lowercase();
            let cmd_lc = cmd.to_lowercase();
            let user_lc = user_str.to_lowercase();
            let pid_lc = pid_str.to_lowercase();
            let matches_self = image_lc.contains(&filter)
                || cmd_lc.contains(&filter)
                || user_lc.contains(&filter)
                || pid_lc.contains(&filter);
            if !matches_self {
                return;
            }
        }

        // Event type filter
        if !self.node_passes_event_filter(&guid) {
            return;
        }

        // Determine injection target and system user for color priority
        let is_injection_target =
            !self.state.event_store.events_targeting_process(&guid).is_empty();
        let is_system = user_str.to_uppercase().contains("SYSTEM");

        // Color priority: synthetic > injection_target > system > terminated > normal
        let text_color = if is_synthetic {
            egui::Color32::DARK_GRAY
        } else if is_injection_target {
            egui::Color32::from_rgb(220, 60, 60)
        } else if is_system {
            egui::Color32::from_rgb(80, 180, 80)
        } else if is_terminated {
            egui::Color32::from_rgb(180, 180, 100)
        } else {
            ui.visuals().text_color()
        };

        let label = if is_synthetic {
            format!("{image_name} ({pid_str}) [synthetic]")
        } else {
            format!("{image_name} ({pid_str})")
        };

        let is_selected = self.state.selected_process == Some(guid);
        let should_scroll = self.state.scroll_to_selected && is_selected;

        // GUID as hex string for clipboard copy
        let guid_hex: String = guid.iter().map(|b| format!("{b:02x}")).collect();
        let cmd_for_copy = cmd.clone();

        // --- Render node (leaf vs collapsible) ---
        let do_expand = Cell::new(false);

        if children.is_empty() {
            let rich = egui::RichText::new(&label).color(text_color);
            let resp = ui.selectable_label(is_selected, rich);
            if resp.clicked() {
                self.select_process(guid);
            }
            if should_scroll {
                resp.scroll_to_me(Some(egui::Align::Center));
                self.state.scroll_to_selected = false;
            }
            resp.on_hover_ui(|ui| {
                ui.label(format!("Image: {image_full}"));
                ui.label(format!("Command: {cmd}"));
                ui.label(format!("User: {user_str}"));
                ui.label(format!("Started: {start_str}"));
            })
            .context_menu(|ui| {
                if ui.button("Copy GUID").clicked() {
                    ui.ctx().copy_text(guid_hex.clone());
                    ui.close_menu();
                }
                if ui.button("Copy Command Line").clicked() {
                    ui.ctx().copy_text(cmd_for_copy.clone());
                    ui.close_menu();
                }
            });
        } else {
            let id = tree_node_id(guid);
            let cs = egui::collapsing_header::CollapsingState::load_with_default_open(
                ui.ctx(),
                id,
                false,
            );

            cs.show_header(ui, |ui| {
                let rich = egui::RichText::new(&label).color(text_color);
                let resp = ui.selectable_label(is_selected, rich);
                if resp.clicked() {
                    self.select_process(guid);
                }
                if should_scroll {
                    resp.scroll_to_me(Some(egui::Align::Center));
                    self.state.scroll_to_selected = false;
                }
                resp.on_hover_ui(|ui| {
                    ui.label(format!("Image: {image_full}"));
                    ui.label(format!("Command: {cmd}"));
                    ui.label(format!("User: {user_str}"));
                    ui.label(format!("Started: {start_str}"));
                })
                .context_menu(|ui| {
                    if ui.button("Copy GUID").clicked() {
                        ui.ctx().copy_text(guid_hex.clone());
                        ui.close_menu();
                    }
                    if ui.button("Copy Command Line").clicked() {
                        ui.ctx().copy_text(cmd_for_copy.clone());
                        ui.close_menu();
                    }
                    if ui.button("Expand All Children").clicked() {
                        do_expand.set(true);
                        ui.close_menu();
                    }
                });
            })
            .body(|ui| {
                for child in children {
                    self.render_tree_node(ui, child);
                }
            });
        }

        if do_expand.get() {
            let ctx = ui.ctx().clone();
            // Also open this node itself
            let mut cs =
                egui::collapsing_header::CollapsingState::load_with_default_open(&ctx, tree_node_id(guid), false);
            cs.set_open(true);
            cs.store(&ctx);
            self.expand_all_children(&ctx, guid);
        }
    }

    fn render_telemetry_panel(&mut self, ui: &mut Ui) {
        // Ctrl+Tab / Ctrl+Shift+Tab: cycle through tabs
        let tabs = [
            TelemetryTab::Overview,
            TelemetryTab::Network,
            TelemetryTab::FileActivity,
            TelemetryTab::Registry,
            TelemetryTab::Pipes,
            TelemetryTab::Injection,
            TelemetryTab::DriversModules,
        ];
        let (tab_forward, tab_backward) = ui.ctx().input(|i| {
            (
                i.modifiers.ctrl && !i.modifiers.shift && i.key_pressed(egui::Key::Tab),
                i.modifiers.ctrl && i.modifiers.shift && i.key_pressed(egui::Key::Tab),
            )
        });
        if tab_forward || tab_backward {
            if let Some(idx) = tabs.iter().position(|&t| t == self.state.active_tab) {
                let next = if tab_forward {
                    (idx + 1).rem_euclid(tabs.len())
                } else {
                    (idx + tabs.len() - 1).rem_euclid(tabs.len())
                };
                self.state.active_tab = tabs[next];
            }
        }

        // Tab bar
        ui.horizontal(|ui| {
            for (tab, label) in [
                (TelemetryTab::Overview, "Overview"),
                (TelemetryTab::Network, "Network"),
                (TelemetryTab::FileActivity, "Files"),
                (TelemetryTab::Registry, "Registry"),
                (TelemetryTab::Pipes, "Pipes"),
                (TelemetryTab::Injection, "Injection"),
                (TelemetryTab::DriversModules, "Drivers"),
            ] {
                if ui
                    .selectable_label(self.state.active_tab == tab, label)
                    .clicked()
                {
                    self.state.active_tab = tab;
                }
            }
        });

        // Global telemetry filter bar (shown for all non-Overview tabs)
        if self.state.active_tab != TelemetryTab::Overview {
            ui.horizontal(|ui| {
                ui.label("🔍");
                egui::TextEdit::singleline(&mut self.state.telemetry_filter)
                    .hint_text("Filter rows…")
                    .show(ui);
                if !self.state.telemetry_filter.is_empty() && ui.small_button("✕").clicked() {
                    self.state.telemetry_filter.clear();
                }
            });
        }

        ui.separator();

        // Show loading progress bar in central panel if loading
        if let Some(progress) = self.state.loading_progress {
            ui.vertical_centered(|ui| {
                ui.add_space(60.0);
                ui.heading("Loading file…");
                ui.add_space(12.0);
                ui.add(
                    egui::ProgressBar::new(progress)
                        .desired_width(400.0)
                        .show_percentage(),
                );
                ui.add_space(8.0);
                let events = self.state.event_store.len();
                if events > 0 {
                    ui.label(format!("{events} events ingested so far"));
                }
            });
            return;
        }

        // Clone filter + time_range to avoid borrow conflict with &mut self in panel calls
        let filter = self.state.telemetry_filter.clone();
        let time_range = self.state.time_range_filter;

        match self.state.active_tab {
            TelemetryTab::Overview => self.render_overview(ui),
            TelemetryTab::Network => {
                if let Some(guid) = self.state.selected_process {
                    panels::network::render_network(
                        ui,
                        &self.state.event_store,
                        guid,
                        &mut self.state.tab_network,
                        &filter,
                        time_range,
                    );
                } else {
                    panels::render_no_selection(ui);
                }
            }
            TelemetryTab::FileActivity => {
                if let Some(guid) = self.state.selected_process {
                    panels::file_activity::render_file_activity(
                        ui,
                        &self.state.event_store,
                        guid,
                        &mut self.state.tab_files,
                        &filter,
                        time_range,
                    );
                } else {
                    panels::render_no_selection(ui);
                }
            }
            TelemetryTab::Registry => {
                if let Some(guid) = self.state.selected_process {
                    panels::registry::render_registry(
                        ui,
                        &self.state.event_store,
                        guid,
                        &mut self.state.tab_registry,
                        &filter,
                        time_range,
                    );
                } else {
                    panels::render_no_selection(ui);
                }
            }
            TelemetryTab::Pipes => {
                if let Some(guid) = self.state.selected_process {
                    panels::pipes::render_pipes(
                        ui,
                        &self.state.event_store,
                        guid,
                        &mut self.state.tab_pipes,
                        &filter,
                        time_range,
                    );
                } else {
                    panels::render_no_selection(ui);
                }
            }
            TelemetryTab::Injection => {
                if let Some(guid) = self.state.selected_process {
                    panels::injection::render_injection(
                        ui,
                        &self.state.event_store,
                        guid,
                        &mut self.state.tab_injection,
                        &filter,
                        time_range,
                    );
                } else {
                    panels::render_no_selection(ui);
                }
            }
            TelemetryTab::DriversModules => {
                if let Some(guid) = self.state.selected_process {
                    panels::drivers::render_drivers(
                        ui,
                        &self.state.event_store,
                        guid,
                        &mut self.state.tab_drivers,
                        &filter,
                        time_range,
                    );
                } else {
                    panels::render_no_selection(ui);
                }
            }
        }
    }

    fn render_overview(&self, ui: &mut Ui) {
        let Some(guid) = self.state.selected_process else {
            ui.vertical_centered(|ui| {
                ui.add_space(40.0);
                ui.label("Select a process in the tree on the left.");
            });
            return;
        };
        let Some(node) = self.state.process_tree.get(&guid) else {
            return;
        };

        egui::ScrollArea::both()
            .auto_shrink([false; 2])
            .show(ui, |ui| {
                ui.heading("Process Details");
                ui.add_space(4.0);

                egui::Grid::new("overview_grid")
                    .num_columns(2)
                    .striped(true)
                    .min_col_width(100.0)
                    .show(ui, |ui| {
                        macro_rules! row {
                            ($label:expr, $val:expr) => {
                                ui.strong($label);
                                ui.label($val);
                                ui.end_row();
                            };
                        }

                        row!("Image", node.image.as_deref().unwrap_or("-"));
                        row!(
                            "PID",
                            node.pid
                                .map(|p| p.to_string())
                                .as_deref()
                                .unwrap_or("-")
                        );
                        row!(
                            "GUID",
                            &format!("{:x?}", guid)
                                .replace(", ", "")
                                .replace('[', "")
                                .replace(']', "")
                        );
                        row!(
                            "Command Line",
                            node.command_line.as_deref().unwrap_or("-")
                        );
                        row!("User", node.user.as_deref().unwrap_or("-"));
                        row!(
                            "Integrity",
                            node.integrity_level.as_deref().unwrap_or("-")
                        );
                        row!(
                            "Logon ID",
                            node.logon_id.as_deref().unwrap_or("-")
                        );
                        row!("Computer", &node.computer);
                        row!(
                            "Start Time",
                            &node.start_time.format("%Y-%m-%d %H:%M:%S%.3f UTC").to_string()
                        );
                        row!(
                            "End Time",
                            &node
                                .end_time
                                .map(|t| t.format("%Y-%m-%d %H:%M:%S%.3f UTC").to_string())
                                .unwrap_or_else(|| "Not Detected".to_owned())
                        );
                        row!("Hashes", node.hashes.as_deref().unwrap_or("-"));
                        row!(
                            "Parent Image",
                            node.parent_image.as_deref().unwrap_or("-")
                        );
                        row!(
                            "Parent PID",
                            &node
                                .parent_pid
                                .map(|p| p.to_string())
                                .unwrap_or_else(|| "-".to_owned())
                        );
                    });

                ui.add_space(12.0);
                ui.separator();
                ui.heading("Event Activity");
                ui.add_space(4.0);

                egui::Grid::new("event_counts")
                    .num_columns(3)
                    .striped(true)
                    .show(ui, |ui| {
                        ui.strong("Category");
                        ui.strong("Event IDs");
                        ui.strong("Count");
                        ui.end_row();

                        let categories: &[(&str, &str, &[u16])] = &[
                            ("Network",   "3, 22",                &[3, 22]),
                            ("Files",     "11,15,23,26,27,28,29", &[11, 15, 23, 26, 27, 28, 29]),
                            ("Registry",  "12, 13, 14",           &[12, 13, 14]),
                            ("Pipes",     "17, 18",               &[17, 18]),
                            ("Injection", "8, 10, 25",            &[8, 10, 25]),
                            ("Drivers",   "6, 7",                 &[6, 7]),
                            ("Other",     "9, 16, 24",            &[9, 16, 24]),
                        ];

                        for (name, ids_str, ids) in categories {
                            let n = self
                                .state
                                .event_store
                                .events_for_process_and_types(&guid, ids)
                                .len();
                            ui.label(*name);
                            ui.label(*ids_str);
                            if n > 0 {
                                ui.strong(n.to_string());
                            } else {
                                ui.label("0");
                            }
                            ui.end_row();
                        }
                    });
            });
    }
}

impl eframe::App for SysTraceApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Poll background loading channel
        self.poll_loading();

        // Request continuous repaints while loading so the progress bar updates
        if self.rx.is_some() || self.state.loading_progress.is_some() {
            ctx.request_repaint();
        }

        // Menu bar
        egui::TopBottomPanel::top("menu_bar").show(ctx, |ui| {
            self.render_menu(ui, ctx);
        });

        // Status bar (registered first so it appears at the very bottom)
        egui::TopBottomPanel::bottom("status_bar").show(ctx, |ui| {
            self.render_status_bar(ui);
        });

        // Timeline panel (stacks above status bar)
        self.render_timeline_panel(ctx);

        // Process tree (left side panel)
        egui::SidePanel::left("process_tree_panel")
            .resizable(true)
            .default_width(300.0)
            .min_width(200.0)
            .show(ctx, |ui| {
                self.render_process_tree_panel(ui);
            });

        // Telemetry panel (central)
        egui::CentralPanel::default().show(ctx, |ui| {
            self.render_telemetry_panel(ui);
        });
    }
}
