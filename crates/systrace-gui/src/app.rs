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
        self.state.active_tab = TelemetryTab::Overview;
        self.state.scroll_to_selected = true;
        self.state.tab_network.selected_row = None;
        self.state.tab_files.selected_row = None;
        self.state.tab_registry.selected_row = None;
        self.state.tab_pipes.selected_row = None;
        self.state.tab_injection.selected_row = None;
        self.state.tab_drivers.selected_row = None;
    }

    // -----------------------------------------------------------------------
    // File loading
    // -----------------------------------------------------------------------

    fn open_file(&mut self, path: PathBuf) {
        let file_size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(1);

        // Preserve cross-file state
        let dark_mode = self.state.dark_mode;
        let bookmarks = std::mem::take(&mut self.state.bookmarks);
        let mut recent_files = std::mem::take(&mut self.state.recent_files);
        recent_files.retain(|p| p != &path);
        recent_files.insert(0, path.clone());
        recent_files.truncate(10);

        // Create a fresh rodeo that will be shared with the parser thread.
        let rodeo = systrace_core::new_rodeo();

        // Reset all state for the new file, then install the new rodeo.
        self.state = AppState::default();
        self.state.rodeo = rodeo.clone();
        self.state.file_size = file_size;
        self.state.loading_progress = Some(0.0);
        self.bytes_read = Arc::new(AtomicU64::new(0));
        self.file_path = Some(path.clone());

        // Restore preserved state
        self.state.dark_mode = dark_mode;
        self.state.bookmarks = bookmarks;
        self.state.recent_files = recent_files;

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
    // Phase 5: Export
    // -----------------------------------------------------------------------

    fn csv_escape(s: &str) -> String {
        if s.contains(',') || s.contains('"') || s.contains('\n') {
            format!("\"{}\"", s.replace('"', "\"\""))
        } else {
            s.to_owned()
        }
    }

    fn json_escape(s: &str) -> String {
        s.replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n")
            .replace('\r', "")
    }

    fn export_events_csv(&self) {
        let Some(path) = rfd::FileDialog::new()
            .add_filter("CSV", &["csv"])
            .set_file_name("systrace_events.csv")
            .save_file()
        else {
            return;
        };

        use std::io::Write;
        let Ok(mut f) = std::fs::File::create(&path) else { return; };
        let rodeo = &self.state.rodeo;
        let _ = writeln!(f, "Time,EventID,EventType,Computer,Image,User");
        for ev in &self.state.event_store.events {
            let time = ev.time_created.format("%Y-%m-%d %H:%M:%S%.3f").to_string();
            let etype = ev.event_type.display_name();
            let computer = rodeo.resolve(&ev.computer);
            let image = ev.image.map(|s| rodeo.resolve(&s).to_owned()).unwrap_or_default();
            let user = ev.user.map(|s| rodeo.resolve(&s).to_owned()).unwrap_or_default();
            let _ = writeln!(
                f,
                "{},{},{},{},{},{}",
                Self::csv_escape(&time),
                ev.event_id,
                etype,
                Self::csv_escape(computer),
                Self::csv_escape(&image),
                Self::csv_escape(&user),
            );
        }
    }

    fn export_tree_dot(&self) {
        let Some(path) = rfd::FileDialog::new()
            .add_filter("DOT / Graphviz", &["dot"])
            .set_file_name("process_tree.dot")
            .save_file()
        else {
            return;
        };

        use std::io::Write;
        let Ok(mut f) = std::fs::File::create(&path) else { return; };
        let _ = writeln!(f, "digraph ProcessTree {{");
        let _ = writeln!(f, "  rankdir=LR;");
        let _ = writeln!(f, "  node [shape=box fontname=\"monospace\"];");
        for (guid, node) in &self.state.process_tree.nodes {
            let gid: String = guid.iter().map(|b| format!("{b:02x}")).collect();
            let label = node.image_name.as_deref().unwrap_or("?");
            let pid = node.pid.map(|p| p.to_string()).unwrap_or_else(|| "?".to_owned());
            let style = if node.is_synthetic {
                " style=dashed"
            } else if node.end_time.is_some() {
                " color=gray"
            } else {
                ""
            };
            let label_esc = label.replace('"', "\\\"");
            let _ = writeln!(f, "  n{gid} [label=\"{label_esc}\\n({pid})\"{style}];");
            if let Some(parent_guid) = &node.parent_guid {
                let pgid: String = parent_guid.iter().map(|b| format!("{b:02x}")).collect();
                let _ = writeln!(f, "  n{pgid} -> n{gid};");
            }
        }
        let _ = writeln!(f, "}}");
    }

    fn export_events_json(&self) {
        let Some(path) = rfd::FileDialog::new()
            .add_filter("JSON", &["json"])
            .set_file_name("systrace_events.json")
            .save_file()
        else {
            return;
        };

        use std::io::Write;
        let Ok(mut f) = std::fs::File::create(&path) else { return; };
        let rodeo = &self.state.rodeo;
        let total = self.state.event_store.events.len();
        let _ = writeln!(f, "[");
        for (i, ev) in self.state.event_store.events.iter().enumerate() {
            let time = ev.time_created.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
            let etype = ev.event_type.display_name();
            let computer = Self::json_escape(rodeo.resolve(&ev.computer));
            let image = ev.image.map(|s| Self::json_escape(rodeo.resolve(&s))).unwrap_or_default();
            let user = ev.user.map(|s| Self::json_escape(rodeo.resolve(&s))).unwrap_or_default();
            let comma = if i < total - 1 { "," } else { "" };
            let _ = writeln!(
                f,
                "  {{\"time\":\"{time}\",\"event_id\":{},\"event_type\":\"{etype}\",\"computer\":\"{computer}\",\"image\":\"{image}\",\"user\":\"{user}\"}}{comma}",
                ev.event_id,
            );
        }
        let _ = writeln!(f, "]");
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

    fn set_all_tree_open(&self, ctx: &egui::Context, open: bool) {
        let guids: Vec<_> = self.state.process_tree.nodes.keys().copied().collect();
        for guid in guids {
            let mut cs = egui::collapsing_header::CollapsingState::load_with_default_open(
                ctx, tree_node_id(guid), false,
            );
            cs.set_open(open);
            cs.store(ctx);
        }
    }

    /// Returns true if any node in the subtree rooted at `guid` matches the filter.
    fn subtree_matches_filter(&self, guid: ProcessGuid, filter: &str) -> bool {
        let Some(node) = self.state.process_tree.get(&guid) else {
            return false;
        };
        let image_lc = node.image_name.as_deref().unwrap_or("").to_lowercase();
        let cmd_lc = node.command_line.as_deref().unwrap_or("").to_lowercase();
        let user_lc = node.user.as_deref().unwrap_or("").to_lowercase();
        let pid_lc = node.pid.map(|p| p.to_string()).unwrap_or_default();
        if image_lc.contains(filter)
            || cmd_lc.contains(filter)
            || user_lc.contains(filter)
            || pid_lc.contains(filter)
        {
            return true;
        }
        let children = node.children.clone();
        children.iter().any(|&c| self.subtree_matches_filter(c, filter))
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

        // Host filter
        if let Some(host) = &self.state.selected_host {
            if &node.computer != host {
                return;
            }
        }

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
    // Event colour / label helpers (shared by hunt timeline popup)
    // -----------------------------------------------------------------------

    /// Map an event_id to its category colour.
    fn event_color(event_id: u16) -> egui::Color32 {
        match event_id {
            3 | 22 => egui::Color32::from_rgb(100, 160, 255),
            11 | 15 | 23 | 26 | 27 | 28 | 29 => egui::Color32::from_rgb(80, 200, 100),
            12 | 13 | 14 => egui::Color32::from_rgb(255, 160, 50),
            8 | 10 | 25 => egui::Color32::from_rgb(220, 60, 60),
            17 | 18 => egui::Color32::from_rgb(180, 100, 220),
            6 | 7 => egui::Color32::from_rgb(80, 200, 200),
            _ => egui::Color32::from_gray(160),
        }
    }

    /// Human-readable label for an event_id.
    fn event_label(event_id: u16) -> &'static str {
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

    /// Nice tick interval in seconds targeting ~8 ticks in `view_secs`.
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

    // -----------------------------------------------------------------------
    // Hunt tab
    // -----------------------------------------------------------------------

    fn render_hunt_tab(&mut self, ui: &mut Ui) {
        if self.state.event_store.len() == 0 {
            panels::render_empty(ui, "No data loaded — open a file first.");
            return;
        }

        // ── Filter bar ───────────────────────────────────────────────────────
        ui.horizontal(|ui| {
            ui.label("Filter:");
            egui::TextEdit::singleline(&mut self.state.hunt_filter)
                .hint_text("image name, user, command line, PID…")
                .desired_width(ui.available_width() - 200.0)
                .show(ui);
            if !self.state.hunt_filter.is_empty() && ui.small_button("✕").clicked() {
                self.state.hunt_filter.clear();
            }
            ui.separator();
            if ui.small_button("Select All").clicked() {
                let filter_lc = self.state.hunt_filter.to_lowercase();
                let guids: Vec<_> = self.state.process_tree.nodes.keys().copied()
                    .filter(|g| Self::hunt_node_matches(&self.state, g, &filter_lc))
                    .collect();
                self.state.hunt_checked.extend(guids);
            }
            if ui.small_button("Deselect All").clicked() {
                self.state.hunt_checked.clear();
            }
        });

        let checked_count = self.state.hunt_checked.len();
        ui.horizontal(|ui| {
            let btn = egui::Button::new(
                egui::RichText::new(format!("Generate Timeline ({checked_count} selected)"))
                    .color(if checked_count > 0 {
                        egui::Color32::from_rgb(80, 200, 100)
                    } else {
                        egui::Color32::GRAY
                    })
            );
            if ui.add_enabled(checked_count > 0, btn).clicked() {
                self.state.hunt_popup_open = true;
                self.state.hunt_zoom = 0.0; // trigger auto-fit
                self.state.hunt_pan = 0.0;
            }
        });

        ui.separator();

        // ── Process list with checkboxes ────────────────────────────────────
        let filter_lc = self.state.hunt_filter.to_lowercase();

        // Collect matching processes in pre-order (roots → children)
        let mut matching: Vec<ProcessGuid> = Vec::new();
        let roots: Vec<_> = self.state.process_tree.roots().to_vec();
        for root in roots {
            Self::hunt_collect_preorder(&self.state, root, &filter_lc, &mut matching);
        }

        if matching.is_empty() {
            ui.centered_and_justified(|ui| {
                if filter_lc.is_empty() {
                    ui.label("No processes in the tree.");
                } else {
                    ui.label(format!("No processes match \"{}\".", self.state.hunt_filter));
                }
            });
            return;
        }

        ui.label(format!("{} processes match", matching.len()));
        ui.separator();

        egui::ScrollArea::vertical()
            .auto_shrink([false; 2])
            .show(ui, |ui| {
                for guid in matching {
                    let node = match self.state.process_tree.get(&guid) {
                        Some(n) => n,
                        None => continue,
                    };
                    let image_name = node.image_name.as_deref().unwrap_or("?");
                    let pid_str = node.pid.map(|p| p.to_string()).unwrap_or_else(|| "?".to_owned());
                    let user_str = node.user.as_deref().unwrap_or("-");
                    let cmd = node.command_line.as_deref().unwrap_or("-");
                    let label_str = format!("{image_name} ({pid_str})  |  {user_str}  |  {cmd}");

                    let mut checked = self.state.hunt_checked.contains(&guid);
                    if ui.checkbox(&mut checked, &label_str).changed() {
                        if checked {
                            self.state.hunt_checked.insert(guid);
                        } else {
                            self.state.hunt_checked.remove(&guid);
                        }
                    }
                }
            });
    }

    fn hunt_node_matches(state: &crate::state::AppState, guid: &ProcessGuid, filter_lc: &str) -> bool {
        if filter_lc.is_empty() {
            return true;
        }
        let Some(node) = state.process_tree.get(guid) else { return false; };
        let image_lc = node.image_name.as_deref().unwrap_or("").to_lowercase();
        let cmd_lc = node.command_line.as_deref().unwrap_or("").to_lowercase();
        let user_lc = node.user.as_deref().unwrap_or("").to_lowercase();
        let pid_str = node.pid.map(|p| p.to_string()).unwrap_or_default();
        image_lc.contains(filter_lc)
            || cmd_lc.contains(filter_lc)
            || user_lc.contains(filter_lc)
            || pid_str.contains(filter_lc)
    }

    fn hunt_collect_preorder(
        state: &crate::state::AppState,
        guid: ProcessGuid,
        filter_lc: &str,
        out: &mut Vec<ProcessGuid>,
    ) {
        let Some(node) = state.process_tree.get(&guid) else { return; };
        if Self::hunt_node_matches(state, &guid, filter_lc) {
            out.push(guid);
        }
        let children = node.children.clone();
        for child in children {
            Self::hunt_collect_preorder(state, child, filter_lc, out);
        }
    }

    fn render_hunt_timeline_popup(&mut self, ctx: &egui::Context) {
        if !self.state.hunt_popup_open {
            return;
        }

        let guids: Vec<ProcessGuid> = self.state.hunt_checked.iter().copied().collect();
        if guids.is_empty() {
            self.state.hunt_popup_open = false;
            return;
        }

        let mut open = self.state.hunt_popup_open;
        egui::Window::new("Hunt Timeline")
            .open(&mut open)
            .resizable(true)
            .default_size([900.0, 400.0])
            .min_size([400.0, 200.0])
            .show(ctx, |ui| {
                // ── Determine global time range ───────────────────────────
                let mut t_start_opt: Option<systrace_core::Timestamp> = None;
                let mut t_end_opt: Option<systrace_core::Timestamp> = None;
                for &guid in &guids {
                    if let Some(node) = self.state.process_tree.get(&guid) {
                        let ts = node.start_time;
                        t_start_opt = Some(match t_start_opt {
                            Some(t) => t.min(ts),
                            None => ts,
                        });
                        if let Some(te) = node.end_time {
                            t_end_opt = Some(match t_end_opt {
                                Some(t) => t.max(te),
                                None => te,
                            });
                        }
                    }
                    for &idx in self.state.event_store.events_for_process(&guid) {
                        let ev_t = self.state.event_store.events[idx].time_created;
                        t_start_opt = Some(match t_start_opt {
                            Some(t) => t.min(ev_t),
                            None => ev_t,
                        });
                        t_end_opt = Some(match t_end_opt {
                            Some(t) => t.max(ev_t),
                            None => ev_t,
                        });
                    }
                }
                let (Some(t_start), Some(t_end)) = (t_start_opt, t_end_opt) else {
                    ui.label("No event data for selected processes.");
                    return;
                };
                let total_secs = ((t_end - t_start).num_milliseconds() as f64 / 1000.0).max(0.001);

                // ── Controls ─────────────────────────────────────────────
                ui.horizontal(|ui| {
                    if ui.small_button("Fit").clicked() {
                        self.state.hunt_zoom = 0.0;
                        self.state.hunt_pan = 0.0;
                    }
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
                        let (rect, _) = ui.allocate_exact_size(egui::vec2(10.0, 10.0), egui::Sense::hover());
                        ui.painter().circle_filled(rect.center(), 5.0, color);
                        ui.label(label);
                    }
                });
                ui.separator();

                // ── Scroll area for swim lanes + time axis ────────────────
                let lane_h = 30.0_f32;
                let axis_h = 24.0_f32;
                let label_w = 180.0_f32;
                let n_lanes = guids.len();
                let content_h = lane_h * n_lanes as f32 + axis_h;
                let available_w = ui.available_width().max(200.0);
                let draw_w = available_w - label_w;

                // Auto-fit zoom
                if self.state.hunt_zoom <= 0.0 {
                    self.state.hunt_zoom = (draw_w as f64 / total_secs).max(0.001);
                    self.state.hunt_pan = 0.0;
                }

                let scroll_area_rect = ui.available_rect_before_wrap();
                // Mouse wheel zoom for the drawing area
                let scroll_y = ui.ctx().input(|i| {
                    if i.pointer.hover_pos().map(|p| scroll_area_rect.contains(p)).unwrap_or(false) {
                        i.smooth_scroll_delta.y
                    } else {
                        0.0
                    }
                });
                if scroll_y.abs() > 0.1 {
                    let zoom_factor = (1.0 + scroll_y as f64 * 0.005).clamp(0.1, 10.0);
                    let cursor_x = ui.ctx().input(|i| i.pointer.hover_pos())
                        .map(|p| (p.x - scroll_area_rect.left() - label_w).max(0.0))
                        .unwrap_or(draw_w / 2.0) as f64;
                    let cursor_t = self.state.hunt_pan + cursor_x / self.state.hunt_zoom;
                    self.state.hunt_zoom *= zoom_factor;
                    self.state.hunt_pan = cursor_t - cursor_x / self.state.hunt_zoom;
                }
                // Clamp pan
                let view_secs = draw_w as f64 / self.state.hunt_zoom;
                self.state.hunt_pan = self.state.hunt_pan
                    .clamp(-view_secs * 0.1, (total_secs + view_secs * 0.1).max(0.0));

                egui::ScrollArea::vertical()
                    .auto_shrink([false; 2])
                    .show(ui, |ui| {
                        let (response, painter) = ui.allocate_painter(
                            egui::vec2(available_w, content_h),
                            egui::Sense::drag(),
                        );
                        let rect = response.rect;

                        if response.dragged() {
                            let delta = response.drag_delta().x as f64;
                            self.state.hunt_pan -= delta / self.state.hunt_zoom;
                        }

                        painter.rect_filled(rect, 0.0, egui::Color32::from_gray(18));

                        // ── Draw each swim lane ───────────────────────────
                        let hover_pos = response.hover_pos();
                        let mut tooltip_info: Option<(egui::Pos2, u16, systrace_core::Timestamp, String)> = None;

                        for (lane_idx, &guid) in guids.iter().enumerate() {
                            let lane_y = rect.top() + lane_idx as f32 * lane_h;
                            let lane_rect = egui::Rect::from_min_size(
                                egui::pos2(rect.left(), lane_y),
                                egui::vec2(available_w, lane_h),
                            );

                            // Alternating background
                            if lane_idx % 2 == 1 {
                                painter.rect_filled(lane_rect, 0.0, egui::Color32::from_gray(24));
                            }

                            // Label (image name + pid)
                            let label_str = if let Some(node) = self.state.process_tree.get(&guid) {
                                let name = node.image_name.as_deref().unwrap_or("?");
                                let pid = node.pid.map(|p| p.to_string()).unwrap_or_else(|| "?".to_owned());
                                format!("{name} ({pid})")
                            } else {
                                "?".to_owned()
                            };
                            painter.text(
                                egui::pos2(rect.left() + 4.0, lane_y + lane_h / 2.0),
                                egui::Align2::LEFT_CENTER,
                                &label_str,
                                egui::FontId::proportional(11.0),
                                egui::Color32::from_gray(200),
                            );

                            // Separator line below lane
                            painter.line_segment(
                                [
                                    egui::pos2(rect.left(), lane_y + lane_h - 1.0),
                                    egui::pos2(rect.right(), lane_y + lane_h - 1.0),
                                ],
                                egui::Stroke::new(0.5, egui::Color32::from_gray(40)),
                            );

                            let dot_y = lane_y + lane_h / 2.0;
                            let draw_left = rect.left() + label_w;

                            // Bucket events for this lane
                            let mut buckets: std::collections::HashMap<i32, (u16, usize)> =
                                std::collections::HashMap::new();
                            for &idx in self.state.event_store.events_for_process(&guid) {
                                let ev = &self.state.event_store.events[idx];
                                let t_off = (ev.time_created - t_start).num_milliseconds() as f64 / 1000.0;
                                let x = draw_left + ((t_off - self.state.hunt_pan) * self.state.hunt_zoom) as f32;
                                if x < draw_left - 10.0 || x > rect.right() + 10.0 { continue; }
                                let col = x as i32;
                                buckets.entry(col)
                                    .and_modify(|(_, cnt)| *cnt += 1)
                                    .or_insert((ev.event_id, 1));
                            }

                            for (&col, &(event_id, count)) in &buckets {
                                let x = col as f32 + 0.5;
                                let pos = egui::pos2(x, dot_y);
                                let radius = if count > 1 { 5.5_f32 } else { 3.5 };
                                let color = Self::event_color(event_id);
                                if count > 1 {
                                    painter.circle_stroke(
                                        pos, radius + 1.5,
                                        egui::Stroke::new(1.0, color.linear_multiply(0.5)),
                                    );
                                }
                                painter.circle_filled(pos, radius, color);

                                if let Some(hp) = hover_pos {
                                    if (hp.x - x).abs() <= radius + 3.0 && (hp.y - dot_y).abs() <= radius + 3.0 {
                                        painter.circle_stroke(
                                            pos, radius + 3.0,
                                            egui::Stroke::new(1.5, egui::Color32::WHITE),
                                        );
                                        // Collect first event time for this bucket for tooltip
                                        if let Some(&idx) = self.state.event_store
                                            .events_for_process(&guid)
                                            .iter()
                                            .find(|&&i| {
                                                let ev = &self.state.event_store.events[i];
                                                let t_off = (ev.time_created - t_start).num_milliseconds() as f64 / 1000.0;
                                                let ex = draw_left + ((t_off - self.state.hunt_pan) * self.state.hunt_zoom) as f32;
                                                ex as i32 == col
                                            })
                                        {
                                            let ev = &self.state.event_store.events[idx];
                                            tooltip_info = Some((pos, event_id, ev.time_created, label_str.clone()));
                                        }
                                    }
                                }
                            }
                        }

                        // ── Time axis at bottom ───────────────────────────
                        let axis_y = rect.top() + n_lanes as f32 * lane_h;
                        let draw_left = rect.left() + label_w;

                        painter.line_segment(
                            [egui::pos2(draw_left, axis_y), egui::pos2(rect.right(), axis_y)],
                            egui::Stroke::new(1.0, egui::Color32::from_gray(100)),
                        );

                        let tick_interval = Self::nice_tick_interval(view_secs);
                        let first_tick = (self.state.hunt_pan / tick_interval).ceil() * tick_interval;
                        let mut t = first_tick;
                        while t <= self.state.hunt_pan + view_secs {
                            let x = draw_left + ((t - self.state.hunt_pan) * self.state.hunt_zoom) as f32;
                            if x >= draw_left && x <= rect.right() {
                                painter.line_segment(
                                    [egui::pos2(x, axis_y), egui::pos2(x, axis_y + 5.0)],
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
                                    egui::pos2(x + 2.0, axis_y + 6.0),
                                    egui::Align2::LEFT_TOP,
                                    label,
                                    egui::FontId::proportional(10.0),
                                    egui::Color32::from_gray(150),
                                );
                            }
                            t += tick_interval;
                        }

                        // ── Tooltip ───────────────────────────────────────
                        if let Some((dot_pos, event_id, ev_time, proc_label)) = tooltip_info {
                            let ts_str = panels::fmt_time(ev_time);
                            egui::show_tooltip_at(
                                ui.ctx(),
                                ui.layer_id(),
                                egui::Id::new("hunt_timeline_tip"),
                                egui::pos2(dot_pos.x + 8.0, dot_pos.y - 12.0),
                                |ui| {
                                    ui.label(&proc_label);
                                    ui.label(format!("EventID {}: {}", event_id, Self::event_label(event_id)));
                                    ui.label(format!("Time: {ts_str}"));
                                },
                            );
                        }
                    });
            });
        self.state.hunt_popup_open = open;
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

                // Recent files submenu
                let recent = self.state.recent_files.clone();
                if !recent.is_empty() {
                    ui.menu_button("Recent Files", |ui| {
                        for path in &recent {
                            let label = path
                                .file_name()
                                .and_then(|n| n.to_str())
                                .unwrap_or("(unknown)");
                            if ui.button(label).clicked() {
                                self.open_file(path.clone());
                                ui.close_menu();
                            }
                        }
                    });
                }

                ui.separator();

                // Export submenu
                ui.menu_button("Export", |ui| {
                    if ui.button("Events as CSV…").clicked() {
                        self.export_events_csv();
                        ui.close_menu();
                    }
                    if ui.button("Events as JSON…").clicked() {
                        self.export_events_json();
                        ui.close_menu();
                    }
                    if ui.button("Process Tree as DOT…").clicked() {
                        self.export_tree_dot();
                        ui.close_menu();
                    }
                });

                ui.separator();

                // Theme toggle
                let theme_label = if self.state.dark_mode { "☀ Light Mode" } else { "🌙 Dark Mode" };
                if ui.button(theme_label).clicked() {
                    self.state.dark_mode = !self.state.dark_mode;
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

        // Host selector (only shown when multiple hosts are present)
        if let Some(meta) = &self.state.file_metadata {
            if meta.computer_names.len() > 1 {
                let names: Vec<String> = {
                    let mut v: Vec<String> = meta.computer_names.iter().cloned().collect();
                    v.sort();
                    v
                };
                ui.horizontal(|ui| {
                    ui.label("Host:");
                    let current = self.state.selected_host.clone().unwrap_or_else(|| "All".to_owned());
                    egui::ComboBox::from_id_salt("host_selector")
                        .selected_text(&current)
                        .show_ui(ui, |ui| {
                            if ui.selectable_label(self.state.selected_host.is_none(), "All").clicked() {
                                self.state.selected_host = None;
                            }
                            for name in &names {
                                let sel = self.state.selected_host.as_deref() == Some(name.as_str());
                                if ui.selectable_label(sel, name).clicked() {
                                    self.state.selected_host = Some(name.clone());
                                }
                            }
                        });
                });
            }
        }

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

        // Expand All / Collapse All buttons
        ui.horizontal(|ui| {
            if ui.small_button("Expand All").clicked() {
                self.set_all_tree_open(ui.ctx(), true);
            }
            if ui.small_button("Collapse All").clicked() {
                self.set_all_tree_open(ui.ctx(), false);
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
        let computer = node.computer.clone();
        // node borrow on process_tree ends here

        // Host filter (Phase 5: multi-host support)
        if let Some(host) = &self.state.selected_host {
            if computer != *host {
                return;
            }
        }

        // Text filter — exact match, no subtree fallback
        let filter = self.state.search_filter.to_lowercase();
        if !filter.is_empty() && !self.subtree_matches_filter(guid, &filter) {
            return;
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

        // MITRE badge: check if any event for this process has a MITRE technique
        let has_mitre = self
            .state
            .event_store
            .events_for_process(&guid)
            .iter()
            .any(|&idx| self.state.event_store.events[idx].mitre_technique.is_some());
        // Bookmark indicator
        let is_bookmarked = self.state.bookmarks.contains_key(&guid);

        let label = {
            let base = if is_synthetic {
                format!("{image_name} ({pid_str}) [synthetic]")
            } else {
                format!("{image_name} ({pid_str})")
            };
            let mut l = base;
            if has_mitre { l = format!("⚑ {l}"); }
            if is_bookmarked { l = format!("🔖 {l}"); }
            l
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
            TelemetryTab::Detection,
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
                (TelemetryTab::DriversModules, "Modules"),
                (TelemetryTab::Detection, "🔍 Hunt"),
            ] {
                if ui
                    .selectable_label(self.state.active_tab == tab, label)
                    .clicked()
                {
                    self.state.active_tab = tab;
                }
            }
        });

        // Global telemetry filter bar (shown for non-Overview, non-Hunt tabs)
        if self.state.active_tab != TelemetryTab::Overview
            && self.state.active_tab != TelemetryTab::Detection
        {
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
            TelemetryTab::Detection => {
                self.render_hunt_tab(ui);
            }
        }
    }

    fn render_overview(&mut self, ui: &mut Ui) {
        let Some(guid) = self.state.selected_process else {
            ui.vertical_centered(|ui| {
                ui.add_space(40.0);
                ui.label("Select a process in the tree on the left.");
            });
            return;
        };

        // Snapshot all node fields as owned values so the borrow on process_tree
        // is released before we need &mut self inside the closure (for bookmarks).
        let (
            ov_image, ov_pid, ov_guid_str, ov_cmdline, ov_user, ov_integrity, ov_logon_id,
            ov_computer, ov_start, ov_end, ov_hashes, ov_parent_image, ov_parent_pid,
        ) = match self.state.process_tree.get(&guid) {
            None => return,
            Some(node) => (
                node.image.clone().unwrap_or_else(|| "-".to_owned()),
                node.pid.map(|p| p.to_string()).unwrap_or_else(|| "-".to_owned()),
                {
                    let s = format!("{:x?}", guid)
                        .replace(", ", "").replace('[', "").replace(']', "");
                    s
                },
                node.command_line.clone().unwrap_or_else(|| "-".to_owned()),
                node.user.clone().unwrap_or_else(|| "-".to_owned()),
                node.integrity_level.clone().unwrap_or_else(|| "-".to_owned()),
                node.logon_id.clone().unwrap_or_else(|| "-".to_owned()),
                node.computer.clone(),
                node.start_time.format("%Y-%m-%d %H:%M:%S%.3f UTC").to_string(),
                node.end_time
                    .map(|t| t.format("%Y-%m-%d %H:%M:%S%.3f UTC").to_string())
                    .unwrap_or_else(|| "Not Detected".to_owned()),
                node.hashes.clone().unwrap_or_else(|| "-".to_owned()),
                node.parent_image.clone().unwrap_or_else(|| "-".to_owned()),
                node.parent_pid.map(|p| p.to_string()).unwrap_or_else(|| "-".to_owned()),
            ),
        };
        // process_tree borrow dropped here — can now use &mut self below

        egui::ScrollArea::vertical()
            .auto_shrink([false; 2])
            .show(ui, |ui| {
                ui.heading("Process Details");
                ui.add_space(4.0);

                egui::ScrollArea::horizontal()
                    .id_salt("proc_detail_hscroll")
                    .show(ui, |ui| {
                        egui::Grid::new("overview_grid")
                            .num_columns(2)
                            .striped(true)
                            .min_col_width(100.0)
                            .show(ui, |ui| {
                                macro_rules! row {
                                    ($label:expr, $val:expr) => {{
                                        ui.strong($label);
                                        let v: &str = $val;
                                        ui.label(v).context_menu(|ui| {
                                            if ui.button("Copy").clicked() {
                                                ui.ctx().copy_text(v.to_owned());
                                                ui.close_menu();
                                            }
                                        });
                                        ui.end_row();
                                    }};
                                    ($label:expr, $val:expr, color: $color:expr) => {{
                                        ui.strong($label);
                                        let v: &str = $val;
                                        ui.label(egui::RichText::new(v).color($color).strong()).context_menu(|ui| {
                                            if ui.button("Copy").clicked() {
                                                ui.ctx().copy_text(v.to_owned());
                                                ui.close_menu();
                                            }
                                        });
                                        ui.end_row();
                                    }};
                                }

                                row!("Image", ov_image.as_str());
                                row!("PID", ov_pid.as_str());
                                row!("GUID", ov_guid_str.as_str());
                                row!("Command Line", ov_cmdline.as_str());

                                // User: green if SYSTEM
                                if ov_user.to_uppercase().contains("SYSTEM") {
                                    row!("User", ov_user.as_str(), color: egui::Color32::from_rgb(80, 180, 80));
                                } else {
                                    row!("User", ov_user.as_str());
                                }

                                // Integrity: red for System, orange for High
                                {
                                    let integrity_upper = ov_integrity.to_uppercase();
                                    if integrity_upper == "SYSTEM" {
                                        row!("Integrity", ov_integrity.as_str(), color: egui::Color32::from_rgb(220, 60, 60));
                                    } else if integrity_upper == "HIGH" {
                                        row!("Integrity", ov_integrity.as_str(), color: egui::Color32::from_rgb(255, 165, 0));
                                    } else {
                                        row!("Integrity", ov_integrity.as_str());
                                    }
                                }
                                row!("Logon ID", ov_logon_id.as_str());
                                row!("Computer", ov_computer.as_str());
                                row!("Start Time", ov_start.as_str());
                                row!("End Time", ov_end.as_str());
                                // Split hashes into separate rows (MD5, SHA256, IMPHASH)
                                {
                                    let mut md5 = "-";
                                    let mut sha256 = "-";
                                    let mut imphash = "-";
                                    for part in ov_hashes.split(',') {
                                        let part = part.trim();
                                        if let Some(val) = part.strip_prefix("MD5=") {
                                            md5 = val;
                                        } else if let Some(val) = part.strip_prefix("SHA256=") {
                                            sha256 = val;
                                        } else if let Some(val) = part.strip_prefix("IMPHASH=") {
                                            imphash = val;
                                        }
                                    }
                                    row!("MD5", md5);
                                    row!("SHA256", sha256);
                                    row!("IMPHASH", imphash);
                                }
                                row!("Parent Image", ov_parent_image.as_str());
                                row!("Parent PID", ov_parent_pid.as_str());
                            });
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
                                ui.label(egui::RichText::new(n.to_string()).color(egui::Color32::from_rgb(80, 200, 100)).strong());
                            } else {
                                ui.label("0");
                            }
                            ui.end_row();
                        }
                    });

                // MITRE ATT&CK annotations
                let mitre_events: Vec<_> = self
                    .state
                    .event_store
                    .events_for_process(&guid)
                    .iter()
                    .filter_map(|&idx| {
                        let ev = &self.state.event_store.events[idx];
                        ev.mitre_technique.as_ref().map(|mt| (ev.event_id, mt.id.clone(), mt.name.clone()))
                    })
                    .collect();
                if !mitre_events.is_empty() {
                    ui.add_space(12.0);
                    ui.separator();
                    ui.heading("MITRE ATT&CK");
                    ui.add_space(4.0);
                    let mut seen = std::collections::HashSet::new();
                    for (eid, tid, tname) in &mitre_events {
                        if seen.insert((eid, tid)) {
                            ui.horizontal(|ui| {
                                ui.colored_label(egui::Color32::from_rgb(220, 120, 60), tid);
                                ui.label(format!("— {tname}  (EventID {eid})"));
                            });
                        }
                    }
                }

                // Notes / bookmarks
                ui.add_space(12.0);
                ui.separator();
                ui.horizontal(|ui| {
                    ui.heading("Notes");
                    if self.state.bookmarks.contains_key(&guid) {
                        ui.label("🔖");
                    }
                });
                ui.add_space(4.0);
                let note = self.state.bookmarks.entry(guid).or_default();
                ui.add(
                    egui::TextEdit::multiline(note)
                        .hint_text("Add investigation notes here…")
                        .desired_width(f32::INFINITY)
                        .desired_rows(4),
                );
            });
    }
}

impl eframe::App for SysTraceApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Apply theme
        if self.state.dark_mode {
            ctx.set_visuals(egui::Visuals::dark());
        } else {
            ctx.set_visuals(egui::Visuals::light());
        }

        // Drag-and-drop file loading
        let dropped = ctx.input(|i| i.raw.dropped_files.clone());
        if let Some(file) = dropped.into_iter().find(|f| f.path.is_some()) {
            if let Some(path) = file.path {
                self.open_file(path);
            }
        }

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

        // Hunt timeline popup (floating window)
        self.render_hunt_timeline_popup(ctx);

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
