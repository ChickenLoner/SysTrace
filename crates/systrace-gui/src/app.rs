use std::cell::Cell;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crossbeam_channel::{Receiver, TryRecvError};
use eframe::egui::{self, Ui};
use systrace_core::{EventDetail, ProcessGuid, SysmonEvent};

use crate::panels;
use crate::state::{AppState, FileMetadata, HelpTab, SpecialFilter, TelemetryTab};

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

/// Draw a horizontal bar chart for stats sections.
/// A small metric card: coloured big number + muted label below.
fn stat_card(ui: &mut egui::Ui, value: &str, label: &str, color: egui::Color32) {
    egui::Frame::new()
        .fill(ui.visuals().faint_bg_color)
        .corner_radius(egui::CornerRadius::same(6))
        .inner_margin(egui::Margin::symmetric(8, 8))
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.vertical_centered(|ui| {
                ui.label(egui::RichText::new(value).strong().size(22.0).color(color));
                ui.label(egui::RichText::new(label).small().color(ui.visuals().weak_text_color()));
            });
        });
}

/// `items`: (label, count, bar_color). `total`: denominator for %.
fn stats_bar_chart(ui: &mut egui::Ui, items: &[(String, usize, egui::Color32)], total: usize) {
    if items.is_empty() { return; }
    let bar_h   = 18.0;
    let gap     = 2.0;
    let label_w = 160.0;
    let count_w = 90.0;
    let bar_max = 160.0_f32; // fixed width — keeps layout compact

    for (label, count, color) in items {
        ui.horizontal(|ui| {
            ui.add_sized(
                [label_w, bar_h],
                egui::Label::new(egui::RichText::new(label).small()).truncate(),
            );
            let pct = if total > 0 { *count as f32 / total as f32 } else { 0.0 };
            let (rect, _) = ui.allocate_exact_size(
                egui::vec2(bar_max, bar_h - gap * 2.0),
                egui::Sense::hover(),
            );
            let rounding = egui::CornerRadius::same(3);
            ui.painter().rect_filled(rect, rounding, ui.visuals().faint_bg_color);
            let fill_w = (pct * bar_max).max(if *count > 0 { 3.0 } else { 0.0 });
            let fill = egui::Rect::from_min_size(rect.min, egui::vec2(fill_w, rect.height()));
            ui.painter().rect_filled(fill, rounding, *color);
            ui.add_sized(
                [count_w, bar_h],
                egui::Label::new(
                    egui::RichText::new(format!("{count}  {:.1}%", pct * 100.0)).small(),
                ),
            );
        });
    }
}

impl SysTraceApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        // Load Windows symbol/emoji fonts as fallbacks so ✕ ⚑ 🔍 🔖 ⚠ render correctly.
        let mut fonts = egui::FontDefinitions::default();
        for (name, path) in [
            ("seguisym",  "C:/Windows/Fonts/seguisym.ttf"),
            ("seguiemj",  "C:/Windows/Fonts/seguiemj.ttf"),
        ] {
            if let Ok(data) = std::fs::read(path) {
                fonts.font_data.insert(name.to_owned(), egui::FontData::from_owned(data).into());
                fonts.families
                    .entry(egui::FontFamily::Proportional)
                    .or_default()
                    .push(name.to_owned());
            }
        }
        cc.egui_ctx.set_fonts(fonts);
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
                    let _ = systrace_core::parse_file_auto(&path2, &etx, &br, &mut errors, &r);
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

        // Collect unique MITRE technique IDs across all events.
        self.state.available_mitre = self
            .state
            .event_store
            .events
            .iter()
            .filter_map(|ev| ev.mitre_technique.as_ref().map(|m| m.id.clone()))
            .collect();
        self.state.mitre_filter.clear();

        // ── Precompute for SpecialFilter ──────────────────────────────────────

        // Network processes: have at least one EventId 3 (NetworkConnect) or 22 (DnsQuery).
        let mut network_processes = std::collections::HashSet::new();
        for &eid in &[3u16, 22] {
            for &idx in self.state.event_store.events_for_type(eid) {
                if let Some(guid) = self.state.event_store.events[idx].process_guid {
                    network_processes.insert(guid);
                }
            }
        }
        self.state.network_processes = network_processes;

        // Persistence processes: registry events (12-14) touching known paths,
        // or process image_name is schtasks.exe / at.exe.
        const PERSIST_PATTERNS: &[&str] = &[
            r"\currentversion\run\",
            r"\currentversion\runonce\",
            r"\currentcontrolset\services\",
            r"\schedule\taskcache\",
            r"\microsoft\wbem\",
            r"\currentversion\winlogon\",
            r"\currentversion\windows\appinitdlls",
            r"\currentversion\explorer\shell folders\",
            r"\startupapproved\",
        ];
        let mut persistence_processes = std::collections::HashSet::new();
        for &eid in &[12u16, 13, 14] {
            for &idx in self.state.event_store.events_for_type(eid) {
                let ev = &self.state.event_store.events[idx];
                if let EventDetail::RegistryEvent { target_object: Some(path), .. } = &ev.detail {
                    let path_lc = path.to_lowercase();
                    if PERSIST_PATTERNS.iter().any(|p| path_lc.contains(p)) {
                        if let Some(guid) = ev.process_guid {
                            persistence_processes.insert(guid);
                        }
                    }
                }
            }
        }
        for node in self.state.process_tree.nodes.values() {
            if let Some(ref name) = node.image_name {
                let lc = name.to_lowercase();
                if lc == "schtasks.exe" || lc == "at.exe" {
                    persistence_processes.insert(node.guid);
                }
            }
        }
        self.state.persistence_processes = persistence_processes;

        // Available users from real (non-synthetic) process nodes (sorted).
        let mut user_set: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        for node in self.state.process_tree.nodes.values() {
            if node.is_synthetic { continue; }
            if let Some(ref user) = node.user {
                user_set.insert(user.clone());
            }
        }
        self.state.available_users = user_set.into_iter().collect();

        // Reset the filter UI state.
        self.state.special_filter = SpecialFilter::default();
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
        let sf = &self.state.special_filter;
        let mitre_active = !self.state.mitre_filter.is_empty();

        if !sf.any_active() && !mitre_active {
            return true;
        }

        // Look up the node for integrity / user checks.
        let node = match self.state.process_tree.get(guid) {
            Some(n) => n,
            None => return true, // synthetic/unknown — don't hide
        };

        // ── Integrity Level (AND) ────────────────────────────────────────────
        if sf.any_integrity_active() {
            let il = node.integrity_level.as_deref().unwrap_or("").to_lowercase();
            let passes = (sf.integrity_system && il == "system")
                || (sf.integrity_high   && il == "high")
                || (sf.integrity_medium && il == "medium")
                || (sf.integrity_low    && il == "low");
            if !passes {
                return false;
            }
        }

        // ── User (AND) ───────────────────────────────────────────────────────
        if !sf.users_checked.is_empty() {
            let user = node.user.as_deref().unwrap_or("");
            if !sf.users_checked.contains(user) {
                return false;
            }
        }

        // ── Network Activity (AND) ───────────────────────────────────────────
        if sf.network && !self.state.network_processes.contains(guid) {
            return false;
        }

        // ── Persistence Activity (AND) ───────────────────────────────────────
        if sf.persistence && !self.state.persistence_processes.contains(guid) {
            return false;
        }

        // ── MITRE Techniques (AND) ───────────────────────────────────────────
        if mitre_active {
            let has_match = self
                .state
                .event_store
                .events_for_process(guid)
                .iter()
                .any(|&idx| {
                    self.state.event_store.events[idx]
                        .mitre_technique
                        .as_ref()
                        .map(|m| self.state.mitre_filter.contains(&m.id))
                        .unwrap_or(false)
                });
            if !has_match {
                return false;
            }
        }

        true
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

    /// Returns true if this node OR any descendant passes the event/special filter.
    /// Allows ancestor nodes to remain visible when a child matches the filter.
    fn subtree_passes_event_filter(&self, guid: ProcessGuid) -> bool {
        if self.node_passes_event_filter(&guid) {
            return true;
        }
        let Some(node) = self.state.process_tree.get(&guid) else {
            return false;
        };
        let children = node.children.clone();
        children.iter().any(|&c| self.subtree_passes_event_filter(c))
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
    // Timeline tab
    // -----------------------------------------------------------------------

    fn render_timeline_tab(&mut self, ui: &mut Ui) {
        if self.state.event_store.len() == 0 {
            panels::render_empty(ui, "No data loaded \u{2014} open a file first.");
            return;
        }

        if !self.state.timeline_generated {
            panels::render_empty(ui, "Select processes in the tree (checkboxes) and click Generate Timeline.");
            return;
        }

        // Event filter bar
        ui.horizontal(|ui| {
            ui.label("Filter events:");
            egui::TextEdit::singleline(&mut self.state.timeline_event_filter)
                .hint_text("Filter rows\u{2026}")
                .desired_width(ui.available_width() - 40.0)
                .show(ui);
            if !self.state.timeline_event_filter.is_empty() && ui.small_button("\u{2715}").clicked() {
                self.state.timeline_event_filter.clear();
            }
        });
        ui.separator();

        let events = self.state.timeline_events.clone();
        let filter = self.state.timeline_event_filter.clone();
        panels::timeline::render_timeline_table(
            ui,
            &self.state.event_store,
            &self.state.process_tree,
            &self.state.rodeo,
            &events,
            &mut self.state.tab_timeline,
            &filter,
        );
    }



    // -----------------------------------------------------------------------
    // Rendering
    // -----------------------------------------------------------------------

    fn render_menu(&mut self, ui: &mut Ui, ctx: &egui::Context) {
        egui::menu::bar(ui, |ui| {
            ui.menu_button("File", |ui| {
                if ui.button("Open…").clicked() {
                    if let Some(path) = rfd::FileDialog::new()
                        .add_filter("Sysmon Logs", &["evtx", "json", "ndjson", "csv"])
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

            if ui.button("Stats").clicked() {
                self.state.show_stats = !self.state.show_stats;
            }

            if ui.button("Help").clicked() {
                self.state.show_help = !self.state.show_help;
            }
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

        let is_timeline_mode = self.state.active_tab == TelemetryTab::Timeline;

        if is_timeline_mode {
            // Timeline mode: show selection controls instead of event type filter
            ui.horizontal(|ui| {
                if ui.small_button("Select All").clicked() {
                    let filter_lc = self.state.search_filter.to_lowercase();
                    let guids: Vec<_> = self.state.process_tree.nodes.keys().copied()
                        .filter(|g| {
                            if filter_lc.is_empty() { return true; }
                            self.subtree_matches_filter(*g, &filter_lc)
                        })
                        .collect();
                    self.state.timeline_checked.extend(guids);
                }
                if ui.small_button("Deselect All").clicked() {
                    self.state.timeline_checked.clear();
                    self.state.timeline_generated = false;
                    self.state.timeline_events.clear();
                }
            });

            // Generate Timeline button
            let checked_count = self.state.timeline_checked.len();
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
                    let mut indices: Vec<usize> = Vec::new();
                    for &guid in &self.state.timeline_checked {
                        indices.extend(self.state.event_store.events_for_process(&guid));
                    }
                    indices.sort_unstable();
                    indices.dedup();
                    indices.sort_by_key(|&i| self.state.event_store.events[i].time_created);
                    self.state.timeline_events = indices;
                    self.state.timeline_generated = true;
                    self.state.tab_timeline.selected_row = None;
                    self.state.timeline_event_filter.clear();
                }
            });
        }

        ui.separator();

        // ── Toolbar row: Expand All / Collapse All / Filter toggle ───────────
        {
            let sf_count = self.state.special_filter.active_category_count();
            let mitre_count = if self.state.mitre_filter.is_empty() { 0 } else { 1 };
            let total_active = sf_count + mitre_count;
            let any_active = total_active > 0;

            ui.horizontal(|ui| {
                if ui.small_button("Expand All").clicked() {
                    self.set_all_tree_open(ui.ctx(), true);
                }
                if ui.small_button("Collapse All").clicked() {
                    self.set_all_tree_open(ui.ctx(), false);
                }
                let label = if total_active > 0 {
                    format!("Filter ({})", total_active)
                } else {
                    "Filter".to_string()
                };
                let mut btn = egui::Button::new(label);
                if self.state.show_filters || any_active {
                    btn = btn.fill(ui.visuals().selection.bg_fill);
                }
                if ui.add(btn).clicked() {
                    self.state.show_filters = !self.state.show_filters;
                }
                if any_active && ui.small_button("✕").clicked() {
                    self.state.special_filter = SpecialFilter::default();
                    self.state.mitre_filter.clear();
                }
            });

            if self.state.show_filters {
                ui.indent("filter_panel", |ui| {
                    // ── Integrity Level ───────────────────────────────────
                    egui::CollapsingHeader::new("Integrity Level")
                        .default_open(false)
                        .show(ui, |ui| {
                            ui.checkbox(&mut self.state.special_filter.integrity_system, "System");
                            ui.checkbox(&mut self.state.special_filter.integrity_high,   "High");
                            ui.checkbox(&mut self.state.special_filter.integrity_medium, "Medium");
                            ui.checkbox(&mut self.state.special_filter.integrity_low,    "Low");
                            if self.state.special_filter.any_integrity_active()
                                && ui.small_button("Clear").clicked()
                            {
                                self.state.special_filter.integrity_system = false;
                                self.state.special_filter.integrity_high   = false;
                                self.state.special_filter.integrity_medium = false;
                                self.state.special_filter.integrity_low    = false;
                            }
                        });

                    // ── User ──────────────────────────────────────────────
                    if !self.state.available_users.is_empty() {
                        let users: Vec<String> = self.state.available_users.clone();
                        egui::CollapsingHeader::new("User")
                            .default_open(false)
                            .show(ui, |ui| {
                                for user in &users {
                                    let mut checked = self.state.special_filter.users_checked.contains(user);
                                    if ui.checkbox(&mut checked, user.as_str()).changed() {
                                        if checked {
                                            self.state.special_filter.users_checked.insert(user.clone());
                                        } else {
                                            self.state.special_filter.users_checked.remove(user);
                                        }
                                    }
                                }
                                if !self.state.special_filter.users_checked.is_empty()
                                    && ui.small_button("Clear").clicked()
                                {
                                    self.state.special_filter.users_checked.clear();
                                }
                            });
                    }

                    // ── Activity ──────────────────────────────────────────
                    egui::CollapsingHeader::new("Activity")
                        .default_open(false)
                        .show(ui, |ui| {
                            ui.checkbox(&mut self.state.special_filter.network,     "Network Connection");
                            ui.checkbox(&mut self.state.special_filter.persistence, "Persistence Activity");
                            if (self.state.special_filter.network || self.state.special_filter.persistence)
                                && ui.small_button("Clear").clicked()
                            {
                                self.state.special_filter.network     = false;
                                self.state.special_filter.persistence = false;
                            }
                        });

                    // ── MITRE Techniques ──────────────────────────────────
                    if !self.state.available_mitre.is_empty() {
                        let mitre_ids: Vec<String> = self.state.available_mitre.iter().cloned().collect();
                        egui::CollapsingHeader::new("MITRE Techniques")
                            .default_open(false)
                            .show(ui, |ui| {
                                for id in &mitre_ids {
                                    let mut checked = self.state.mitre_filter.contains(id);
                                    if ui.checkbox(&mut checked, id.as_str()).changed() {
                                        if checked {
                                            self.state.mitre_filter.insert(id.clone());
                                        } else {
                                            self.state.mitre_filter.remove(id);
                                        }
                                    }
                                }
                                if !self.state.mitre_filter.is_empty()
                                    && ui.small_button("Clear All").clicked()
                                {
                                    self.state.mitre_filter.clear();
                                }
                            });
                    }
                });
            }
        }

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

        // Event type filter — guard: skip entire subtree if nothing in it passes
        if !self.subtree_passes_event_filter(guid) {
            return;
        }
        // If this node itself fails the filter, skip its row but still recurse into children
        // so that deeply nested matching processes remain reachable.
        if !self.node_passes_event_filter(&guid) {
            for child in children {
                self.render_tree_node(ui, child);
            }
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
        let is_timeline_mode = self.state.active_tab == TelemetryTab::Timeline;

        if children.is_empty() {
            ui.horizontal(|ui| {
                // Timeline checkbox (before the label)
                if is_timeline_mode {
                    let mut checked = self.state.timeline_checked.contains(&guid);
                    if ui.checkbox(&mut checked, "").changed() {
                        if checked {
                            self.state.timeline_checked.insert(guid);
                        } else {
                            self.state.timeline_checked.remove(&guid);
                        }
                    }
                }
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
            });
        } else {
            let id = tree_node_id(guid);
            let cs = egui::collapsing_header::CollapsingState::load_with_default_open(
                ui.ctx(),
                id,
                false,
            );

            cs.show_header(ui, |ui| {
                // Timeline checkbox (before the label)
                if is_timeline_mode {
                    let mut checked = self.state.timeline_checked.contains(&guid);
                    if ui.checkbox(&mut checked, "").changed() {
                        if checked {
                            self.state.timeline_checked.insert(guid);
                        } else {
                            self.state.timeline_checked.remove(&guid);
                        }
                    }
                }
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
            TelemetryTab::Timeline,
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
                (TelemetryTab::Detection, "Detection"),
                (TelemetryTab::Timeline, "Timeline"),
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
            && self.state.active_tab != TelemetryTab::Timeline
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
                if let Some(guid) = self.state.selected_process {
                    panels::detection::render_detection_table(
                        ui,
                        &self.state.event_store,
                        guid,
                        &mut self.state.tab_detection,
                        &filter,
                        time_range,
                    );
                } else {
                    panels::render_no_selection(ui);
                }
            }
            TelemetryTab::Timeline => {
                self.render_timeline_tab(ui);
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
            ov_file_version, ov_description, ov_product, ov_company, ov_original_file_name,
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
                node.file_version.clone().unwrap_or_else(|| "-".to_owned()),
                node.description.clone().unwrap_or_else(|| "-".to_owned()),
                node.product.clone().unwrap_or_else(|| "-".to_owned()),
                node.company.clone().unwrap_or_else(|| "-".to_owned()),
                node.original_file_name.clone().unwrap_or_else(|| "-".to_owned()),
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
                                row!("File Version", ov_file_version.as_str());
                                row!("Description", ov_description.as_str());
                                row!("Product", ov_product.as_str());
                                row!("Company", ov_company.as_str());
                                row!("Original File Name", ov_original_file_name.as_str());
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
    // -----------------------------------------------------------------------
    // Stats popup
    // -----------------------------------------------------------------------

    fn render_stats_window(&mut self, ctx: &egui::Context) {
        use crate::panels::{event_color, event_label};

        let mut open = self.state.show_stats;

        egui::Window::new("Statistics")
            .open(&mut open)
            .resizable(true)
            .default_width(460.0)
            .default_height(560.0)
            .show(ctx, |ui| {
                let rodeo = self.state.rodeo.clone();

                // ── Determine host filter ─────────────────────────────────
                let host_filter = self.state.selected_host.as_deref();

                // ── Collect filtered events ───────────────────────────────
                let total_events = self.state.event_store.len();
                let filtered_events: Vec<&systrace_core::SysmonEvent> = self
                    .state
                    .event_store
                    .events
                    .iter()
                    .filter(|ev| {
                        if let Some(host) = host_filter {
                            rodeo.resolve(&ev.computer) == host
                        } else {
                            true
                        }
                    })
                    .collect();
                let filtered_count = filtered_events.len();

                // ── Time range ────────────────────────────────────────────
                let time_range = if filtered_events.is_empty() {
                    None
                } else {
                    let min_t = filtered_events.iter().map(|e| e.time_created).min();
                    let max_t = filtered_events.iter().map(|e| e.time_created).max();
                    min_t.zip(max_t)
                };

                // ── Per-EventID counts ────────────────────────────────────
                let mut event_id_counts: std::collections::BTreeMap<u16, usize> =
                    std::collections::BTreeMap::new();
                for ev in &filtered_events {
                    *event_id_counts.entry(ev.event_id).or_insert(0) += 1;
                }

                // ── Per-computer counts ───────────────────────────────────
                let mut host_counts: std::collections::BTreeMap<String, usize> =
                    std::collections::BTreeMap::new();
                for ev in &filtered_events {
                    let computer = rodeo.resolve(&ev.computer).to_owned();
                    *host_counts.entry(computer).or_insert(0) += 1;
                }

                // ── Process-level stats (nodes matching host filter) ──────
                let mut user_counts: std::collections::BTreeMap<String, usize> =
                    std::collections::BTreeMap::new();
                let mut integrity_counts: std::collections::BTreeMap<String, usize> =
                    std::collections::BTreeMap::new();
                for node in self.state.process_tree.nodes.values() {
                    if let Some(host) = host_filter {
                        if node.computer != host {
                            continue;
                        }
                    }
                    if !node.is_synthetic {
                        let user = node.user.as_deref().unwrap_or("(unknown)").to_owned();
                        *user_counts.entry(user).or_insert(0) += 1;
                        let il = node.integrity_level.as_deref().unwrap_or("(unknown)").to_owned();
                        *integrity_counts.entry(il).or_insert(0) += 1;
                    }
                }

                egui::ScrollArea::vertical().auto_shrink([false; 2]).show(ui, |ui| {
                    // ── Summary cards ─────────────────────────────────────
                    let proc_count = if host_filter.is_some() {
                        user_counts.values().sum::<usize>()
                    } else {
                        self.state.process_tree.nodes.values()
                            .filter(|n| !n.is_synthetic).count()
                    };
                    let event_types_seen = event_id_counts.len();

                    let accent   = ui.visuals().selection.bg_fill;
                    let clr_proc = egui::Color32::from_rgb(60, 180, 100);
                    let clr_type = egui::Color32::from_rgb(210, 140, 40);
                    let clr_dur  = egui::Color32::from_rgb(120, 160, 220);

                    // Row 1: 3 metric cards
                    ui.columns(3, |cols| {
                        stat_card(&mut cols[0], &format!("{filtered_count}"), "Events", accent);
                        stat_card(&mut cols[1], &format!("{proc_count}"), "Processes", clr_proc);
                        stat_card(&mut cols[2], &format!("{event_types_seen}"), "Event Types", clr_type);
                    });

                    ui.add_space(6.0);

                    // Row 2: duration + host
                    if let Some((t_min, t_max)) = time_range {
                        let duration   = t_max - t_min;
                        let total_secs = duration.num_seconds().abs();
                        let h = total_secs / 3600;
                        let m = (total_secs % 3600) / 60;
                        let s = total_secs % 60;
                        let dur_str = if h > 0 { format!("{h}h {m}m {s}s") }
                                      else if m > 0 { format!("{m}m {s}s") }
                                      else { format!("{s}s") };

                        ui.columns(2, |cols| {
                            stat_card(&mut cols[0], &dur_str, "Duration", clr_dur);
                            stat_card(&mut cols[1], host_filter.unwrap_or("All"), "Host", egui::Color32::GRAY);
                        });

                        ui.add_space(6.0);

                        // Time range banner
                        egui::Frame::new()
                            .fill(ui.visuals().faint_bg_color)
                            .corner_radius(egui::CornerRadius::same(4))
                            .inner_margin(egui::Margin::symmetric(10, 6))
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    ui.label(egui::RichText::new(
                                        t_min.format("%Y-%m-%d %H:%M:%S UTC").to_string()
                                    ).small().color(ui.visuals().weak_text_color()));
                                    ui.label(egui::RichText::new("→").small());
                                    ui.label(egui::RichText::new(
                                        t_max.format("%Y-%m-%d %H:%M:%S UTC").to_string()
                                    ).small().color(ui.visuals().weak_text_color()));
                                });
                            });
                    } else {
                        ui.columns(1, |cols| {
                            stat_card(&mut cols[0], host_filter.unwrap_or("All"), "Host", egui::Color32::GRAY);
                        });
                    }

                    ui.add_space(12.0);

                    // ── Integrity distribution ────────────────────────────
                    ui.strong("Integrity Level (Processes)");
                    ui.add_space(4.0);
                    if integrity_counts.is_empty() {
                        ui.label("No process data loaded.");
                    } else {
                        let total_procs: usize = integrity_counts.values().sum();
                        // Order: System, High, Medium, Low, then others
                        let order = ["system","high","medium","low"];
                        let mut items: Vec<(String, usize, egui::Color32)> = order.iter()
                            .filter_map(|k| {
                                integrity_counts.iter()
                                    .find(|(il, _)| il.to_lowercase() == *k)
                                    .map(|(il, &c)| {
                                        let color = match il.to_lowercase().as_str() {
                                            "system" => egui::Color32::from_rgb(200, 60, 60),
                                            "high"   => egui::Color32::from_rgb(210, 120, 40),
                                            "medium" => egui::Color32::from_rgb(180, 180, 50),
                                            _        => egui::Color32::from_rgb(60, 180, 80),
                                        };
                                        (il.clone(), c, color)
                                    })
                            })
                            .collect();
                        // Append any unlisted integrity levels
                        for (il, &c) in &integrity_counts {
                            if !order.iter().any(|k| il.to_lowercase() == *k) {
                                items.push((il.clone(), c, egui::Color32::GRAY));
                            }
                        }
                        stats_bar_chart(ui, &items, total_procs);
                    }

                    ui.add_space(12.0);

                    // ── Per-user process count ────────────────────────────
                    ui.strong("Processes per User");
                    ui.add_space(4.0);
                    if user_counts.is_empty() {
                        ui.label("No process data loaded.");
                    } else {
                        let total_procs: usize = user_counts.values().sum();
                        let palette: &[egui::Color32] = &[
                            egui::Color32::from_rgb(86, 180, 233),
                            egui::Color32::from_rgb(230, 159, 0),
                            egui::Color32::from_rgb(0, 158, 115),
                            egui::Color32::from_rgb(240, 228, 66),
                            egui::Color32::from_rgb(0, 114, 178),
                            egui::Color32::from_rgb(213, 94, 0),
                            egui::Color32::from_rgb(204, 121, 167),
                        ];
                        let mut user_vec: Vec<(&String, usize)> = user_counts.iter()
                            .map(|(u, &c)| (u, c)).collect();
                        user_vec.sort_by(|a, b| b.1.cmp(&a.1));
                        let items: Vec<(String, usize, egui::Color32)> = user_vec.iter()
                            .take(12)
                            .enumerate()
                            .map(|(i, (u, c))| (u.to_string(), *c, palette[i % palette.len()]))
                            .collect();
                        stats_bar_chart(ui, &items, total_procs);
                    }

                    ui.add_space(12.0);

                    // ── Per-EventID breakdown ─────────────────────────────
                    ui.strong("Event Type Breakdown");
                    ui.add_space(4.0);
                    if !event_id_counts.is_empty() {
                        let mut ev_vec: Vec<(u16, usize)> = event_id_counts.iter()
                            .map(|(&id, &c)| (id, c)).collect();
                        ev_vec.sort_by(|a, b| b.1.cmp(&a.1));
                        let items: Vec<(String, usize, egui::Color32)> = ev_vec.iter()
                            .take(20)
                            .map(|(id, c)| {
                                let label = format!("{} — {}", id, event_label(*id));
                                (*c, label, event_color(*id))
                            })
                            .map(|(c, l, col)| (l, c, col))
                            .collect();
                        stats_bar_chart(ui, &items, filtered_count);
                    }

                    ui.add_space(12.0);

                    // ── Host breakdown ────────────────────────────────────
                    if host_counts.len() > 1 {
                        ui.strong("Host / Computer Breakdown");
                        ui.add_space(4.0);
                        let accent = ui.visuals().selection.bg_fill;
                        let mut host_vec: Vec<(&String, usize)> = host_counts.iter()
                            .map(|(h, &c)| (h, c)).collect();
                        host_vec.sort_by(|a, b| b.1.cmp(&a.1));
                        let items: Vec<(String, usize, egui::Color32)> = host_vec.iter()
                            .map(|(h, c)| (h.to_string(), *c, accent))
                            .collect();
                        stats_bar_chart(ui, &items, total_events);
                    }
                });
            });

        self.state.show_stats = open;
    }

    // -----------------------------------------------------------------------
    // Help window
    // -----------------------------------------------------------------------

    fn render_help_window(&mut self, ctx: &egui::Context) {
        let mut open = self.state.show_help;
        egui::Window::new("Help")
            .open(&mut open)
            .resizable(true)
            .default_width(520.0)
            .default_height(420.0)
            .show(ctx, |ui| {
                // Tab bar
                ui.horizontal(|ui| {
                    for (tab, label) in [
                        (HelpTab::ColorGuide, "Color Guide"),
                        (HelpTab::KeyboardShortcuts, "Keyboard Shortcuts"),
                        (HelpTab::FeatureGuide, "Feature Guide"),
                    ] {
                        if ui.selectable_label(self.state.help_tab == tab, label).clicked() {
                            self.state.help_tab = tab;
                        }
                    }
                });
                ui.separator();

                egui::ScrollArea::vertical().auto_shrink([false; 2]).show(ui, |ui| {
                    match self.state.help_tab {
                        HelpTab::ColorGuide => self.render_help_color_guide(ui),
                        HelpTab::KeyboardShortcuts => self.render_help_shortcuts(ui),
                        HelpTab::FeatureGuide => self.render_help_feature_guide(ui),
                    }
                });
            });
        self.state.show_help = open;
    }

    fn render_help_color_guide(&self, ui: &mut egui::Ui) {
        let swatch = |ui: &mut egui::Ui, color: egui::Color32, label: &str| {
            ui.horizontal(|ui| {
                let (rect, _) = ui.allocate_exact_size(
                    egui::vec2(16.0, 16.0),
                    egui::Sense::hover(),
                );
                ui.painter().rect_filled(rect, 2.0, color);
                ui.label(label);
            });
        };

        ui.strong("Process Tree Colors");
        ui.add_space(4.0);
        swatch(ui, egui::Color32::DARK_GRAY,              "Synthetic — process inferred from parent GUID, no EventId 1");
        swatch(ui, egui::Color32::from_rgb(220, 60, 60),  "Injection target — process was accessed/injected into");
        swatch(ui, egui::Color32::from_rgb(80, 180, 80),  "SYSTEM user — process running as SYSTEM");
        swatch(ui, egui::Color32::from_rgb(180, 180, 100),"Terminated — EventId 5 (ProcessTerminate) seen");
        ui.label("(default)  Normal process");

        ui.add_space(10.0);
        ui.strong("Event / Panel Colors");
        ui.add_space(4.0);
        swatch(ui, egui::Color32::from_rgb(60, 130, 220),  "Network — EventId 3/22");
        swatch(ui, egui::Color32::from_rgb(80, 180, 80),   "Files — EventId 11/15/23/26/27/28/29");
        swatch(ui, egui::Color32::from_rgb(220, 140, 40),  "Registry — EventId 12/13/14");
        swatch(ui, egui::Color32::from_rgb(220, 60, 60),   "Injection — EventId 8/10/25");
        swatch(ui, egui::Color32::from_rgb(160, 80, 220),  "Pipes — EventId 17/18");
        swatch(ui, egui::Color32::from_rgb(80, 180, 220),  "Drivers/Modules — EventId 6/7");

        ui.add_space(10.0);
        ui.strong("Integrity Level Colors (Overview tab)");
        ui.add_space(4.0);
        swatch(ui, egui::Color32::from_rgb(220, 60, 60),  "System integrity");
        swatch(ui, egui::Color32::from_rgb(255, 165, 0),  "High integrity");
        ui.label("(default)  Medium / Low integrity");

        ui.add_space(10.0);
        ui.strong("MITRE ATT&CK");
        ui.add_space(4.0);
        swatch(ui, egui::Color32::from_rgb(220, 120, 60), "MITRE technique ID (shown in all telemetry columns)");
        ui.label("  ⚑ flag prefix in tree = process has at least one MITRE-tagged event");
    }

    fn render_help_shortcuts(&self, ui: &mut egui::Ui) {
        let shortcuts: &[(&str, &str)] = &[
            ("Ctrl+O",           "Open file dialog"),
            ("Ctrl+F",           "Focus process search box"),
            ("Arrow Up/Down",    "Navigate process tree (when search not focused)"),
            ("Ctrl+Tab",         "Cycle to next telemetry tab"),
            ("Ctrl+Shift+Tab",   "Cycle to previous telemetry tab"),
            ("Click row",        "Select telemetry table row"),
            ("Click column header", "Sort telemetry table by that column (toggles asc/desc)"),
            ("Right-click row",  "Copy individual columns or full row"),
            ("Right-click tree node", "Copy GUID, command line; expand all children"),
            ("Drag & Drop",      "Drop a .json / .ndjson file onto the window to open it"),
        ];

        egui::Grid::new("shortcuts_grid")
            .num_columns(2)
            .striped(true)
            .min_col_width(180.0)
            .show(ui, |ui| {
                ui.strong("Shortcut");
                ui.strong("Action");
                ui.end_row();
                for (key, action) in shortcuts {
                    ui.label(egui::RichText::new(*key).monospace());
                    ui.label(*action);
                    ui.end_row();
                }
            });
    }

    fn render_help_feature_guide(&self, ui: &mut egui::Ui) {
        let section = |ui: &mut egui::Ui, title: &str, body: &str| {
            ui.strong(title);
            ui.add_space(2.0);
            ui.label(body);
            ui.add_space(8.0);
        };

        section(ui, "Process Tree (left panel)",
            "Shows all processes from Sysmon EventId 1. Click a node to select it and view \
             its telemetry. Use the search box (🔍) to filter by name, PID, user, or command \
             line. Expand All / Collapse All and the Filter toggle are in the toolbar row below \
             the search box. The Filter panel is always accessible, including while in Timeline mode. \
             ⚑ prefix = process has at least one MITRE-tagged event. 🔖 prefix = bookmarked.");

        section(ui, "Filter panel",
            "Click the Filter button in the toolbar to expand forensic filters. All categories \
             are AND logic — a process must satisfy every active category to appear.\n\
             • Integrity Level — System / High / Medium / Low checkboxes.\n\
             • User — checkbox per unique user found in real (non-synthetic) ProcessCreate events.\n\
             • Activity — Network Connection (has EventId 3/22) or Persistence Activity \
             (touches Run keys, Services, Task Scheduler, WMI, Winlogon, AppInit_DLLs, \
             or is schtasks.exe / at.exe).\n\
             • MITRE Techniques — checkbox per technique ID found in loaded events.\n\
             The badge on the button (e.g. \"Filter (2)\") shows how many categories are active. \
             Click ✕ to clear all at once. Parent nodes without matching events are skipped \
             but their children are still shown if they match.");

        section(ui, "Overview tab",
            "Shows process metadata: image path, PID, GUID, command line, user, integrity, \
             hashes, parent, file version, description, product, company. Below that: \
             per-category event counts. MITRE ATT&CK annotations appear if present. \
             The Notes field lets you attach investigation notes (bookmarks) to a process.");

        section(ui, "Network tab",
            "EventId 3 (NetworkConnect) and 22 (DnsQuery) for the selected process. \
             Columns: Time, Direction, Protocol, Source, Destination, Hostname, MITRE. \
             Right-click any row to copy individual fields or the full row.");

        section(ui, "Files tab",
            "File system events: EventId 11 (Create), 15 (ADS Stream), 23/26 (Delete), \
             27/28/29 (Block/Exec). Columns: Time, Action, Target Filename, Hashes, MITRE.");

        section(ui, "Registry tab",
            "Registry events: EventId 12 (Create/Delete key), 13 (SetValue), 14 (Rename). \
             Columns: Time, Action, Target Object, Details, MITRE.");

        section(ui, "Pipes tab",
            "Named pipe events: EventId 17 (Create), 18 (Connect). \
             Columns: Time, Action, Pipe Name, MITRE.");

        section(ui, "Injection tab",
            "Process injection events: EventId 8 (CreateRemoteThread), 10 (ProcessAccess), \
             25 (ProcessTampering). Shows both source and target side for the selected process. \
             Columns: Time, Type, Role, Source, Target, Details, MITRE.");

        section(ui, "Modules tab",
            "Driver/image loads: EventId 6 (DriverLoad), 7 (ImageLoad). \
             Columns: Time, Type, Image Loaded, Signature, Status, MITRE.");

        section(ui, "Detection tab",
            "Suspicious events not shown elsewhere: EventId 2 (FileCreateTime/timestomp), \
             4 (SysmonState), 9 (RawAccessRead), 16 (ConfigChange), 19-21 (WMI), \
             24 (ClipboardChange). Color-coded by category with a legend bar at the top.");

        section(ui, "Timeline tab",
            "Cross-process event timeline. Check processes in the tree (checkboxes appear \
             on the left when this tab is active), then click Generate Timeline to see all \
             their events sorted by time in one table. Supports horizontal scrolling and \
             right-click copy per column. The Filter panel remains available in the sidebar \
             to narrow which processes appear in the tree before selecting.");

        section(ui, "Stats popup (menu bar)",
            "Click Stats in the menu bar for a summary of the loaded file. Shows metric \
             cards (event count, process count, event types seen, duration, time range) \
             and horizontal bar charts for: Integrity Level distribution, Processes per User \
             (top 12), Event Type Breakdown (top 20), and Host breakdown (if multi-host). \
             Stats respect the current host filter.");

        section(ui, "Export (File menu)",
            "Events as CSV — all events with time, EventID, type, computer, image, user. \
             Events as JSON — same data as JSON array. \
             Process Tree as DOT — Graphviz dot file for visualisation.");
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

        // Stats popup (floating)
        if self.state.show_stats {
            self.render_stats_window(ctx);
        }

        // Help window (floating)
        if self.state.show_help {
            self.render_help_window(ctx);
        }

        // Status bar (registered first so it appears at the very bottom)
        egui::TopBottomPanel::bottom("status_bar").show(ctx, |ui| {
            self.render_status_bar(ui);
        });

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
