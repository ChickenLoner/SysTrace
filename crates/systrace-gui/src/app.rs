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
    }

    // -----------------------------------------------------------------------
    // File loading
    // -----------------------------------------------------------------------

    fn open_file(&mut self, path: PathBuf) {
        let file_size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(1);

        // Reset all state for the new file
        self.state = AppState::default();
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
                std::thread::spawn(move || {
                    let mut errors = Vec::new();
                    let _ = systrace_core::parse_file(&path2, &etx, &br, &mut errors);
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
                    for event in batch {
                        if event.event_id == 1 {
                            self.state.process_tree.insert_process_create(&event);
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

        for event in &self.state.event_store.events {
            computer_names.insert(event.computer.clone());
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

        // Clone filter to avoid borrow conflict with &mut self in panel calls
        let filter = self.state.telemetry_filter.clone();

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

        // Status bar
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
