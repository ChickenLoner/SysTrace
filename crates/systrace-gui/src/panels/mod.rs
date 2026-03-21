pub mod detection;
pub mod drivers;
pub mod file_activity;
pub mod injection;
pub mod network;
pub mod pipes;
pub mod registry;
pub mod sigma;
pub mod timeline;

/// Column sort state for a telemetry table.
#[derive(Debug, Clone)]
pub struct SortState {
    pub column: usize,
    pub ascending: bool,
}

impl Default for SortState {
    fn default() -> Self {
        Self { column: 0, ascending: true }
    }
}

impl SortState {
    /// Toggle: same column flips direction; different column resets to ascending.
    pub fn toggle(&mut self, col: usize) {
        if self.column == col {
            self.ascending = !self.ascending;
        } else {
            self.column = col;
            self.ascending = true;
        }
    }

    /// Sort indicator arrow for a given header column.
    pub fn indicator(&self, col: usize) -> &'static str {
        if self.column == col {
            if self.ascending { " ▲" } else { " ▼" }
        } else {
            ""
        }
    }
}

/// Per-tab UI state: current sort column/direction and selected row index.
#[derive(Debug, Clone, Default)]
pub struct TabState {
    pub sort: SortState,
    pub selected_row: Option<usize>,
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Format a timestamp for compact table display (time only).
pub fn fmt_time(ts: systrace_core::Timestamp) -> String {
    ts.format("%Y-%m-%d %H:%M:%S%.3f").to_string()
}

/// Render a centred placeholder when there are no events for the active tab.
pub fn render_empty(ui: &mut eframe::egui::Ui, msg: &str) {
    ui.vertical_centered(|ui| {
        ui.add_space(40.0);
        ui.label(msg);
    });
}

/// Render a "select a process first" hint.
pub fn render_no_selection(ui: &mut eframe::egui::Ui) {
    ui.vertical_centered(|ui| {
        ui.add_space(40.0);
        ui.label("Select a process in the tree on the left.");
    });
}

/// Flip ordering when descending sort is active.
pub fn cmp_ord(o: std::cmp::Ordering, asc: bool) -> std::cmp::Ordering {
    if asc { o } else { o.reverse() }
}

/// Build formatted column header strings with sort arrows.
pub fn make_headers(names: &[&str], sort: &SortState) -> Vec<String> {
    names
        .iter()
        .enumerate()
        .map(|(i, &name)| format!("{}{}", name, sort.indicator(i)))
        .collect()
}

/// Map a Sysmon event_id to its category colour.
pub fn event_color(event_id: u16) -> eframe::egui::Color32 {
    use eframe::egui::Color32;
    match event_id {
        3 | 22 => Color32::from_rgb(100, 160, 255),
        11 | 15 | 23 | 26 | 27 | 28 | 29 => Color32::from_rgb(80, 200, 100),
        12 | 13 | 14 => Color32::from_rgb(255, 160, 50),
        8 | 10 | 25 => Color32::from_rgb(220, 60, 60),
        17 | 18 => Color32::from_rgb(180, 100, 220),
        6 | 7 => Color32::from_rgb(80, 200, 200),
        _ => Color32::from_gray(160),
    }
}

/// Human-readable label for a Sysmon event_id.
pub fn event_label(event_id: u16) -> &'static str {
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
        _ => "Unknown",
    }
}
