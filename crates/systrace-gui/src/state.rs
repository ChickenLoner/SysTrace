use std::collections::{HashMap, HashSet};

use systrace_core::{EventStore, ProcessGuid, ProcessTree, Timestamp};

use crate::panels::TabState;

pub use systrace_core::SharedRodeo;

/// Event category filter for the process tree.
/// When any field is true, only processes with matching events are shown.
#[derive(Debug, Clone, Default)]
pub struct TreeEventFilter {
    pub network: bool,
    pub files: bool,
    pub registry: bool,
    pub pipes: bool,
    pub injection: bool,
    pub drivers: bool,
}

impl TreeEventFilter {
    pub fn any_active(&self) -> bool {
        self.network || self.files || self.registry
            || self.pipes || self.injection || self.drivers
    }
}

/// Which telemetry tab is active.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TelemetryTab {
    #[default]
    Overview,
    Network,
    FileActivity,
    Registry,
    Pipes,
    Injection,
    DriversModules,
}

/// Metadata computed once file loading is complete.
#[derive(Debug, Clone)]
#[allow(dead_code)] // fields used in Phase 3 telemetry panels
pub struct FileMetadata {
    pub path: String,
    pub total_records: u64,
    pub unique_processes: usize,
    pub event_type_counts: HashMap<u16, usize>,
    pub time_range: Option<(Timestamp, Timestamp)>,
    pub computer_names: HashSet<String>,
}

/// Zoom / pan state for the timeline panel.
#[derive(Debug, Clone)]
pub struct TimelineState {
    pub visible: bool,
    /// Pixels per second. 0.0 means "auto-fit on next render".
    pub zoom: f64,
    /// Seconds offset from the process start time shown at the left edge.
    pub pan_offset: f64,
    /// When true, telemetry tables are filtered to the visible time window.
    pub filter_active: bool,
}

impl Default for TimelineState {
    fn default() -> Self {
        Self { visible: false, zoom: 0.0, pan_offset: 0.0, filter_active: false }
    }
}

impl TimelineState {
    /// Reset zoom/pan so the next render auto-fits the process range.
    pub fn reset(&mut self) {
        self.zoom = 0.0;
        self.pan_offset = 0.0;
    }
}

/// All application state owned by the main thread.
pub struct AppState {
    pub process_tree: ProcessTree,
    pub event_store: EventStore,
    pub selected_process: Option<ProcessGuid>,
    pub active_tab: TelemetryTab,
    pub search_filter: String,
    /// 0.0..=1.0 during loading; None when idle.
    pub loading_progress: Option<f32>,
    pub parse_error_count: usize,
    pub file_metadata: Option<FileMetadata>,
    /// File size in bytes (for progress computation).
    pub file_size: u64,
    // Per-tab sort/selection state
    pub tab_network: TabState,
    pub tab_files: TabState,
    pub tab_registry: TabState,
    pub tab_pipes: TabState,
    pub tab_injection: TabState,
    pub tab_drivers: TabState,
    /// Global text filter applied to all telemetry table panels simultaneously.
    pub telemetry_filter: String,
    /// Event category checkboxes for narrowing the process tree.
    pub tree_event_filter: TreeEventFilter,
    /// Pre-order visible node list for keyboard navigation (rebuilt each frame).
    pub flat_visible: Vec<ProcessGuid>,
    /// When true, the next render of the selected node calls scroll_to_me().
    pub scroll_to_selected: bool,
    /// Timeline panel state.
    pub timeline: TimelineState,
    /// Shared string interner for `SysmonEvent.computer/image/user` fields.
    pub rodeo: SharedRodeo,
    /// Active time range filter for telemetry tables (None = no filter).
    pub time_range_filter: Option<(Timestamp, Timestamp)>,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            process_tree: ProcessTree::new(),
            event_store: EventStore::new(),
            selected_process: None,
            active_tab: TelemetryTab::Overview,
            search_filter: String::new(),
            loading_progress: None,
            parse_error_count: 0,
            file_metadata: None,
            file_size: 0,
            tab_network: TabState::default(),
            tab_files: TabState::default(),
            tab_registry: TabState::default(),
            tab_pipes: TabState::default(),
            tab_injection: TabState::default(),
            tab_drivers: TabState::default(),
            telemetry_filter: String::new(),
            tree_event_filter: TreeEventFilter::default(),
            flat_visible: Vec::new(),
            scroll_to_selected: false,
            timeline: TimelineState::default(),
            rodeo: systrace_core::new_rodeo(),
            time_range_filter: None,
        }
    }
}
