use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

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
    Detection,
    Timeline,
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
    pub tab_detection: TabState,
    /// Global text filter applied to all telemetry table panels simultaneously.
    pub telemetry_filter: String,
    /// Event category checkboxes for narrowing the process tree.
    pub tree_event_filter: TreeEventFilter,
    /// Pre-order visible node list for keyboard navigation (rebuilt each frame).
    pub flat_visible: Vec<ProcessGuid>,
    /// When true, the next render of the selected node calls scroll_to_me().
    pub scroll_to_selected: bool,
    /// Shared string interner for `SysmonEvent.computer/image/user` fields.
    pub rodeo: SharedRodeo,
    /// Active time range filter for telemetry tables (None = no filter).
    pub time_range_filter: Option<(Timestamp, Timestamp)>,
    // ── Phase 5 additions ────────────────────────────────────────────────────
    /// Currently selected host filter (None = show all hosts).
    pub selected_host: Option<String>,
    /// Dark mode toggle (true = dark, false = light).
    pub dark_mode: bool,
    /// Per-process notes/bookmarks.  Key = ProcessGuid.
    pub bookmarks: HashMap<ProcessGuid, String>,
    /// Recently opened file paths (most recent first, max 10).
    pub recent_files: Vec<PathBuf>,
    // ── Timeline tab ──────────────────────────────────────────────────────────
    /// Processes checked/selected for timeline generation.
    pub timeline_checked: HashSet<ProcessGuid>,
    /// Cached sorted event indices (built on "Generate Timeline" click).
    pub timeline_events: Vec<usize>,
    /// Whether the timeline has been generated (shows event table vs placeholder).
    pub timeline_generated: bool,
    /// Sort/selection state for the timeline event table.
    pub tab_timeline: TabState,
    /// Text filter for the timeline event table rows.
    pub timeline_event_filter: String,
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
            tab_detection: TabState::default(),
            telemetry_filter: String::new(),
            tree_event_filter: TreeEventFilter::default(),
            flat_visible: Vec::new(),
            scroll_to_selected: false,
            rodeo: systrace_core::new_rodeo(),
            time_range_filter: None,
            selected_host: None,
            dark_mode: true,
            bookmarks: HashMap::new(),
            recent_files: Vec::new(),
            timeline_checked: HashSet::new(),
            timeline_events: Vec::new(),
            timeline_generated: false,
            tab_timeline: TabState::default(),
            timeline_event_filter: String::new(),
        }
    }
}
