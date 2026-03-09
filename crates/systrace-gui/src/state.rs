use std::collections::{HashMap, HashSet};

use systrace_core::{EventStore, ProcessGuid, ProcessTree, Timestamp};

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
        }
    }
}
