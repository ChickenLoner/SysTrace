//! Sigma rule engine for Sysmon logs.
//!
//! Supports a Sysmon-focused subset of the Sigma specification:
//! - YAML rule parsing with field modifiers (contains, startswith, endswith, re, all)
//! - Condition expressions (and, or, not, 1 of, all of)
//! - Sysmon logsource category → event ID mapping
//! - Two built-in detection rules

pub mod rule;
pub mod matcher;

pub use rule::{SigmaRule, SigmaLevel, SigmaLogsource, SigmaDetection, SigmaSelection, SigmaFieldMatch, Modifier, ConditionExpr};
pub use matcher::{SigmaMatch, evaluate_rules};

// ---------------------------------------------------------------------------
// Sysmon category → event ID mapping
// ---------------------------------------------------------------------------

/// Map a Sigma logsource category to the corresponding Sysmon event IDs.
/// Returns an empty slice for unknown/unsupported categories.
pub fn category_to_event_ids(category: Option<&str>) -> &'static [u16] {
    match category {
        Some("process_creation")      => &[1],
        Some("network_connection")    => &[3],
        Some("process_termination")   => &[5],
        Some("driver_load")           => &[6],
        Some("image_load")            => &[7],
        Some("create_remote_thread")  => &[8],
        Some("raw_access_thread")     => &[9],
        Some("process_access")        => &[10],
        Some("file_event")            => &[11, 23, 26, 27, 28, 29],
        Some("registry_event")        => &[12, 13, 14],
        Some("registry_add")          => &[12],
        Some("registry_set")          => &[13],
        Some("registry_rename")       => &[14],
        Some("file_create")           => &[11],
        Some("file_stream_create")    => &[15],
        Some("sysmon_config_change")  => &[16],
        Some("pipe_created")          => &[17],
        Some("pipe_connected")        => &[18],
        Some("wmi_event")             => &[19, 20, 21],
        Some("dns_query")             => &[22],
        Some("file_delete")           => &[23, 26],
        Some("clipboard_change")      => &[24],
        Some("process_tampering")     => &[25],
        _ => &[],
    }
}
