pub mod event;
pub mod event_store;
pub mod evtx;
pub mod parser;
pub mod process_tree;
pub mod types;

// Convenience re-exports
pub use event::{EventDetail, SysmonEvent, SysmonEventType};
pub use event_store::EventStore;
pub use parser::{parse_file, parse_file_auto};
pub use process_tree::{ProcessNode, ProcessTree};
pub use types::{MitreTechnique, ParseError, ProcessGuid, Timestamp, parse_guid, parse_guid_opt, parse_mitre_rule_name};

// String interning re-exports
pub use lasso::Spur;
/// Thread-safe string interner shared between the parser thread and the UI thread.
pub type SharedRodeo = std::sync::Arc<lasso::ThreadedRodeo<lasso::Spur>>;

/// Create a new, empty `SharedRodeo`.
pub fn new_rodeo() -> SharedRodeo {
    std::sync::Arc::new(lasso::ThreadedRodeo::new())
}
