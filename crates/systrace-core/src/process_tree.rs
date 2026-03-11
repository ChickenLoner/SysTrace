use rustc_hash::FxHashMap;

use crate::event::{EventDetail, SysmonEvent};
use crate::types::{ProcessGuid, Timestamp};

/// A node in the process tree.
#[derive(Debug, Clone)]
pub struct ProcessNode {
    pub guid: ProcessGuid,
    pub pid: Option<u32>,
    pub image: Option<String>,
    /// Just the filename portion (e.g. "svchost.exe")
    pub image_name: Option<String>,
    pub command_line: Option<String>,
    pub parent_guid: Option<ProcessGuid>,
    pub parent_pid: Option<u32>,
    pub parent_image: Option<String>,
    pub parent_command_line: Option<String>,
    /// Children ordered by start_time (insertion order is preserved; sorted on finalise)
    pub children: Vec<ProcessGuid>,
    pub start_time: Timestamp,
    /// Filled by EventId=5 (ProcessTerminate)
    pub end_time: Option<Timestamp>,
    pub user: Option<String>,
    pub hashes: Option<String>,
    pub integrity_level: Option<String>,
    pub logon_id: Option<String>,
    pub computer: String,
    /// True if this node was synthesised from a child's parent fields
    /// (the parent's own ProcessCreate event was never observed).
    pub is_synthetic: bool,
}

impl ProcessNode {
    fn image_name_from(image: &Option<String>) -> Option<String> {
        image.as_deref().and_then(|p| {
            // Handle both / and \ separators
            p.rsplit(|c| c == '\\' || c == '/')
                .next()
                .map(|s| s.to_owned())
        })
    }
}

/// The process forest (multiple root processes possible).
pub struct ProcessTree {
    /// All known nodes keyed by ProcessGuid.
    pub nodes: FxHashMap<ProcessGuid, ProcessNode>,
    /// Roots: nodes whose parent was never observed (sorted by start_time on access).
    pub roots: Vec<ProcessGuid>,
    /// Children waiting for their parent to appear.
    pending_children: FxHashMap<ProcessGuid, Vec<ProcessGuid>>,
}

impl Default for ProcessTree {
    fn default() -> Self {
        Self {
            nodes: FxHashMap::default(),
            roots: Vec::new(),
            pending_children: FxHashMap::default(),
        }
    }
}

impl ProcessTree {
    pub fn new() -> Self {
        Self::default()
    }

    /// Process an EventId=1 (ProcessCreate) event.
    pub fn insert_process_create(&mut self, event: &SysmonEvent, rodeo: &crate::SharedRodeo) {
        let guid = match event.process_guid {
            Some(g) => g,
            None => return,
        };

        // Resolve interned fields to owned Strings for ProcessNode storage.
        let image: Option<String> = event.image.map(|s| rodeo.resolve(&s).to_owned());
        let user: Option<String>  = event.user.map(|s| rodeo.resolve(&s).to_owned());
        let computer: String      = rodeo.resolve(&event.computer).to_owned();

        // If a synthetic placeholder already exists for this guid, promote it.
        let node = if let Some(mut existing) = self.nodes.remove(&guid) {
            // Promote synthetic node with real data
            existing.is_synthetic = false;
            existing.pid = event.process_id;
            existing.image_name = ProcessNode::image_name_from(&image);
            existing.image = image.clone();
            existing.user = user.clone();
            existing.computer = computer.clone();
            existing.start_time = event.time_created;

            if let EventDetail::ProcessCreate {
                command_line,
                hashes,
                parent_process_guid,
                parent_process_id,
                parent_image,
                parent_command_line,
                parent_user,
                logon_id,
                integrity_level,
                ..
            } = &event.detail
            {
                existing.command_line = command_line.clone();
                existing.hashes = hashes.clone();
                existing.parent_guid = *parent_process_guid;
                existing.parent_pid = *parent_process_id;
                existing.parent_image = parent_image.clone();
                existing.parent_command_line = parent_command_line.clone();
                existing.logon_id = logon_id.clone();
                existing.integrity_level = integrity_level.clone();
                if existing.user.is_none() {
                    existing.user = parent_user.clone();
                }
            }
            existing
        } else {
            // Extract ProcessCreate-specific fields
            let (command_line, hashes, parent_process_guid, parent_process_id,
                parent_image, parent_command_line, logon_id, integrity_level) =
                if let EventDetail::ProcessCreate {
                    command_line,
                    hashes,
                    parent_process_guid,
                    parent_process_id,
                    parent_image,
                    parent_command_line,
                    logon_id,
                    integrity_level,
                    ..
                } = &event.detail
                {
                    (
                        command_line.clone(),
                        hashes.clone(),
                        *parent_process_guid,
                        *parent_process_id,
                        parent_image.clone(),
                        parent_command_line.clone(),
                        logon_id.clone(),
                        integrity_level.clone(),
                    )
                } else {
                    (None, None, None, None, None, None, None, None)
                };

            ProcessNode {
                guid,
                pid: event.process_id,
                image_name: ProcessNode::image_name_from(&image),
                image,
                command_line,
                parent_guid: parent_process_guid,
                parent_pid: parent_process_id,
                parent_image,
                parent_command_line,
                children: Vec::new(),
                start_time: event.time_created,
                end_time: None,
                user,
                hashes,
                integrity_level,
                logon_id,
                computer,
                is_synthetic: false,
            }
        };

        let parent_guid = node.parent_guid;
        self.nodes.insert(guid, node);

        // Attach to parent or queue as pending
        self.attach_to_parent(guid, parent_guid);

        // Check if any pending children were waiting for *this* node
        if let Some(pending) = self.pending_children.remove(&guid) {
            for child_guid in pending {
                if let Some(child_node) = self.nodes.get_mut(&child_guid) {
                    child_node.parent_guid = Some(guid);
                }
                if let Some(parent_node) = self.nodes.get_mut(&guid) {
                    // Avoid duplicates (synthetic node may already list this child)
                    if !parent_node.children.contains(&child_guid) {
                        parent_node.children.push(child_guid);
                    }
                }
                // Remove child from roots if it was tentatively put there
                self.roots.retain(|r| r != &child_guid);
            }
        }
    }

    /// Attach `guid` to its parent (if known), or add to pending/roots.
    fn attach_to_parent(&mut self, guid: ProcessGuid, parent_guid: Option<ProcessGuid>) {
        match parent_guid {
            None => {
                // No parent info — this is a root
                if !self.roots.contains(&guid) {
                    self.roots.push(guid);
                }
            }
            Some(pg) => {
                if self.nodes.contains_key(&pg) {
                    // Parent already known — attach immediately
                    let parent = self.nodes.get_mut(&pg).unwrap();
                    if !parent.children.contains(&guid) {
                        parent.children.push(guid);
                    }
                } else {
                    // Parent not yet seen — add to pending
                    self.pending_children
                        .entry(pg)
                        .or_default()
                        .push(guid);

                    // Also synthesise a placeholder parent so the tree is navigable
                    self.ensure_synthetic_parent(pg, guid);
                }
            }
        }
    }

    /// Create (or update) a synthetic parent node from a child's parent fields.
    fn ensure_synthetic_parent(&mut self, parent_guid: ProcessGuid, child_guid: ProcessGuid) {
        if self.nodes.contains_key(&parent_guid) {
            return;
        }
        // Grab parent info from the child's node
        let (parent_image, parent_pid, parent_command_line, computer, start_time) = {
            let child = self.nodes.get(&child_guid).unwrap();
            (
                child.parent_image.clone(),
                child.parent_pid,
                child.parent_command_line.clone(),
                child.computer.clone(),
                child.start_time, // approximate
            )
        };

        let synthetic = ProcessNode {
            guid: parent_guid,
            pid: parent_pid,
            image: parent_image.clone(),
            image_name: ProcessNode::image_name_from(&parent_image),
            command_line: parent_command_line,
            parent_guid: None,
            parent_pid: None,
            parent_image: None,
            parent_command_line: None,
            children: vec![child_guid],
            start_time,
            end_time: None,
            user: None,
            hashes: None,
            integrity_level: None,
            logon_id: None,
            computer,
            is_synthetic: true,
        };
        self.nodes.insert(parent_guid, synthetic);
        if !self.roots.contains(&parent_guid) {
            self.roots.push(parent_guid);
        }
    }

    /// Process an EventId=5 (ProcessTerminate) event — sets end_time.
    pub fn update_process_terminate(&mut self, guid: ProcessGuid, end_time: Timestamp) {
        if let Some(node) = self.nodes.get_mut(&guid) {
            node.end_time = Some(end_time);
        }
    }

    /// Finalise the tree after all events have been ingested.
    /// Sorts roots and children by start_time.
    pub fn finalise(&mut self) {
        // Flush remaining pending_children as roots (orphans with no synthetic parent)
        let orphan_parents: Vec<ProcessGuid> = self.pending_children.keys().copied().collect();
        for parent_guid in orphan_parents {
            if !self.nodes.contains_key(&parent_guid) {
                // Should already have a synthetic node; if not, nothing to do.
                if !self.roots.contains(&parent_guid) {
                    self.roots.push(parent_guid);
                }
            }
        }
        self.pending_children.clear();

        // Sort roots by start_time.
        // Build a temporary start_time lookup to avoid simultaneous mut/imm borrows.
        let start_times: rustc_hash::FxHashMap<ProcessGuid, Timestamp> = self
            .nodes
            .iter()
            .map(|(g, n)| (*g, n.start_time))
            .collect();

        self.roots.sort_by_key(|g| start_times.get(g).copied());

        for node in self.nodes.values_mut() {
            node.children.sort_by_key(|g| start_times.get(g).copied());
        }
    }

    /// Return roots sorted by start_time (call after `finalise()`).
    pub fn roots(&self) -> &[ProcessGuid] {
        &self.roots
    }

    /// Return children of a process, sorted by start_time.
    pub fn children_of(&self, guid: &ProcessGuid) -> &[ProcessGuid] {
        self.nodes
            .get(guid)
            .map(|n| n.children.as_slice())
            .unwrap_or(&[])
    }

    pub fn get(&self, guid: &ProcessGuid) -> Option<&ProcessNode> {
        self.nodes.get(guid)
    }

    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{EventDetail, SysmonEvent, SysmonEventType};
    use crate::types::parse_guid;

    fn make_ts(offset_secs: i64) -> Timestamp {
        chrono::DateTime::from_timestamp(1_700_000_000 + offset_secs, 0).unwrap()
    }

    fn make_create_event(
        guid_str: &str,
        parent_guid_str: Option<&str>,
        pid: u32,
        image: &str,
    ) -> SysmonEvent {
        let guid = parse_guid(guid_str).unwrap();
        let parent_guid = parent_guid_str.map(|s| parse_guid(s).unwrap());
        SysmonEvent {
            event_id: 1,
            event_type: SysmonEventType::ProcessCreate,
            time_created: make_ts(pid as i64),
            record_number: pid as u64,
            computer: "TEST".to_owned(),
            process_guid: Some(guid),
            process_id: Some(pid),
            image: Some(image.to_owned()),
            user: None,
            rule_name: None,
            mitre_technique: None,
            detail: EventDetail::ProcessCreate {
                command_line: None,
                current_directory: None,
                hashes: None,
                parent_process_guid: parent_guid,
                parent_process_id: None,
                parent_image: Some("parent.exe".to_owned()),
                parent_command_line: None,
                parent_user: None,
                logon_guid: None,
                logon_id: None,
                terminal_session_id: None,
                integrity_level: None,
                file_version: None,
                description: None,
                product: None,
                company: None,
                original_file_name: None,
            },
        }
    }

    const GUID_ROOT:  &str = "00000000-0000-0000-0001-000000000000";
    const GUID_CHILD: &str = "00000000-0000-0000-0002-000000000000";
    const GUID_GRAND: &str = "00000000-0000-0000-0003-000000000000";

    #[test]
    fn basic_parent_child() {
        let mut tree = ProcessTree::new();
        let root_event  = make_create_event(GUID_ROOT,  None,           1, "root.exe");
        let child_event = make_create_event(GUID_CHILD, Some(GUID_ROOT), 2, "child.exe");

        tree.insert_process_create(&root_event);
        tree.insert_process_create(&child_event);
        tree.finalise();

        assert_eq!(tree.roots().len(), 1);
        let root_children = tree.children_of(&parse_guid(GUID_ROOT).unwrap());
        assert_eq!(root_children.len(), 1);
        assert_eq!(root_children[0], parse_guid(GUID_CHILD).unwrap());
    }

    #[test]
    fn out_of_order_child_before_parent() {
        let mut tree = ProcessTree::new();
        let root_event  = make_create_event(GUID_ROOT,  None,           1, "root.exe");
        let child_event = make_create_event(GUID_CHILD, Some(GUID_ROOT), 2, "child.exe");

        // Insert child before parent
        tree.insert_process_create(&child_event);
        tree.insert_process_create(&root_event);
        tree.finalise();

        // After finalise, child should be parented to root
        let root_children = tree.children_of(&parse_guid(GUID_ROOT).unwrap());
        assert_eq!(root_children.len(), 1);
        assert_eq!(root_children[0], parse_guid(GUID_CHILD).unwrap());
    }

    #[test]
    fn orphan_gets_synthetic_parent() {
        let mut tree = ProcessTree::new();
        let child_event = make_create_event(GUID_CHILD, Some(GUID_ROOT), 2, "child.exe");
        tree.insert_process_create(&child_event);
        tree.finalise();

        // Root guid should have a synthetic node
        let root_guid = parse_guid(GUID_ROOT).unwrap();
        let synth = tree.get(&root_guid).unwrap();
        assert!(synth.is_synthetic);
        assert!(tree.roots().contains(&root_guid));
    }
}
