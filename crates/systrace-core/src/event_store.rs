use rustc_hash::FxHashMap;

use crate::event::SysmonEvent;
use crate::types::ProcessGuid;

/// Multi-index event store.
///
/// Events are stored in insertion order in `events`. All indices hold
/// `usize` positions into that Vec — no copying of event data.
pub struct EventStore {
    /// Primary storage: all events in insertion order.
    pub events: Vec<SysmonEvent>,

    /// ProcessGuid → indices of events whose primary process is this guid.
    pub by_process: FxHashMap<ProcessGuid, Vec<usize>>,

    /// EventId → indices of events of that type.
    pub by_event_type: FxHashMap<u16, Vec<usize>>,

    /// Secondary process guid (target) → indices.
    /// Populated for EventId 8 (CreateRemoteThread) and 10 (ProcessAccess).
    pub by_target_process: FxHashMap<ProcessGuid, Vec<usize>>,
}

impl Default for EventStore {
    fn default() -> Self {
        Self {
            events: Vec::new(),
            by_process: FxHashMap::default(),
            by_event_type: FxHashMap::default(),
            by_target_process: FxHashMap::default(),
        }
    }
}

impl EventStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Pre-allocate event storage when the approximate count is known.
    pub fn with_capacity(n: usize) -> Self {
        Self {
            events: Vec::with_capacity(n),
            ..Self::default()
        }
    }

    /// Insert an event and update all indices.
    pub fn insert(&mut self, event: SysmonEvent) {
        let idx = self.events.len();

        // Index by primary process guid
        if let Some(guid) = event.process_guid {
            self.by_process.entry(guid).or_default().push(idx);
        }

        // Index by event type
        self.by_event_type
            .entry(event.event_id)
            .or_default()
            .push(idx);

        // Cross-process indexing for injection events
        if let Some(target_guid) = event.secondary_process_guid() {
            self.by_target_process.entry(target_guid).or_default().push(idx);
        }

        self.events.push(event);
    }

    /// All indices for a given process guid (primary).
    pub fn events_for_process(&self, guid: &ProcessGuid) -> &[usize] {
        self.by_process
            .get(guid)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// All indices for a given event type.
    pub fn events_for_type(&self, event_id: u16) -> &[usize] {
        self.by_event_type
            .get(&event_id)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Events for a process filtered by event type.
    /// Returns a new Vec of indices (intersection of the two index lists).
    pub fn events_for_process_and_type(
        &self,
        guid: &ProcessGuid,
        event_id: u16,
    ) -> Vec<usize> {
        let proc_indices = self.events_for_process(guid);
        if proc_indices.is_empty() {
            return Vec::new();
        }
        // proc_indices is ordered; filter by event_id in one pass.
        proc_indices
            .iter()
            .copied()
            .filter(|&i| self.events[i].event_id == event_id)
            .collect()
    }

    /// Events for a process filtered by a slice of event types.
    pub fn events_for_process_and_types(
        &self,
        guid: &ProcessGuid,
        event_ids: &[u16],
    ) -> Vec<usize> {
        let proc_indices = self.events_for_process(guid);
        if proc_indices.is_empty() {
            return Vec::new();
        }
        proc_indices
            .iter()
            .copied()
            .filter(|&i| event_ids.contains(&self.events[i].event_id))
            .collect()
    }

    /// Events where this process was the *target* (injection events).
    pub fn events_targeting_process(&self, guid: &ProcessGuid) -> &[usize] {
        self.by_target_process
            .get(guid)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Total number of events.
    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Count of events per EventId.
    pub fn event_type_counts(&self) -> Vec<(u16, usize)> {
        let mut counts: Vec<(u16, usize)> = self
            .by_event_type
            .iter()
            .map(|(id, v)| (*id, v.len()))
            .collect();
        counts.sort_by_key(|(id, _)| *id);
        counts
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{EventDetail, SysmonEvent, SysmonEventType};
    use crate::types::parse_guid;

    fn dummy_event(event_id: u16, guid_str: &str) -> SysmonEvent {
        SysmonEvent {
            event_id,
            event_type: SysmonEventType::from_event_id(event_id),
            time_created: chrono::DateTime::from_timestamp(0, 0).unwrap(),
            record_number: 0,
            computer: "test".to_owned(),
            process_guid: Some(parse_guid(guid_str).unwrap()),
            process_id: Some(100),
            image: None,
            user: None,
            rule_name: None,
            mitre_technique: None,
            detail: EventDetail::ProcessTerminate,
        }
    }

    const G1: &str = "00000000-0000-0000-0001-000000000000";
    const G2: &str = "00000000-0000-0000-0002-000000000000";

    #[test]
    fn basic_indexing() {
        let mut store = EventStore::new();
        store.insert(dummy_event(1, G1));
        store.insert(dummy_event(3, G1));
        store.insert(dummy_event(1, G2));

        let guid1 = parse_guid(G1).unwrap();
        let guid2 = parse_guid(G2).unwrap();

        assert_eq!(store.events_for_process(&guid1).len(), 2);
        assert_eq!(store.events_for_process(&guid2).len(), 1);
        assert_eq!(store.events_for_type(1).len(), 2);
        assert_eq!(store.events_for_type(3).len(), 1);
    }

    #[test]
    fn events_for_process_and_type() {
        let mut store = EventStore::new();
        store.insert(dummy_event(1, G1));
        store.insert(dummy_event(3, G1));
        store.insert(dummy_event(3, G1));

        let guid1 = parse_guid(G1).unwrap();
        let network = store.events_for_process_and_type(&guid1, 3);
        assert_eq!(network.len(), 2);
    }
}
