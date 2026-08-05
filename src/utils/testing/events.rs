use crate::{
    err::ForensicError,
    traits::events::{EventLevel, EventLogIterator, EventLogQuery, EventLogReader, EventRecord},
};
use std::collections::BTreeMap;

use crate::utils::time::ForensicTimestamp;

/// In-memory event log reader for testing.
///
/// Stores events grouped by channel. Use `basic_event_log()` for a pre-populated
/// instance or build your own with `TestingEventLogReader::new()` + `add_event()`.
#[derive(Debug, Clone)]
pub struct TestingEventLogReader {
    events: BTreeMap<String, Vec<EventRecord>>,
}

impl Default for TestingEventLogReader {
    fn default() -> Self {
        Self::new()
    }
}

impl TestingEventLogReader {
    pub fn new() -> Self {
        Self {
            events: BTreeMap::new(),
        }
    }

    pub fn add_event(&mut self, event: EventRecord) {
        self.events
            .entry(event.channel.clone())
            .or_default()
            .push(event);
    }
}

struct TestingEventLogIteratorInner {
    events: Vec<EventRecord>,
    pos: usize,
}

impl EventLogIterator for TestingEventLogIteratorInner {
    fn next(&mut self) -> crate::err::ForensicResult<Option<EventRecord>> {
        if self.pos >= self.events.len() {
            return Ok(None);
        }
        let event = self.events[self.pos].clone();
        self.pos += 1;
        Ok(Some(event))
    }
}

impl EventLogReader for TestingEventLogReader {
    fn channels(&self) -> crate::err::ForensicResult<Vec<String>> {
        Ok(self.events.keys().cloned().collect())
    }

    fn query(
        &self,
        query: &EventLogQuery,
    ) -> crate::err::ForensicResult<Box<dyn EventLogIterator + '_>> {
        let mut matched: Vec<EventRecord> = Vec::new();
        for events in self.events.values() {
            for event in events {
                if query.matches(event) {
                    matched.push(event.clone());
                }
            }
        }
        // Sort by timestamp then record_id for deterministic output
        matched.sort_by(|a, b| {
            a.timestamp
                .cmp(&b.timestamp)
                .then(a.record_id.cmp(&b.record_id))
        });
        Ok(Box::new(TestingEventLogIteratorInner {
            events: matched,
            pos: 0,
        }))
    }

    fn event_count(&self, channel: &str) -> crate::err::ForensicResult<u64> {
        match self.events.get(channel) {
            Some(v) => Ok(v.len() as u64),
            None => Err(ForensicError::other(
                "TestingEventLogReader",
                "channel not found".to_string(),
            )),
        }
    }
}

/// Creates a pre-populated `TestingEventLogReader` with sample Security and System events.
pub fn basic_event_log() -> TestingEventLogReader {
    let mut reader = TestingEventLogReader::new();
    // Security events
    reader.add_event(EventRecord {
        record_id: 1001,
        event_id: 4624,
        timestamp: ForensicTimestamp::from_unix_secs(1700000100),
        provider: "Microsoft-Windows-Security-Auditing".into(),
        channel: "Security".into(),
        level: EventLevel::Information,
        computer: "WORKSTATION1".into(),
        user_sid: Some("S-1-5-18".into()),
        data: BTreeMap::new(),
    });
    reader.add_event(EventRecord {
        record_id: 1002,
        event_id: 4625,
        timestamp: ForensicTimestamp::from_unix_secs(1700000200),
        provider: "Microsoft-Windows-Security-Auditing".into(),
        channel: "Security".into(),
        level: EventLevel::Information,
        computer: "WORKSTATION1".into(),
        user_sid: Some("S-1-5-21-1234567890-1234567890-1234567890-1001".into()),
        data: BTreeMap::new(),
    });
    reader.add_event(EventRecord {
        record_id: 1003,
        event_id: 4688,
        timestamp: ForensicTimestamp::from_unix_secs(1700000300),
        provider: "Microsoft-Windows-Security-Auditing".into(),
        channel: "Security".into(),
        level: EventLevel::Information,
        computer: "WORKSTATION1".into(),
        user_sid: Some("S-1-5-18".into()),
        data: BTreeMap::new(),
    });
    // System events
    reader.add_event(EventRecord {
        record_id: 2001,
        event_id: 7045,
        timestamp: ForensicTimestamp::from_unix_secs(1700000150),
        provider: "Service Control Manager".into(),
        channel: "System".into(),
        level: EventLevel::Information,
        computer: "WORKSTATION1".into(),
        user_sid: None,
        data: BTreeMap::new(),
    });
    reader.add_event(EventRecord {
        record_id: 2002,
        event_id: 104,
        timestamp: ForensicTimestamp::from_unix_secs(1700000250),
        provider: "Microsoft-Windows-Eventlog".into(),
        channel: "System".into(),
        level: EventLevel::Warning,
        computer: "WORKSTATION1".into(),
        user_sid: Some("S-1-5-18".into()),
        data: BTreeMap::new(),
    });
    reader
}
