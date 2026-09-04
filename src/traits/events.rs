use std::collections::BTreeMap;

use crate::{
    artifact::{Artifact, WindowsArtifacts, WindowsEvents},
    data::ForensicData,
    err::{ForensicError, ForensicResult},
    field::{Field, Text},
    provenance::ProvenanceId,
    utils::time::ForensicTimestamp,
};

// ============================================================================
// EventLevel
// ============================================================================

/// Windows event log severity level.
///
/// Numeric values match the Windows Event Log API severity IDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum EventLevel {
    Critical = 1,
    Error = 2,
    Warning = 3,
    Information = 4,
    Verbose = 5,
}

impl EventLevel {
    /// Create from a numeric Windows severity ID.
    pub fn from_id(id: u8) -> Option<EventLevel> {
        match id {
            1 => Some(EventLevel::Critical),
            2 => Some(EventLevel::Error),
            3 => Some(EventLevel::Warning),
            4 => Some(EventLevel::Information),
            5 => Some(EventLevel::Verbose),
            _ => None,
        }
    }

    /// Returns the numeric ID for this level.
    pub fn id(self) -> u8 {
        self as u8
    }
}

impl std::fmt::Display for EventLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EventLevel::Critical => write!(f, "Critical"),
            EventLevel::Error => write!(f, "Error"),
            EventLevel::Warning => write!(f, "Warning"),
            EventLevel::Information => write!(f, "Information"),
            EventLevel::Verbose => write!(f, "Verbose"),
        }
    }
}

// ============================================================================
// EventRecord
// ============================================================================

/// A single Windows event log record.
///
/// Contains the standard event fields plus an extensible `data` map
/// for event-specific payloads (EventData, UserData XML elements, etc.).
#[derive(Debug, Clone)]
pub struct EventRecord {
    pub record_id: u64,
    pub event_id: u32,
    pub timestamp: ForensicTimestamp,
    pub provider: String,
    pub channel: String,
    pub level: EventLevel,
    pub computer: String,
    pub user_sid: Option<String>,
    /// Extensible payload — event-specific key/value data.
    pub data: BTreeMap<Text, Field>,
}

impl EventRecord {
    /// Converts this record into a [`ForensicData`], under the given
    /// provenance (obtained from the [`crate::provenance::SourceHandle`] the
    /// caller minted this record's id from — e.g. `Acquisition::LiveApi` for a
    /// live event log reader, `Acquisition::ImageRead` for one replayed from
    /// an exported `.evtx` file).
    pub fn into_forensic_data(self, provenance: ProvenanceId) -> ForensicData {
        let event = self;
        let artifact = Artifact::Windows(WindowsArtifacts::WinEvt(match event.channel.as_str() {
            "Security" => WindowsEvents::Security,
            "System" => WindowsEvents::System,
            "Application" => WindowsEvents::Application,
            "Setup" => WindowsEvents::Setup,
            _ => WindowsEvents::Other(event.channel.clone()),
        }));
        let mut fd = ForensicData::new("", artifact, provenance);
        fd.insert(
            Text::Borrowed("event.record_id"),
            Field::U64(event.record_id),
        );
        fd.insert(
            Text::Borrowed("event.code"),
            Field::U64(event.event_id as u64),
        );
        fd.insert(
            Text::Borrowed("@timestamp"),
            Field::Date(event.timestamp),
        );
        fd.insert(
            Text::Borrowed("event.provider"),
            Field::from(event.provider),
        );
        fd.insert(Text::Borrowed("event.channel"), Field::from(event.channel));
        fd.insert(
            Text::Borrowed("event.severity"),
            Field::U64(event.level.id() as u64),
        );
        fd.insert(Text::Borrowed("host.name"), Field::from(event.computer));
        if let Some(sid) = event.user_sid {
            fd.insert(Text::Borrowed("user.id"), Field::from(sid));
        }
        for (k, v) in event.data {
            fd.insert(k, v);
        }
        fd
    }
}

// ============================================================================
// EventLogQuery
// ============================================================================

/// A query filter for event log iteration.
///
/// All filters are optional — an empty query matches all events.
/// Multiple values within a filter are OR'd (e.g., event_ids \[4624, 4625\]
/// matches records with either ID). Filters across different fields are AND'd.
///
/// # Example
/// ```
/// use forensic_rs::traits::events::{EventLogQuery, EventLevel};
/// use forensic_rs::utils::time::ForensicTimestamp;
///
/// let query = EventLogQuery::new()
///     .with_event_ids(&[4624, 4625])
///     .with_channels(&["Security"])
///     .with_levels(&[EventLevel::Information, EventLevel::Warning])
///     .with_time_range(
///         ForensicTimestamp::from_unix_secs(1700000000),
///         ForensicTimestamp::from_unix_secs(1700100000),
///     );
/// ```
#[derive(Debug, Clone, Default)]
pub struct EventLogQuery {
    pub event_ids: Vec<u32>,
    pub time_from: Option<ForensicTimestamp>,
    pub time_to: Option<ForensicTimestamp>,
    pub providers: Vec<String>,
    pub levels: Vec<EventLevel>,
    pub channels: Vec<String>,
}

impl EventLogQuery {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_event_ids(mut self, ids: &[u32]) -> Self {
        self.event_ids.extend_from_slice(ids);
        self
    }

    pub fn with_time_range(mut self, from: ForensicTimestamp, to: ForensicTimestamp) -> Self {
        self.time_from = Some(from);
        self.time_to = Some(to);
        self
    }

    pub fn with_providers(mut self, providers: &[&str]) -> Self {
        self.providers
            .extend(providers.iter().map(|s| s.to_string()));
        self
    }

    pub fn with_levels(mut self, levels: &[EventLevel]) -> Self {
        self.levels.extend_from_slice(levels);
        self
    }

    pub fn with_channels(mut self, channels: &[&str]) -> Self {
        self.channels.extend(channels.iter().map(|s| s.to_string()));
        self
    }

    /// Returns true if the given record matches all active filters.
    pub fn matches(&self, record: &EventRecord) -> bool {
        if !self.event_ids.is_empty() && !self.event_ids.contains(&record.event_id) {
            return false;
        }
        if let Some(from) = self.time_from {
            if record.timestamp < from {
                return false;
            }
        }
        if let Some(to) = self.time_to {
            if record.timestamp > to {
                return false;
            }
        }
        if !self.providers.is_empty() && !self.providers.iter().any(|p| p == &record.provider) {
            return false;
        }
        if !self.levels.is_empty() && !self.levels.contains(&record.level) {
            return false;
        }
        if !self.channels.is_empty() && !self.channels.iter().any(|c| c == &record.channel) {
            return false;
        }
        true
    }
}

// ============================================================================
// EventLogIterator
// ============================================================================

/// Fallible iterator over event log records.
///
/// Uses explicit `next()` → `ForensicResult<Option<EventRecord>>` instead of
/// `std::Iterator` to allow error propagation during iteration (consistent
/// with the `ForensicRows` pattern from the database trait).
pub trait EventLogIterator {
    /// Returns the next record, `Ok(None)` at end, or an error.
    fn next(&mut self) -> ForensicResult<Option<EventRecord>>;
}

// ============================================================================
// EventLogReader
// ============================================================================

/// Abstract reader for Windows event logs.
///
/// Implementations may read from parsed `.evtx` files, live Windows Event Log API,
/// in-memory mocks, or any other source — the trait decouples analysis logic from
/// the data source.
///
/// # Object Safety
/// All methods use concrete types (no generics) so the trait can be used as
/// `&dyn EventLogReader` or `Box<dyn EventLogReader>`.
///
/// `Send + Sync`: a mounted event log is cached and shared across parallel
/// pipeline workers the same way `FileSystem`/`Registry` are (RFC 0001 §1,
/// P5) -- see [`crate::traits::format::Mounted::EventLog`].
pub trait EventLogReader: Send + Sync {
    /// List available log channels (e.g., "Security", "System", "Application").
    fn channels(&self) -> ForensicResult<Vec<String>>;

    /// Query events matching the given filter. Returns a fallible iterator.
    fn query(&self, query: &EventLogQuery) -> ForensicResult<Box<dyn EventLogIterator + '_>>;

    /// Returns the total number of events in a channel (optional capability).
    ///
    /// Default implementation returns an error indicating the operation is unsupported.
    #[allow(unused_variables)]
    fn event_count(&self, channel: &str) -> ForensicResult<u64> {
        Err(ForensicError::other(
            "EventLogReader",
            "event_count is not supported by this implementation".to_string(),
        ))
    }
}

/// Ergonomic wrappers for `dyn EventLogReader` consumers.
impl dyn EventLogReader {
    /// Query all events without any filter.
    pub fn query_all(&self) -> ForensicResult<Box<dyn EventLogIterator + '_>> {
        self.query(&EventLogQuery::new())
    }

    /// Query all events in a specific channel.
    pub fn query_channel(&self, channel: &str) -> ForensicResult<Box<dyn EventLogIterator + '_>> {
        self.query(&EventLogQuery::new().with_channels(&[channel]))
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::FieldAccess;
    use crate::utils::testing::test_provenance_id;

    #[test]
    fn event_level_round_trip() {
        for id in 1..=5u8 {
            let level = EventLevel::from_id(id).unwrap();
            assert_eq!(level.id(), id);
        }
        assert!(EventLevel::from_id(0).is_none());
        assert!(EventLevel::from_id(6).is_none());
    }

    #[test]
    fn query_builder_and_matching() {
        let record = EventRecord {
            record_id: 1,
            event_id: 4624,
            timestamp: ForensicTimestamp::from_unix_secs(1700050000),
            provider: "Microsoft-Windows-Security-Auditing".into(),
            channel: "Security".into(),
            level: EventLevel::Information,
            computer: "WORKSTATION1".into(),
            user_sid: Some("S-1-5-18".into()),
            data: BTreeMap::new(),
        };

        // Empty query matches everything
        assert!(EventLogQuery::new().matches(&record));

        // Matching event ID
        assert!(EventLogQuery::new()
            .with_event_ids(&[4624, 4625])
            .matches(&record));
        assert!(!EventLogQuery::new()
            .with_event_ids(&[4625])
            .matches(&record));

        // Matching channel
        assert!(EventLogQuery::new()
            .with_channels(&["Security"])
            .matches(&record));
        assert!(!EventLogQuery::new()
            .with_channels(&["System"])
            .matches(&record));

        // Matching time range
        let query = EventLogQuery::new().with_time_range(
            ForensicTimestamp::from_unix_secs(1700000000),
            ForensicTimestamp::from_unix_secs(1700100000),
        );
        assert!(query.matches(&record));

        let query = EventLogQuery::new().with_time_range(
            ForensicTimestamp::from_unix_secs(1700060000),
            ForensicTimestamp::from_unix_secs(1700100000),
        );
        assert!(!query.matches(&record));

        // Matching level
        assert!(EventLogQuery::new()
            .with_levels(&[EventLevel::Information])
            .matches(&record));
        assert!(!EventLogQuery::new()
            .with_levels(&[EventLevel::Error])
            .matches(&record));

        // Matching provider
        assert!(EventLogQuery::new()
            .with_providers(&["Microsoft-Windows-Security-Auditing"])
            .matches(&record));
        assert!(!EventLogQuery::new()
            .with_providers(&["OtherProvider"])
            .matches(&record));
    }

    #[test]
    fn event_record_to_forensic_data() {
        let record = EventRecord {
            record_id: 42,
            event_id: 4624,
            timestamp: ForensicTimestamp::from_unix_secs(1700050000),
            provider: "Microsoft-Windows-Security-Auditing".into(),
            channel: "Security".into(),
            level: EventLevel::Information,
            computer: "WORKSTATION1".into(),
            user_sid: Some("S-1-5-18".into()),
            data: BTreeMap::new(),
        };

        let mut fd: ForensicData = record.into_forensic_data(test_provenance_id());
        assert_eq!(fd.get_u64("event.record_id"), FieldAccess::Some(42));
        assert_eq!(fd.get_u64("event.code"), FieldAccess::Some(4624));
    }
}
