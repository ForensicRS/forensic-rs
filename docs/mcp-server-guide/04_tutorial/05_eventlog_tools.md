# Tutorial: Building Event Log Tools

This chapter walks through implementing `security.logon_events`, a tool that queries Windows Security event logs for logon anomalies.

## Scenario

During incident response, you need to identify suspicious logon activity:
- Failed logon attempts (event 4625)
- Successful interactive logons (event 4624)
- Network logons (event 4623)
- Special privileges used (event 4672)

**Note:** This example uses a **mock implementation** that returns realistic-looking data without requiring actual event log files.

## Understanding EventLogReader

The `EventLogReader` trait provides abstract event log access:

```rust
pub trait EventLogReader: Send + Sync {
    fn channels(&self) -> ForensicResult<Vec<String>>;
    fn query(&self, query: &EventLogQuery) -> ForensicResult<Box<dyn EventLogIterator + '_>>;
    fn event_count(&self, channel: &str) -> ForensicResult<u64>;
}

pub struct EventLogQuery {
    // Builder pattern for constructing queries
}

impl EventLogQuery {
    pub fn new() -> Self { ... }
    pub fn with_channels(&mut self, channels: &[&str]) -> &mut Self { ... }
    pub fn with_event_ids(&mut self, ids: &[u32]) -> &mut Self { ... }
    pub fn with_levels(&mut self, levels: &[EventLevel]) -> &mut Self { ... }
    pub fn with_start_time(&mut self, time: ForensicTimestamp) -> &mut Self { ... }
    pub fn with_end_time(&mut self, time: ForensicTimestamp) -> &mut Self { ... }
}

pub enum EventLevel {
    Critical,
    Error,
    Warning,
    Information,
}
```

## What We're Building

A tool that:
- Accepts `case_id` and optional `hours` parameter (default: 24)
- Queries Security event log for logon-related events
- Returns timestamp, event ID, user, logon type, and source IP

## Complete Mock Implementation

```rust
// src/tools/events.rs

use std::collections::BTreeMap;

use forensic_rs::field::Text;
use forensic_rs::prelude::*;

/// Tool that queries Windows Security event logs for logon activity
///
/// Note: This is a MOCK implementation that returns realistic-looking data
/// without requiring actual .evtx files. For a real implementation,
/// see the EventLogReader trait and examples/event_gap_detector.rs.
pub struct LogonEventsTool {
    descriptor: ToolDescriptor,
}

impl LogonEventsTool {
    pub fn new() -> Self {
        Self {
            descriptor: ToolDescriptor {
                id: "security.logon_events".into(),
                title: "Security Logon Events".into(),
                description: "Queries Windows Security event log for logon activity \
                    including successful logons (4624), failed logons (4625), and \
                    special privilege assignments (4672). Use this to identify \
                    suspicious authentication patterns.".into(),

                input_schema: ValueSchema::object()
                    .property("case_id", ValueSchema::Type(ValueType::Text))
                    .required("case_id")
                    .property("hours", ValueSchema::Type(ValueType::Integer))
                    .into(),

                output_schema: Some(
                    ValueSchema::object()
                        .property("case_id", ValueSchema::Type(ValueType::Text))
                        .property("events", ValueSchema::Array(Box::new(
                            ValueSchema::Object(ObjectSchema {
                                properties: vec![
                                    (Text::Borrowed("time"), ValueSchema::Type(ValueType::Timestamp)),
                                    (Text::Borrowed("event_id"), ValueSchema::Type(ValueType::Integer)),
                                    (Text::Borrowed("event_type"), ValueSchema::Type(ValueType::Text)),
                                    (Text::Borrowed("user"), ValueSchema::Type(ValueType::Text)),
                                    (Text::Borrowed("logon_type"), ValueSchema::Type(ValueType::Text)),
                                    (Text::Borrowed("source_ip"), ValueSchema::Type(ValueType::Text)),
                                    (Text::Borrowed("message"), ValueSchema::Type(ValueType::Text)),
                                ],
                                required: vec![Text::Borrowed("time"), Text::Borrowed("event_id"),
                                               Text::Borrowed("event_type"), Text::Borrowed("user")],
                                allow_additional_properties: false,
                            })
                        )))
                        .property("total_found", ValueSchema::Type(ValueType::Integer))
                        .required(["case_id", "events", "total_found"])
                        .into(),
                ),

                hints: ToolHints {
                    read_only: true,
                    idempotent: true,
                    ..ToolHints::default()
                },
            },
        }
    }
}

impl ForensicTool for LogonEventsTool {
    fn descriptor(&self) -> &ToolDescriptor {
        &self.descriptor
    }

    fn invoke(
        &self,
        input: CapabilityValue,
        context: &InvocationContext,
    ) -> CapabilityResult<ToolResult> {
        // Parse input
        let fields = input.as_object().ok_or_else(||
            CapabilityError::new(CapabilityErrorKind::InvalidInput, "input must be an object")
        )?;

        let case_id = fields
            .get("case_id")
            .and_then(CapabilityValue::as_text)
            .ok_or_else(|| CapabilityError::new(CapabilityErrorKind::InvalidInput, "case_id required"))?;

        let hours = fields
            .get("hours")
            .and_then(CapabilityValue::as_u64)
            .unwrap_or(24) as u32;

        // Check cancellation
        if context.cancellation.is_cancelled() {
            return Err(CapabilityError::new(CapabilityErrorKind::Cancelled, "cancelled"));
        }

        // Report progress
        context.report_progress(
            ProgressUpdate::new(0).with_total(1)
                .with_message(format!("Querying Security event log (last {} hours)", hours))
        ).ok();

        // MOCK DATA: In a real implementation, you would:
        //
        // 1. Get EventLogReader from TriageSources
        //    let reader = sources.event_log().ok_or_else(|| ...)?;
        //
        // 2. Build query for logon events
        //    let query = EventLogQuery::new()
        //        .with_channels(&["Security"])
        //        .with_event_ids(&[4624, 4625, 4672])
        //        .with_levels(&[EventLevel::Information]);
        //
        // 3. Execute query
        //    let mut iter = reader.query(&query)?;
        //    while let Some(record) = iter.next()? {
        //        let event = parse_logon_event(&record)?;
        //        events.push(event);
        //    }

        // Mock event data (realistic for a potentially compromised workstation)
        let mock_events = vec![
            LogonEvent {
                time: ForensicTimestamp::with_ymd_and_hms(2024, 1, 15, 8, 0, 15, 0).unwrap(),
                event_id: 4624,
                event_type: "Successful Logon".to_string(),
                user: "WORKSTATION01\\Administrator".to_string(),
                logon_type: "Interactive (2)".to_string(),
                source_ip: "192.168.1.100".to_string(),
                message: "An account was successfully logged on.".to_string(),
            },
            LogonEvent {
                time: ForensicTimestamp::with_ymd_and_hms(2024, 1, 15, 8, 15, 32, 0).unwrap(),
                event_id: 4624,
                event_type: "Successful Logon".to_string(),
                user: "WORKSTATION01\\user1".to_string(),
                logon_type: "Interactive (2)".to_string(),
                source_ip: "192.168.1.101".to_string(),
                message: "An account was successfully logged on.".to_string(),
            },
            LogonEvent {
                time: ForensicTimestamp::with_ymd_and_hms(2024, 1, 15, 9, 22, 8, 0).unwrap(),
                event_id: 4625,
                event_type: "Failed Logon".to_string(),
                user: "WORKSTATION01\\Unknown".to_string(),
                logon_type: "Interactive (2)".to_string(),
                source_ip: "10.0.0.55".to_string(),
                message: "An account failed to log on.".to_string(),
            },
            LogonEvent {
                time: ForensicTimestamp::with_ymd_and_hms(2024, 1, 15, 9, 22, 15, 0).unwrap(),
                event_id: 4625,
                event_type: "Failed Logon".to_string(),
                user: "WORKSTATION01\\admin".to_string(),
                logon_type: "Interactive (2)".to_string(),
                source_ip: "10.0.0.55".to_string(),
                message: "An account failed to log on.".to_string(),
            },
            LogonEvent {
                time: ForensicTimestamp::with_ymd_and_hms(2024, 1, 15, 9, 23, 1, 0).unwrap(),
                event_id: 4624,
                event_type: "Successful Logon".to_string(),
                user: "WORKSTATION01\\admin".to_string(),
                logon_type: "Interactive (2)".to_string(),
                source_ip: "10.0.0.55".to_string(),
                message: "An account was successfully logged on.".to_string(),
            },
            LogonEvent {
                time: ForensicTimestamp::with_ymd_and_hms(2024, 1, 15, 9, 23, 5, 0).unwrap(),
                event_id: 4672,
                event_type: "Special Privileges Assigned".to_string(),
                user: "WORKSTATION01\\admin".to_string(),
                logon_type: "N/A".to_string(),
                source_ip: "N/A".to_string(),
                message: "Special privileges assigned to new logon.".to_string(),
            },
            LogonEvent {
                time: ForensicTimestamp::with_ymd_and_hms(2024, 1, 15, 14, 32, 0, 0).unwrap(),
                event_id: 4624,
                event_type: "Successful Logon".to_string(),
                user: "WORKSTATION01\\user1".to_string(),
                logon_type: "Network (3)".to_string(),
                source_ip: "192.168.1.50".to_string(),
                message: "An account was successfully logged on.".to_string(),
            },
        ];

        let total_found = mock_events.len();
        let events: Vec<_> = mock_events.into_iter().map(|e| {
            let mut map = BTreeMap::new();
            map.insert(Text::Borrowed("time"), CapabilityValue::Timestamp(e.time));
            map.insert(Text::Borrowed("event_id"), CapabilityValue::from(e.event_id));
            map.insert(Text::Borrowed("event_type"), CapabilityValue::from(e.event_type));
            map.insert(Text::Borrowed("user"), CapabilityValue::from(e.user));
            map.insert(Text::Borrowed("logon_type"), CapabilityValue::from(e.logon_type));
            map.insert(Text::Borrowed("source_ip"), CapabilityValue::from(e.source_ip));
            map.insert(Text::Borrowed("message"), CapabilityValue::from(e.message));
            CapabilityValue::Object(map)
        }).collect();

        // Report completion
        context.report_progress(
            ProgressUpdate::new(1).with_total(1).with_message("Query complete"))
        .ok();

        // Build result
        let mut result_map = BTreeMap::new();
        result_map.insert(Text::Borrowed("case_id"), CapabilityValue::from(case_id.to_string()));
        result_map.insert(Text::Borrowed("events"), CapabilityValue::Array(events));
        result_map.insert(Text::Borrowed("total_found"), CapabilityValue::from(total_found as u64));

        Ok(ToolResult::structured(CapabilityValue::Object(result_map)))
    }
}

#[derive(Clone)]
struct LogonEvent {
    time: ForensicTimestamp,
    event_id: u32,
    event_type: String,
    user: String,
    logon_type: String,
    source_ip: String,
    message: String,
}
```

## Event ID Reference

Common Security Logon Event IDs:

| Event ID | Description | Logon Type |
|----------|-------------|------------|
| 4624 | Successful logon | 2=Interactive, 3=Network, 10=RemoteInteractive |
| 4625 | Failed logon | 2=Interactive, 3=Network |
| 4672 | Special privileges assigned | N/A |
| 4634 | Logoff | Various |
| 4647 | User initiated logoff | Various |
| 4648 | Explicit credentials used | 2=Interactive |

## Real EventLogReader Pattern

For a real implementation, you would use `EventLogReader` like this:

```rust
// Pattern from examples/event_gap_detector.rs
use forensic_rs::traits::events::{EventLogQuery, EventLevel};

fn query_logons(reader: &dyn EventLogReader, hours: u32) -> ForensicResult<Vec<LogonEvent>> {
    let query = EventLogQuery::new()
        .with_channels(&["Security"])
        .with_event_ids(&[4624, 4625, 4672])
        .with_levels(&[EventLevel::Information]);

    let mut iter = reader.query(&query)?;
    let mut events = Vec::new();

    while let Some(record) = iter.next()? {
        // Parse record into LogonEvent
        let event = parse_event_record(&record)?;
        events.push(event);
    }

    Ok(events)
}
```

## Next Steps

- [Resources](./06_resources.md) - Expose event logs as ResourceProvider
- [Access Control](./07_access_control.md) - Implement authentication and authorization
- See [examples/event_gap_detector.rs](../../examples/event_gap_detector.rs) for event log analysis patterns
