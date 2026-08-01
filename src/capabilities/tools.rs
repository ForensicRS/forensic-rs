//! Protocol-neutral forensic tool contracts.

use std::sync::{Arc, Mutex};

use crate::{bridge::CancellationToken, field::Text};

use super::{access::AccessContext, schema::ValueSchema, value::CapabilityValue};

/// A progress update emitted while a tool invocation is active.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgressUpdate {
    /// Current completed work. Values must increase during an invocation.
    pub current: u64,
    /// Expected total work when known.
    pub total: Option<u64>,
    /// Human-readable status supplied by the tool.
    pub message: Option<String>,
}

impl ProgressUpdate {
    pub fn new(current: u64) -> Self {
        Self {
            current,
            total: None,
            message: None,
        }
    }

    pub fn with_total(mut self, total: u64) -> Self {
        self.total = Some(total);
        self
    }

    pub fn with_message(mut self, message: impl Into<String>) -> Self {
        self.message = Some(message.into());
        self
    }
}

/// Receives protocol-neutral progress updates from a running tool.
pub trait ProgressReporter: Send + Sync {
    fn report(&self, update: ProgressUpdate) -> CapabilityResult<()>;
}

/// Default reporter for callers that do not need progress notifications.
#[derive(Debug, Default)]
pub struct NoopProgressReporter;

impl ProgressReporter for NoopProgressReporter {
    fn report(&self, _update: ProgressUpdate) -> CapabilityResult<()> {
        Ok(())
    }
}

/// A caller-scoped tool invocation.
#[derive(Clone)]
pub struct InvocationContext {
    pub access: AccessContext,
    pub cancellation: CancellationToken,
    progress: Arc<dyn ProgressReporter>,
    last_progress: Arc<Mutex<Option<u64>>>,
}

impl std::fmt::Debug for InvocationContext {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("InvocationContext")
            .field("access", &self.access)
            .field("cancellation", &self.cancellation)
            .finish_non_exhaustive()
    }
}

impl InvocationContext {
    /// Create an invocation context from a trusted access context.
    pub fn new(access: AccessContext) -> Self {
        Self {
            access,
            cancellation: CancellationToken::new(),
            progress: Arc::new(NoopProgressReporter),
            last_progress: Arc::new(Mutex::new(None)),
        }
    }

    /// Replace the default no-op reporter with an adapter-provided reporter.
    pub fn with_progress_reporter(mut self, progress: Arc<dyn ProgressReporter>) -> Self {
        self.progress = progress;
        self
    }

    /// Emit a monotonic progress update for this invocation.
    pub fn report_progress(&self, update: ProgressUpdate) -> CapabilityResult<()> {
        if self.cancellation.is_cancelled() {
            return Err(CapabilityError::new(
                CapabilityErrorKind::Cancelled,
                "operation cancelled",
            ));
        }
        let mut last_progress = self.last_progress.lock().map_err(|_| {
            CapabilityError::new(
                CapabilityErrorKind::Internal,
                "progress state is unavailable",
            )
        })?;
        if let Some(last) = *last_progress {
            if update.current <= last {
                return Err(CapabilityError::new(
                    CapabilityErrorKind::InvalidInput,
                    "progress must increase during an invocation",
                ));
            }
        }
        if let Some(total) = update.total {
            if update.current > total {
                return Err(CapabilityError::new(
                    CapabilityErrorKind::InvalidInput,
                    "progress cannot exceed total",
                ));
            }
        }
        self.progress.report(update.clone())?;
        *last_progress = Some(update.current);
        Ok(())
    }
}

/// Stable, transport-neutral metadata used to discover a forensic tool.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq)]
pub struct ToolDescriptor {
    /// Stable identifier used for lookup and external adapter mapping.
    pub id: String,
    /// Human-readable name suitable for clients.
    pub title: String,
    /// Human-readable description of the tool behavior.
    pub description: String,
    /// Schema for untrusted tool arguments.
    pub input_schema: ValueSchema,
    /// Expected schema for structured output, when the tool returns one.
    pub output_schema: Option<ValueSchema>,
    pub hints: ToolHints,
}

/// Behavioral hints that external adapters may map to their protocol metadata.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ToolHints {
    pub read_only: bool,
    pub destructive: bool,
    pub idempotent: bool,
    pub opens_external_world: bool,
}

/// Content returned by a tool in addition to optional structured output.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq)]
pub enum ToolContent {
    Text(Text),
    Bytes {
        data: Vec<u8>,
        media_type: Option<String>,
    },
    ResourceReference {
        provider: String,
        path: String,
        name: String,
    },
}

/// Successful result from a forensic tool invocation.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq)]
pub struct ToolResult {
    pub content: Vec<ToolContent>,
    pub structured: Option<CapabilityValue>,
}

impl ToolResult {
    pub fn structured(value: CapabilityValue) -> Self {
        Self {
            content: Vec::new(),
            structured: Some(value),
        }
    }
}

/// Stable error categories suitable for a protocol adapter to map externally.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityErrorKind {
    InvalidInput,
    NotFound,
    Cancelled,
    AccessDenied,
    Conflict,
    Unavailable,
    Internal,
}

/// Error returned by the capability API.
///
/// Server-facing registries sanitize hidden/denied capability lookups to
/// [`CapabilityErrorKind::NotFound`] before they reach a requester.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityError {
    pub kind: CapabilityErrorKind,
    pub message: String,
}

impl CapabilityError {
    pub fn new(kind: CapabilityErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    pub fn not_found() -> Self {
        Self::new(CapabilityErrorKind::NotFound, "capability not found")
    }
}

impl std::fmt::Display for CapabilityError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for CapabilityError {}

pub type CapabilityResult<T> = Result<T, CapabilityError>;

/// A discoverable, caller-scoped forensic operation.
///
/// Implementations receive a trusted [`InvocationContext`]. They must treat
/// `input` as untrusted data and check `context.cancellation` during long work.
pub trait ForensicTool: Send + Sync {
    fn descriptor(&self) -> &ToolDescriptor;

    fn invoke(
        &self,
        input: CapabilityValue,
        context: &InvocationContext,
    ) -> CapabilityResult<ToolResult>;
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    #[derive(Default)]
    struct CollectingReporter {
        updates: Mutex<Vec<ProgressUpdate>>,
    }

    impl ProgressReporter for CollectingReporter {
        fn report(&self, update: ProgressUpdate) -> CapabilityResult<()> {
            self.updates.lock().unwrap().push(update);
            Ok(())
        }
    }

    #[test]
    fn invocation_progress_is_monotonic_and_forwarded() {
        let reporter = Arc::new(CollectingReporter::default());
        let context = InvocationContext::new(AccessContext::new("analyst", "tenant"))
            .with_progress_reporter(reporter.clone());
        context
            .report_progress(ProgressUpdate::new(1).with_total(2).with_message("started"))
            .unwrap();
        context
            .report_progress(ProgressUpdate::new(2).with_total(2))
            .unwrap();

        assert_eq!(reporter.updates.lock().unwrap().len(), 2);
        let error = context.report_progress(ProgressUpdate::new(2)).unwrap_err();
        assert_eq!(error.kind, CapabilityErrorKind::InvalidInput);

        context.cancellation.cancel();
        let error = context.report_progress(ProgressUpdate::new(3)).unwrap_err();
        assert_eq!(error.kind, CapabilityErrorKind::Cancelled);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_round_trip_preserves_tool_descriptor_and_result() {
        let descriptor = ToolDescriptor {
            id: "forensics.read_file".to_string(),
            title: "Read file".to_string(),
            description: "Reads authorized evidence".to_string(),
            input_schema: ValueSchema::Type(super::super::schema::ValueType::Object),
            output_schema: Some(ValueSchema::Type(super::super::schema::ValueType::Object)),
            hints: ToolHints {
                read_only: true,
                ..ToolHints::default()
            },
        };
        let result = ToolResult {
            content: vec![ToolContent::ResourceReference {
                provider: "evidence".to_string(),
                path: "/case/file.txt".to_string(),
                name: "file.txt".to_string(),
            }],
            structured: Some(CapabilityValue::from("ok")),
        };

        let descriptor_json = serde_json::to_string(&descriptor).unwrap();
        let result_json = serde_json::to_string(&result).unwrap();
        assert_eq!(
            serde_json::from_str::<ToolDescriptor>(&descriptor_json).unwrap(),
            descriptor
        );
        assert_eq!(
            serde_json::from_str::<ToolResult>(&result_json).unwrap(),
            result
        );
    }
}
