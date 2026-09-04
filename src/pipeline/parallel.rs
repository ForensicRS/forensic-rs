//! Parallel triage pipeline.
//!
//! Distributes independent analysis tasks across a thread-pool work queue.
//! Each task runs on a worker thread and streams [`PipelineEvent`] messages
//! over a **bounded** [`std::sync::mpsc::sync_channel`] back to the main
//! thread.  The main thread routes all records and findings through the shared
//! sinks — sinks therefore need no `Send` bound.
//!
//! # Recommended API: [`AnalysisModule`]
//!
//! [`AnalysisModule`] is the **primary** way to create parallel tasks.
//! Build it with [`AnalysisModuleBuilder`], then register parser factories on
//! the pipeline builder. At `build()` time parsers are automatically matched
//! to each module by intersecting the analyzer's `supported_artifacts()`
//! with each factory's [`ParserDescriptor::artifacts`](crate::traits::forensic::ParserDescriptor):
//!
//! ```rust,ignore
//! // 1. Build an analyzer-centric module — no explicit parsers needed.
//! let module = AnalysisModuleBuilder::new("evt_gap")
//!     .analyzer(Box::new(EventGapDetector::new()))
//!     .sources(|| TriageSources::builder().build())
//!     .context(TriageContext::new("HOST01", "case-42"))
//!     .build()?;
//!
//! // 2. Register factories once; auto-matching injects them at build() time.
//! let mut pipeline = ParallelPipeline::builder()
//!     .workers(4)
//!     .module(module)
//!     .parser(Arc::new(EvtxParserFactory::new()))
//!     .sink(Box::new(FindingCollector::new()))
//!     .build()?;
//!
//! // 3. Run and inspect per-task statistics.
//! let result = pipeline.run()?;
//! for (task, stats) in &result.task_stats {
//!     println!("{task}: {} items, {} findings", stats.items_processed, stats.findings_count);
//! }
//! ```
//!
//! For full control (multiple analyzers, custom source setup) use
//! [`StandardParallelTask`] via [`StandardParallelTaskBuilder`].
//!
//! # Thread-safety model
//!
//! | Component | Requirement |
//! |-----------|-------------|
//! | [`AnalysisModule`] | `Send + 'static` — built via [`AnalysisModuleBuilder`] |
//! | [`StandardParallelTask`] | `Send + 'static` — lower-level alternative |
//! | Parser factory | `Send + Sync` (part of [`ArtifactParserFactory`]'s bound) — one `Arc` can serve every worker |
//! | Enricher / Analyzer inside a task | `Send + 'static` |
//! | [`TriageSources`] | **none** – created on the worker thread via the sources factory |
//! | [`TriageSink`] | **none** – only ever called from the main thread |

use std::collections::{BTreeMap, VecDeque};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::mpsc::{self, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread;

use compact_str::CompactString;

use crate::{
    bridge::CancellationToken,
    data::ForensicData,
    err::{ForensicError, ForensicResult},
    traits::forensic::{ArtifactParserFactory, ParserRun},
};

use super::{
    context::{ParseContext, TriageContext},
    finding::{AnomalyTally, Finding},
    processor::{ChannelDestination, RecordProcessor},
    sources::TriageSources,
    traits::{Analyzer, Enricher, TriageSink},
    ErrorAction,
};

// ============================================================
// PipelineEvent
// ============================================================

/// A message streamed from a worker thread to the main thread.
pub enum PipelineEvent {
    /// A processed `ForensicData` record ready for sinks.
    Data(ForensicData),
    /// A `Finding` produced by an analyzer.
    Finding(Finding),
    /// A non-fatal error that occurred during task execution.
    TaskError { task: String, error: ForensicError },
    /// Signals that a task finished, carrying its local statistics.
    TaskDone {
        task: String,
        items_processed: u64,
        findings_count: u64,
    },
}

// ============================================================
// ParallelPipelineTask trait
// ============================================================

/// A self-contained unit of parallel work.
///
/// Implement this trait for full control over task execution.
/// For the common case — a single parser with enrichers and analyzers —
/// use [`StandardParallelTask`] via [`StandardParallelTaskBuilder`].
pub trait ParallelPipelineTask: Send + 'static {
    /// Short identifier, used in results and log messages.
    fn name(&self) -> &str;

    /// Execute the task, streaming events to the main thread.
    ///
    /// `tx` is a clone of the pipeline's bounded channel sender.  If the
    /// channel is full the `send` call will block until capacity is
    /// available, providing backpressure.  The task consumes itself so its
    /// resources are freed on the worker thread when execution completes.
    fn run(self: Box<Self>, tx: SyncSender<PipelineEvent>);

    /// Execute the task with cooperative cancellation support.
    ///
    /// Existing task implementations can rely on the default behavior. Built-in
    /// tasks override this method and check `cancellation` between records.
    fn run_cancellable(
        self: Box<Self>,
        tx: SyncSender<PipelineEvent>,
        _cancellation: CancellationToken,
    ) {
        self.run(tx);
    }

    /// Adopt a pipeline-wide default [`TriageContext`] (see
    /// [`ParallelPipelineBuilder::context`]), if this task wasn't given its
    /// own explicit context already. No-op by default — a third-party
    /// [`ParallelPipelineTask`] that manages its own context can leave this
    /// unimplemented and simply not participate in the shared-store
    /// mechanism.
    fn adopt_shared_context(&mut self, _ctx: &TriageContext) {}
}

// ============================================================
// Task statistics / result types
// ============================================================

/// Per-task item and finding counts, included in [`ParallelPipelineResult`].
#[derive(Debug, Default, Clone)]
pub struct TaskStats {
    /// `ForensicData` records produced by this task.
    pub items_processed: u64,
    /// `Finding`s produced by this task's analyzers.
    pub findings_count: u64,
}

/// Summary of a completed parallel pipeline run.
#[derive(Debug, Default)]
pub struct ParallelPipelineResult {
    /// Total `ForensicData` records that reached the sinks.
    pub items_processed: u64,
    /// Total `Finding`s that reached the sinks.
    pub findings_count: u64,
    /// Non-fatal errors, as `(task_name, error)` pairs.
    pub errors: Vec<(String, ForensicError)>,
    /// Names of all tasks that ran (in completion order).
    pub tasks_run: Vec<String>,
    /// Per-task breakdown of items and findings.
    pub task_stats: BTreeMap<String, TaskStats>,
    /// The shared [`crate::provenance::ProvenanceStore`] every task/module
    /// minted into, when [`ParallelPipelineBuilder::context`] configured
    /// one. `None` if no pipeline-wide context was set — in that case each
    /// task minted into its own independent store and no single handle
    /// here could resolve confidence across all of them.
    ///
    /// Cheap to clone (an `Arc` handle) — use it to call
    /// `data.confidence(&store)` on records a sink collected during this
    /// run.
    pub provenance_store: Option<crate::provenance::ProvenanceStore>,
}

// ============================================================
// StandardParallelTask
// ============================================================

/// A parallel task that wraps a single parser with its enrichers, analyzers,
/// and a lazy source factory.
///
/// The `sources_factory` closure is called *on the worker thread*, so
/// [`TriageSources`] does not need to be `Send`.
///
/// Build with [`StandardParallelTaskBuilder`].
pub struct StandardParallelTask {
    name: String,
    factory: Arc<dyn ArtifactParserFactory>,
    enrichers: Vec<Box<dyn Enricher + Send + 'static>>,
    analyzers: Vec<Box<dyn Analyzer + Send + 'static>>,
    /// Called on the worker thread so `TriageSources` needs no `Send` bound.
    sources_factory: Box<dyn FnOnce() -> TriageSources + Send + 'static>,
    context: Option<TriageContext>,
    error_action: ErrorAction,
}

impl ParallelPipelineTask for StandardParallelTask {
    fn name(&self) -> &str {
        &self.name
    }

    fn run(self: Box<Self>, tx: SyncSender<PipelineEvent>) {
        self.run_cancellable(tx, CancellationToken::new());
    }

    fn run_cancellable(
        mut self: Box<Self>,
        tx: SyncSender<PipelineEvent>,
        cancellation: CancellationToken,
    ) {
        let task_name = self.name.clone();

        if cancellation.is_cancelled() {
            let _ = tx.send(PipelineEvent::TaskDone {
                task: task_name,
                items_processed: 0,
                findings_count: 0,
            });
            return;
        }

        // Install the thread-local ForensicContext for this worker thread.
        // Fall back to a default context if none was provided.
        let mut context = self.context.take().unwrap_or_default();
        context.install();

        // Create data sources on the worker thread via the factory.
        let sources = (self.sources_factory)();
        let analyzer_artifacts: Vec<Vec<crate::artifact::Artifact>> = self
            .analyzers
            .iter()
            .map(|analyzer| analyzer.supported_artifacts())
            .collect();

        let ctx = ParseContext::new(&sources, &context, &cancellation);
        if !self.factory.can_parse(&ctx) {
            let _ = tx.send(PipelineEvent::TaskDone {
                task: task_name,
                items_processed: 0,
                findings_count: 0,
            });
            return;
        }

        let parser_id = self.factory.descriptor().id.to_string();
        let run = match self.factory.open(&ctx) {
            Ok(run) => run,
            Err(e) => {
                let finding = Finding::from_error(format!("parser '{parser_id}'"), &e);
                if tx.send(PipelineEvent::Finding(finding)).is_err() {
                    return;
                }
                let _ = tx.send(PipelineEvent::TaskError {
                    task: task_name.clone(),
                    error: e,
                });
                let _ = tx.send(PipelineEvent::TaskDone {
                    task: task_name,
                    items_processed: 0,
                    findings_count: 1,
                });
                return;
            }
        };

        let mut tally = AnomalyTally::new();
        let mut dest = ChannelDestination::new(tx.clone());
        let mut proc = RecordProcessor::new(
            &mut dest,
            &mut self.enrichers,
            &mut self.analyzers,
            &analyzer_artifacts,
            &mut context,
            &mut tally,
            &cancellation,
            self.error_action,
            // The parallel pipeline has always respected `ErrorAction::Halt`
            // at every stage (parser, enricher, analyzer) — preserved here.
            true,
            &parser_id,
        );

        match run {
            ParserRun::Pull(stream) => proc.drive_pull(stream),
            ParserRun::Push(drive) => {
                if let Err(e) = drive(&mut proc) {
                    proc.parser_error(e);
                }
            }
        }

        // Halt or not, finalize still runs — this task has only ever had
        // one parser, so there is nothing left to skip either way.
        proc.finalize_analyzers();
        proc.flush_tally();
        let outcome = proc.finish();

        for error in outcome.errors {
            let _ = tx.send(PipelineEvent::TaskError {
                task: task_name.clone(),
                error,
            });
        }

        let _ = tx.send(PipelineEvent::TaskDone {
            task: task_name,
            items_processed: outcome.items,
            findings_count: outcome.findings,
        });
    }

    fn adopt_shared_context(&mut self, ctx: &TriageContext) {
        if self.context.is_none() {
            self.context = Some(ctx.clone());
        }
    }
}

// ============================================================
// StandardParallelTaskBuilder
// ============================================================

/// Fluent builder for [`StandardParallelTask`].
///
/// # Example
/// ```rust,ignore
/// let task = StandardParallelTaskBuilder::new("mft_parser")
///     .parser(Arc::new(MftParserFactory::new()))
///     .analyzer(Box::new(MftGapAnalyzer::new()))
///     .sources(|| TriageSources::builder()
///         .vfs(Box::new(ZipVirtualFS::open("triage.zip").unwrap()))
///         .build())
///     .context(TriageContext::new("WORKSTATION01", "acme"))
///     .build()?;
/// ```
pub struct StandardParallelTaskBuilder {
    name: String,
    parser: Option<Arc<dyn ArtifactParserFactory>>,
    enrichers: Vec<Box<dyn Enricher + Send + 'static>>,
    analyzers: Vec<Box<dyn Analyzer + Send + 'static>>,
    sources_factory: Option<Box<dyn FnOnce() -> TriageSources + Send + 'static>>,
    context: Option<TriageContext>,
    error_action: ErrorAction,
}

impl StandardParallelTaskBuilder {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            parser: None,
            enrichers: Vec::new(),
            analyzers: Vec::new(),
            sources_factory: None,
            context: None,
            error_action: ErrorAction::Continue,
        }
    }

    /// Set the parser for this task. **Required.**
    pub fn parser(mut self, parser: Arc<dyn ArtifactParserFactory>) -> Self {
        self.parser = Some(parser);
        self
    }

    pub fn enricher(mut self, enricher: Box<dyn Enricher + Send + 'static>) -> Self {
        self.enrichers.push(enricher);
        self
    }

    pub fn analyzer(mut self, analyzer: Box<dyn Analyzer + Send + 'static>) -> Self {
        self.analyzers.push(analyzer);
        self
    }

    /// Supply a closure that creates [`TriageSources`] **on the worker thread**.
    ///
    /// Because the closure is called on the worker thread, `TriageSources`
    /// itself does not need to be `Send`.  **Required.**
    pub fn sources(mut self, factory: impl FnOnce() -> TriageSources + Send + 'static) -> Self {
        self.sources_factory = Some(Box::new(factory));
        self
    }

    /// Set the [`TriageContext`] for this task.
    ///
    /// If not set, a default context is used.  The context is installed as
    /// the thread-local [`ForensicContext`](crate::context::ForensicContext)
    /// at the start of task execution.
    pub fn context(mut self, ctx: TriageContext) -> Self {
        self.context = Some(ctx);
        self
    }

    /// Configure error handling. Defaults to [`ErrorAction::Continue`].
    pub fn on_error(mut self, action: ErrorAction) -> Self {
        self.error_action = action;
        self
    }

    /// Build the task.
    ///
    /// Returns an error if no parser or no sources factory was provided.
    pub fn build(self) -> ForensicResult<StandardParallelTask> {
        let parser = match self.parser {
            Some(p) => p,
            None => {
                return Err(ForensicError::missing_data(
                    "parser",
                    CompactString::const_new("StandardParallelTaskBuilder: call .parser() before .build()"),
                ))
            }
        };
        let sources_factory = match self.sources_factory {
            Some(f) => f,
            None => {
                return Err(ForensicError::missing_data(
                    "sources_factory",
                    CompactString::const_new("StandardParallelTaskBuilder: call .sources() before .build()"),
                ))
            }
        };
        Ok(StandardParallelTask {
            name: self.name,
            factory: parser,
            enrichers: self.enrichers,
            analyzers: self.analyzers,
            sources_factory,
            context: self.context,
            error_action: self.error_action,
        })
    }
}

// ============================================================
// AnalysisModule  (analyzer-centric parallel task)
// ============================================================

/// An analyzer-centric parallel task.
///
/// `AnalysisModule` inverts the ownership model compared to
/// [`StandardParallelTask`]: the **analyzer** is the primary concept and
/// declares (via [`Analyzer::supported_artifacts`]) which artifact types it
/// needs.  Parsers are resolved from that declaration.
///
/// Two wiring modes — mutually exclusive:
/// - **Explicit**: add parsers directly via
///   [`AnalysisModuleBuilder::parser`].  Auto-match is skipped.
/// - **Auto-match**: leave the parser list empty and register factories on
///   [`ParallelPipelineBuilder::parser`].  At `build()` time the pipeline
///   intersects the analyzer's supported artifacts with each factory's
///   [`ParserDescriptor::artifacts`](crate::traits::forensic::ParserDescriptor)
///   and injects matching parsers — sharing the same `Arc`, never
///   constructing anything.
///
/// All parsers share the same [`TriageSources`] instance (created once per
/// task on the worker thread).  The analyzer's `finalize()` is called once
/// after **all** parsers finish, enabling cross-parser aggregate detection.
///
/// Build with [`AnalysisModuleBuilder`].
pub struct AnalysisModule {
    name: String,
    analyzer: Box<dyn Analyzer + Send + 'static>,
    parsers: Vec<Arc<dyn ArtifactParserFactory>>,
    enrichers: Vec<Box<dyn Enricher + Send + 'static>>,
    sources_factory: Box<dyn FnOnce() -> TriageSources + Send + 'static>,
    context: Option<TriageContext>,
    error_action: ErrorAction,
}

impl ParallelPipelineTask for AnalysisModule {
    fn name(&self) -> &str {
        &self.name
    }

    fn run(self: Box<Self>, tx: SyncSender<PipelineEvent>) {
        self.run_cancellable(tx, CancellationToken::new());
    }

    fn run_cancellable(
        mut self: Box<Self>,
        tx: SyncSender<PipelineEvent>,
        cancellation: CancellationToken,
    ) {
        let task_name = self.name.clone();

        if cancellation.is_cancelled() {
            let _ = tx.send(PipelineEvent::TaskDone {
                task: task_name,
                items_processed: 0,
                findings_count: 0,
            });
            return;
        }

        let mut context = self.context.take().unwrap_or_default();
        context.install();

        // All parsers for this module share one TriageSources instance,
        // created on the worker thread via the factory.
        let sources = (self.sources_factory)();
        // One analyzer, so this is a length-1 slice — `RecordProcessor` is
        // generic over the analyzer count to share its logic with
        // `StandardParallelTask`'s N-analyzer shape.
        let analyzer_artifacts = vec![self.analyzer.supported_artifacts()];

        let mut total_items: u64 = 0;
        let mut total_findings: u64 = 0;
        let mut all_errors: Vec<ForensicError> = Vec::new();
        // Shared across every parser in this module — flushed once, after
        // all parsers, into aggregate cross-parser findings.
        let mut tally = AnomalyTally::new();

        'parsers: for factory in &self.parsers {
            if cancellation.is_cancelled() {
                break 'parsers;
            }
            let ctx = ParseContext::new(&sources, &context, &cancellation);
            if !factory.can_parse(&ctx) {
                continue 'parsers;
            }

            let parser_id = factory.descriptor().id.to_string();
            let run = match factory.open(&ctx) {
                Ok(run) => run,
                Err(e) => {
                    let finding = Finding::from_error(format!("parser '{parser_id}'"), &e);
                    if tx.send(PipelineEvent::Finding(finding)).is_err() {
                        return;
                    }
                    total_findings += 1;
                    let _ = tx.send(PipelineEvent::TaskError {
                        task: task_name.clone(),
                        error: e,
                    });
                    match self.error_action {
                        ErrorAction::Continue => continue 'parsers,
                        ErrorAction::Halt => break 'parsers,
                    }
                }
            };

            let mut dest = ChannelDestination::new(tx.clone());
            let mut proc = RecordProcessor::new(
                &mut dest,
                &mut self.enrichers,
                std::slice::from_mut(&mut self.analyzer),
                &analyzer_artifacts,
                &mut context,
                &mut tally,
                &cancellation,
                self.error_action,
                true,
                &parser_id,
            );

            match run {
                ParserRun::Pull(stream) => proc.drive_pull(stream),
                ParserRun::Push(drive) => {
                    if let Err(e) = drive(&mut proc) {
                        proc.parser_error(e);
                    }
                }
            }

            // `is_stopped` also covers the channel's receiver having been
            // dropped mid-parse — not just an `ErrorAction::Halt` — so a
            // closed channel stops the whole module instead of wastefully
            // opening every remaining parser.
            let stop = proc.is_stopped();
            let outcome = proc.finish();
            total_items += outcome.items;
            total_findings += outcome.findings;
            all_errors.extend(outcome.errors);
            if stop {
                break 'parsers;
            }
        }

        // Finalize once after all parsers — enables cross-parser analysis —
        // and flush the module-wide tally, regardless of whether the loop
        // above ended naturally or via `ErrorAction::Halt`.
        let mut dest = ChannelDestination::new(tx.clone());
        let mut final_proc = RecordProcessor::new(
            &mut dest,
            &mut self.enrichers,
            std::slice::from_mut(&mut self.analyzer),
            &analyzer_artifacts,
            &mut context,
            &mut tally,
            &cancellation,
            self.error_action,
            true,
            "",
        );
        final_proc.finalize_analyzers();
        final_proc.flush_tally();
        let final_outcome = final_proc.finish();
        total_findings += final_outcome.findings;
        all_errors.extend(final_outcome.errors);

        for error in all_errors {
            let _ = tx.send(PipelineEvent::TaskError {
                task: task_name.clone(),
                error,
            });
        }

        let _ = tx.send(PipelineEvent::TaskDone {
            task: task_name,
            items_processed: total_items,
            findings_count: total_findings,
        });
    }

    fn adopt_shared_context(&mut self, ctx: &TriageContext) {
        if self.context.is_none() {
            self.context = Some(ctx.clone());
        }
    }
}

// ============================================================
// AnalysisModuleBuilder
// ============================================================

/// Fluent builder for [`AnalysisModule`].
///
/// # Example
/// ```rust,ignore
/// let module = AnalysisModuleBuilder::new("mft_gap_analysis")
///     .analyzer(Box::new(MftGapAnalyzer::new()))
///     .parser(Arc::new(MftParserFactory::new()))    // explicit — overrides auto-match
///     .sources(|| TriageSources::builder()
///         .vfs(Box::new(ZipVfs::open("triage.zip")?))
///         .build())
///     .context(TriageContext::new("WORKSTATION01", "acme"))
///     .build()?;
/// ```
pub struct AnalysisModuleBuilder {
    name: String,
    analyzer: Option<Box<dyn Analyzer + Send + 'static>>,
    parsers: Vec<Arc<dyn ArtifactParserFactory>>,
    enrichers: Vec<Box<dyn Enricher + Send + 'static>>,
    sources_factory: Option<Box<dyn FnOnce() -> TriageSources + Send + 'static>>,
    context: Option<TriageContext>,
    error_action: ErrorAction,
}

impl AnalysisModuleBuilder {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            analyzer: None,
            parsers: Vec::new(),
            enrichers: Vec::new(),
            sources_factory: None,
            context: None,
            error_action: ErrorAction::Continue,
        }
    }

    /// Set the analyzer. **Required.**
    ///
    /// The analyzer's [`Analyzer::supported_artifacts`] declaration drives
    /// parser auto-matching when no explicit parsers are supplied.
    pub fn analyzer(mut self, analyzer: Box<dyn Analyzer + Send + 'static>) -> Self {
        self.analyzer = Some(analyzer);
        self
    }

    /// Add an explicit parser.
    ///
    /// Calling this at least once disables auto-matching — the module will
    /// only use the parsers you provide.
    pub fn parser(mut self, parser: Arc<dyn ArtifactParserFactory>) -> Self {
        self.parsers.push(parser);
        self
    }

    pub fn enricher(mut self, enricher: Box<dyn Enricher + Send + 'static>) -> Self {
        self.enrichers.push(enricher);
        self
    }

    /// Supply a closure that creates [`TriageSources`] **on the worker thread**.
    ///
    /// The closure is called once; all parsers in the module share the
    /// resulting sources.  **Required.**
    pub fn sources(mut self, factory: impl FnOnce() -> TriageSources + Send + 'static) -> Self {
        self.sources_factory = Some(Box::new(factory));
        self
    }

    pub fn context(mut self, ctx: TriageContext) -> Self {
        self.context = Some(ctx);
        self
    }

    /// Configure error handling. Defaults to [`ErrorAction::Continue`].
    pub fn on_error(mut self, action: ErrorAction) -> Self {
        self.error_action = action;
        self
    }

    /// Build the module.
    ///
    /// Returns an error if no analyzer or no sources factory was provided.
    /// If no parsers were added, auto-matching will be performed by
    /// [`ParallelPipelineBuilder::build`] if any parsers are registered.
    pub fn build(self) -> ForensicResult<AnalysisModule> {
        let analyzer = match self.analyzer {
            Some(a) => a,
            None => {
                return Err(ForensicError::missing_data(
                    "analyzer",
                    CompactString::const_new("AnalysisModuleBuilder: call .analyzer() before .build()"),
                ))
            }
        };
        let sources_factory = match self.sources_factory {
            Some(f) => f,
            None => {
                return Err(ForensicError::missing_data(
                    "sources_factory",
                    CompactString::const_new("AnalysisModuleBuilder: call .sources() before .build()"),
                ))
            }
        };
        Ok(AnalysisModule {
            name: self.name,
            analyzer,
            parsers: self.parsers,
            enrichers: self.enrichers,
            sources_factory,
            context: self.context,
            error_action: self.error_action,
        })
    }
}

// ============================================================
// ParallelPipeline
// ============================================================

/// Parallel counterpart to [`TriagePipeline`](super::TriagePipeline).
///
/// Distributes tasks across a thread-pool work queue where each worker pulls
/// the next available task as soon as it finishes its current one.  Results
/// are funnelled back to the main thread via a bounded channel and routed
/// through shared sinks.
///
/// Use [`ParallelPipeline::builder`] to construct.
pub struct ParallelPipeline {
    workers: usize,
    channel_capacity: usize,
    tasks: Vec<Box<dyn ParallelPipelineTask>>,
    sinks: Vec<Box<dyn TriageSink>>,
    provenance_store: Option<crate::provenance::ProvenanceStore>,
}

impl ParallelPipeline {
    pub fn builder() -> ParallelPipelineBuilder {
        ParallelPipelineBuilder::new()
    }

    /// Execute all tasks in parallel and route results to the shared sinks.
    ///
    /// Tasks are moved onto worker threads and consumed.  After this call the
    /// task list is empty; the sinks remain accessible for post-run inspection.
    ///
    /// The method blocks until every task has finished and all sinks have been
    /// finalised.
    pub fn run(&mut self) -> ForensicResult<ParallelPipelineResult> {
        self.run_with_cancellation(CancellationToken::new())
    }

    /// Execute all tasks with cooperative cancellation support.
    ///
    /// Cancellation prevents built-in tasks from starting additional parser
    /// work and stops them between records. A task already blocked in backend
    /// I/O must be cancelled by that backend's own mechanism.
    pub fn run_with_cancellation(
        &mut self,
        cancellation: CancellationToken,
    ) -> ForensicResult<ParallelPipelineResult> {
        let mut result = ParallelPipelineResult {
            provenance_store: self.provenance_store.clone(),
            ..Default::default()
        };

        if self.tasks.is_empty() {
            for sink in &mut self.sinks {
                sink.finalize()?;
            }
            return Ok(result);
        }

        // Bounded channel — workers block when it's full (backpressure).
        let (tx, rx) = mpsc::sync_channel::<PipelineEvent>(self.channel_capacity);

        // Move all tasks into a shared work queue.
        let task_queue: Arc<Mutex<VecDeque<Box<dyn ParallelPipelineTask>>>> = {
            let mut q = VecDeque::with_capacity(self.tasks.len());
            for task in self.tasks.drain(..) {
                q.push_back(task);
            }
            Arc::new(Mutex::new(q))
        };

        let worker_count = {
            let q = task_queue.lock().unwrap();
            self.workers.min(q.len())
        };
        let mut handles = Vec::with_capacity(worker_count);

        for _ in 0..worker_count {
            let queue = Arc::clone(&task_queue);
            let worker_tx = tx.clone();
            let worker_cancellation = cancellation.clone();
            handles.push(thread::spawn(move || {
                loop {
                    let task = {
                        let mut q = queue.lock().unwrap();
                        q.pop_front()
                    };
                    match task {
                        Some(t) => {
                            let task_name = t.name().to_string();
                            if catch_unwind(AssertUnwindSafe(|| {
                                t.run_cancellable(worker_tx.clone(), worker_cancellation.clone());
                            }))
                            .is_err()
                            {
                                let _ = worker_tx.send(PipelineEvent::TaskError {
                                    task: task_name.clone(),
                                    error: ForensicError::other(
                                        "pipeline",
                                        "task panicked during execution".to_string(),
                                    ),
                                });
                                let _ = worker_tx.send(PipelineEvent::TaskDone {
                                    task: task_name,
                                    items_processed: 0,
                                    findings_count: 0,
                                });
                            }
                        }
                        None => break,
                    }
                }
                // worker_tx drops here, decrementing the sender count.
            }));
        }

        // Drop the original sender so the channel closes when all workers finish.
        drop(tx);

        // Main-thread event loop — fan events into sinks.
        for event in rx {
            match event {
                PipelineEvent::Data(data) => {
                    result.items_processed += 1;
                    for sink in &mut self.sinks {
                        if let Err(e) = sink.on_data(&data) {
                            result.errors.push(("sink".to_string(), e));
                        }
                    }
                }
                PipelineEvent::Finding(finding) => {
                    result.findings_count += 1;
                    for sink in &mut self.sinks {
                        if let Err(e) = sink.on_finding(&finding) {
                            result.errors.push(("sink".to_string(), e));
                        }
                    }
                }
                PipelineEvent::TaskError { task, error } => {
                    result.errors.push((task, error));
                }
                PipelineEvent::TaskDone {
                    task,
                    items_processed,
                    findings_count,
                } => {
                    if !result.tasks_run.contains(&task) {
                        result.tasks_run.push(task.clone());
                    }
                    let stats = result.task_stats.entry(task).or_default();
                    stats.items_processed += items_processed;
                    stats.findings_count += findings_count;
                }
            }
        }

        // Join worker threads.
        for handle in handles {
            let _ = handle.join();
        }

        // Finalize sinks now that all events have been processed.
        for sink in &mut self.sinks {
            if let Err(e) = sink.finalize() {
                result.errors.push(("sink_finalize".to_string(), e));
            }
        }

        Ok(result)
    }

    /// Number of worker threads this pipeline was configured with.
    pub fn workers(&self) -> usize {
        self.workers
    }

    /// Channel backpressure capacity.
    pub fn channel_capacity(&self) -> usize {
        self.channel_capacity
    }

    /// The shared [`crate::provenance::ProvenanceStore`] configured via
    /// [`ParallelPipelineBuilder::context`], if any — available before
    /// [`Self::run`] returns, so a caller can start resolving confidence on
    /// records a sink collects as the run progresses rather than only
    /// after it completes. Also returned on [`ParallelPipelineResult`].
    pub fn provenance_store(&self) -> Option<&crate::provenance::ProvenanceStore> {
        self.provenance_store.as_ref()
    }
}

// ============================================================
// ParallelPipelineBuilder
// ============================================================

/// Fluent builder for [`ParallelPipeline`].
pub struct ParallelPipelineBuilder {
    workers: usize,
    channel_capacity: Option<usize>,
    tasks: Vec<Box<dyn ParallelPipelineTask>>,
    pending_modules: Vec<AnalysisModule>,
    /// Pool of parsers available for auto-matching into `pending_modules`.
    /// Each is an `Arc`, so a single instance can be shared into any number
    /// of matching modules with no construction at match time.
    parsers: Vec<Arc<dyn ArtifactParserFactory>>,
    sinks: Vec<Box<dyn TriageSink>>,
    context: Option<TriageContext>,
}

impl ParallelPipelineBuilder {
    pub fn new() -> Self {
        let workers = thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4);
        Self {
            workers,
            channel_capacity: None,
            tasks: Vec::new(),
            pending_modules: Vec::new(),
            parsers: Vec::new(),
            sinks: Vec::new(),
            context: None,
        }
    }

    /// Set a pipeline-wide default [`TriageContext`], propagated to every
    /// task/module that doesn't set its own explicit context via its own
    /// builder's `.context()`.
    ///
    /// Without this, each task/module that doesn't set its own context
    /// falls back to `TriageContext::default()` independently — a
    /// *different* default instance per task, and therefore a different,
    /// unshared [`crate::provenance::ProvenanceStore`] per task. A record
    /// reaching a sink on the main thread then carries a `ProvenanceId`
    /// that resolves only against the one store its own task happened to
    /// use, which the main thread has no handle to — `data.confidence(&store)`
    /// is effectively unavailable. Setting a shared context here — and
    /// keeping a `.provenance_store()` handle to it, or reading
    /// [`ParallelPipelineResult::provenance_store`] after the run — closes
    /// that gap: every task/module clones the same context, which clones
    /// the same underlying store (see [`TriageContext`]'s `Clone` docs).
    ///
    /// A task/module with its own explicit `.context(...)` is left alone —
    /// this only fills in tasks/modules that didn't set one.
    pub fn context(mut self, ctx: TriageContext) -> Self {
        self.context = Some(ctx);
        self
    }

    /// Number of worker threads.
    ///
    /// Defaults to [`std::thread::available_parallelism`] (number of logical
    /// CPU cores), falling back to 4 if unavailable.
    pub fn workers(mut self, n: usize) -> Self {
        self.workers = n.max(1);
        self
    }

    /// Capacity of the bounded channel between worker threads and main thread.
    ///
    /// When the channel is full, worker threads block until the main thread
    /// consumes events, preventing runaway memory growth.
    ///
    /// Defaults to `workers × 64`.
    pub fn channel_capacity(mut self, n: usize) -> Self {
        self.channel_capacity = Some(n.max(1));
        self
    }

    /// Add a low-level [`ParallelPipelineTask`] (e.g. a [`StandardParallelTask`]).
    ///
    /// For analyzer-centric orchestration prefer [`ParallelPipelineBuilder::module`].
    pub fn task(mut self, task: Box<dyn ParallelPipelineTask>) -> Self {
        self.tasks.push(task);
        self
    }

    /// Add an [`AnalysisModule`].
    ///
    /// If the module was built without explicit parsers, parser auto-matching
    /// is performed at [`build`](Self::build) time using the parsers
    /// registered via [`Self::parser`].
    pub fn module(mut self, module: AnalysisModule) -> Self {
        self.pending_modules.push(module);
        self
    }

    /// Register a parser for auto-matching.
    ///
    /// At [`build`](Self::build) time the pipeline intersects each parser's
    /// [`ParserDescriptor::artifacts`](crate::traits::forensic::ParserDescriptor)
    /// with each [`AnalysisModule`]'s [`Analyzer::supported_artifacts`]. When
    /// the sets overlap, the same `Arc` is cloned into that module — no
    /// construction happens at match time, so registering a parser here
    /// costs nothing for a module it doesn't end up matching.
    ///
    /// A parser registered here is **never** added to modules that already
    /// have explicit parsers — explicit always wins. If an analyzer's
    /// `supported_artifacts()` is empty (the "accept all" default) it
    /// receives every registered parser.
    pub fn parser(mut self, parser: Arc<dyn ArtifactParserFactory>) -> Self {
        self.parsers.push(parser);
        self
    }

    /// Registers every factory currently in `registry` for auto-matching.
    pub fn parsers_from(mut self, registry: &super::registry::ParserRegistry) -> Self {
        self.parsers
            .extend(registry.ids().filter_map(|id| registry.get(id)).cloned());
        self
    }

    pub fn sink(mut self, sink: Box<dyn TriageSink>) -> Self {
        self.sinks.push(sink);
        self
    }

    /// Finalise the builder, performing parser auto-matching and returning
    /// a ready-to-run [`ParallelPipeline`].
    pub fn build(mut self) -> ForensicResult<ParallelPipeline> {
        let capacity = self.channel_capacity.unwrap_or(self.workers * 64);

        // Auto-match: inject parsers into modules that have none. Matching
        // never constructs anything — it only clones an `Arc`.
        for module in &mut self.pending_modules {
            if module.parsers.is_empty() && !self.parsers.is_empty() {
                let analyzer_artifacts = module.analyzer.supported_artifacts();
                for parser in &self.parsers {
                    let descriptor = parser.descriptor();
                    let matches = analyzer_artifacts.is_empty()
                        || analyzer_artifacts.iter().any(|a| descriptor.handles(a));
                    if matches {
                        module.parsers.push(Arc::clone(parser));
                    }
                }
            }
        }

        // Propagate the pipeline-wide default context to every task/module
        // that doesn't already have its own — see `Self::context`'s docs.
        // Modules first, while still the concrete type; already-boxed tasks
        // (added via `.task()`) go through the trait method below, since a
        // `Box<dyn ParallelPipelineTask>` can't be unwrapped back to its
        // concrete fields.
        if let Some(shared) = &self.context {
            for module in &mut self.pending_modules {
                module.adopt_shared_context(shared);
            }
        }

        // Box pending modules into the task list.
        let mut tasks = self.tasks;
        for module in self.pending_modules {
            tasks.push(Box::new(module));
        }
        if let Some(shared) = &self.context {
            for task in &mut tasks {
                task.adopt_shared_context(shared);
            }
        }

        let provenance_store = self.context.as_ref().map(|ctx| ctx.provenance_store());

        Ok(ParallelPipeline {
            workers: self.workers,
            channel_capacity: capacity,
            tasks,
            sinks: self.sinks,
            provenance_store,
        })
    }
}

impl Default for ParallelPipelineBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        artifact::Artifact,
        data::ForensicData,
        err::ForensicResult,
        pipeline::{
            context::ParseContext,
            finding::Finding,
            sinks::FindingCollector,
            sources::TriageSources,
            traits::TriageSink,
        },
        traits::forensic::{ArtifactParserFactory, ParserDescriptor, ParserRun},
        utils::testing::TestParserFactoryBuilder,
    };

    // -------------------------------------------------------------------
    // Mini mock parser
    // -------------------------------------------------------------------

    fn mock_parser_with_records(n: usize, host: &str) -> Arc<dyn ArtifactParserFactory> {
        Arc::new(
            TestParserFactoryBuilder::new("mock_parser")
                .description("mock")
                .version("0.1")
                .with_records(n, host, Artifact::Unknown)
                .build(),
        )
    }

    // -------------------------------------------------------------------
    // Counting sink (Send not required — runs on main thread only)
    // -------------------------------------------------------------------

    struct CountingSink {
        data_count: u64,
        finding_count: u64,
    }

    impl CountingSink {
        fn new() -> Self {
            Self {
                data_count: 0,
                finding_count: 0,
            }
        }
    }

    impl TriageSink for CountingSink {
        fn name(&self) -> &str {
            "counting_sink"
        }
        fn on_data(&mut self, _data: &ForensicData) -> ForensicResult<()> {
            self.data_count += 1;
            Ok(())
        }
        fn on_finding(&mut self, _f: &Finding) -> ForensicResult<()> {
            self.finding_count += 1;
            Ok(())
        }
    }

    fn empty_sources() -> TriageSources {
        TriageSources::builder().build()
    }

    // -------------------------------------------------------------------
    // Tests
    // -------------------------------------------------------------------

    #[test]
    fn two_tasks_run_and_both_reach_sink() {
        let task_a = StandardParallelTaskBuilder::new("task_a")
            .parser(mock_parser_with_records(5, "host-a"))
            .sources(empty_sources)
            .build()
            .unwrap();

        let task_b = StandardParallelTaskBuilder::new("task_b")
            .parser(mock_parser_with_records(3, "host-b"))
            .sources(empty_sources)
            .build()
            .unwrap();

        let mut pipeline = ParallelPipeline::builder()
            .workers(2)
            .task(Box::new(task_a))
            .task(Box::new(task_b))
            .sink(Box::new(CountingSink::new()))
            .build()
            .unwrap();

        let result = pipeline.run().unwrap();

        assert_eq!(result.items_processed, 8);
        assert!(result.tasks_run.contains(&"task_a".to_string()));
        assert!(result.tasks_run.contains(&"task_b".to_string()));
        assert_eq!(result.task_stats["task_a"].items_processed, 5);
        assert_eq!(result.task_stats["task_b"].items_processed, 3);
        assert!(result.errors.is_empty());
    }

    #[test]
    fn work_queue_exhausts_all_tasks() {
        // 4 tasks but only 2 workers — each worker must pick up 2 tasks.
        let tasks: Vec<Box<dyn ParallelPipelineTask>> = (0..4)
            .map(|i| -> Box<dyn ParallelPipelineTask> {
                Box::new(
                    StandardParallelTaskBuilder::new(format!("task_{}", i))
                        .parser(mock_parser_with_records(2, "h"))
                        .sources(empty_sources)
                        .build()
                        .unwrap(),
                )
            })
            .collect();

        let mut builder = ParallelPipeline::builder()
            .workers(2)
            .sink(Box::new(CountingSink::new()));
        for t in tasks {
            builder = builder.task(t);
        }
        let mut pipeline = builder.build().unwrap();
        let result = pipeline.run().unwrap();

        assert_eq!(result.items_processed, 8); // 4 tasks × 2 records
        assert_eq!(result.tasks_run.len(), 4);
    }

    /// A parser factory whose `open()` always fails. `push_mode` selects
    /// whether the failure is reported synchronously by `open()` itself, or
    /// (when `true`) from inside a `ParserRun::Push` closure — exercising
    /// [`RecordProcessor::parser_error`](crate::pipeline::processor::RecordProcessor).
    struct FailParser {
        descriptor: ParserDescriptor,
        push_mode: bool,
    }
    impl ArtifactParserFactory for FailParser {
        fn descriptor(&self) -> &ParserDescriptor {
            &self.descriptor
        }
        fn open(&self, _ctx: &ParseContext<'_>) -> ForensicResult<ParserRun> {
            if self.push_mode {
                Ok(ParserRun::push(|_out| {
                    Err(ForensicError::missing_data(
                        "test",
                        CompactString::const_new("intentional failure"),
                    ))
                }))
            } else {
                Err(ForensicError::missing_data(
                    "test",
                    CompactString::const_new("intentional failure"),
                ))
            }
        }
    }

    #[test]
    fn task_error_does_not_block_other_tasks() {
        let failing_task = StandardParallelTaskBuilder::new("failing")
            .parser(Arc::new(FailParser {
                descriptor: ParserDescriptor::new("fail_parser", "fail_parser", "always fails", "0.1"),
                push_mode: false,
            }))
            .sources(empty_sources)
            .build()
            .unwrap();

        let good_task = StandardParallelTaskBuilder::new("good")
            .parser(mock_parser_with_records(4, "h"))
            .sources(empty_sources)
            .build()
            .unwrap();

        let mut pipeline = ParallelPipeline::builder()
            .workers(2)
            .task(Box::new(failing_task))
            .task(Box::new(good_task))
            .sink(Box::new(FindingCollector::new()))
            .build()
            .unwrap();

        let result = pipeline.run().unwrap();

        // The good task's records must all arrive.
        assert_eq!(result.items_processed, 4);
        // The failing task produces an error.
        assert!(!result.errors.is_empty());
        // Both tasks still complete (TaskDone is sent even after init failure).
        assert_eq!(result.tasks_run.len(), 2);
    }

    #[test]
    fn push_mode_parser_error_is_reported_like_a_pull_error() {
        // Same failure, but surfaced from inside a `ParserRun::Push` closure
        // instead of `open()` itself — exercises `RecordProcessor::parser_error`.
        let failing_task = StandardParallelTaskBuilder::new("failing_push")
            .parser(Arc::new(FailParser {
                descriptor: ParserDescriptor::new("fail_parser", "fail_parser", "always fails", "0.1"),
                push_mode: true,
            }))
            .sources(empty_sources)
            .build()
            .unwrap();

        let mut pipeline = ParallelPipeline::builder()
            .workers(1)
            .task(Box::new(failing_task))
            .sink(Box::new(FindingCollector::new()))
            .build()
            .unwrap();

        let result = pipeline.run().unwrap();

        assert_eq!(result.items_processed, 0);
        assert!(!result.errors.is_empty());
        assert_eq!(result.tasks_run, vec!["failing_push"]);
    }

    #[test]
    fn pre_cancelled_pipeline_skips_builtin_task_work() {
        let task = StandardParallelTaskBuilder::new("cancelled")
            .parser(mock_parser_with_records(4, "h"))
            .sources(empty_sources)
            .build()
            .unwrap();
        let mut pipeline = ParallelPipeline::builder()
            .workers(1)
            .task(Box::new(task))
            .sink(Box::new(CountingSink::new()))
            .build()
            .unwrap();
        let cancellation = CancellationToken::new();
        cancellation.cancel();

        let result = pipeline.run_with_cancellation(cancellation).unwrap();

        assert_eq!(result.items_processed, 0);
        assert_eq!(result.task_stats["cancelled"].items_processed, 0);
        assert_eq!(result.tasks_run, vec!["cancelled"]);
    }

    #[test]
    fn in_flight_cancellation_stops_after_current_record() {
        struct CancellingAnalyzer {
            cancellation: CancellationToken,
        }

        impl Analyzer for CancellingAnalyzer {
            fn name(&self) -> &str {
                "cancelling_analyzer"
            }

            fn analyze(
                &mut self,
                _data: &ForensicData,
                _context: &TriageContext,
                _out: &mut Vec<Finding>,
            ) -> ForensicResult<()> {
                self.cancellation.cancel();
                Ok(())
            }
        }

        let cancellation = CancellationToken::new();
        let task = StandardParallelTaskBuilder::new("cancelled_in_flight")
            .parser(mock_parser_with_records(4, "h"))
            .analyzer(Box::new(CancellingAnalyzer {
                cancellation: cancellation.clone(),
            }))
            .sources(empty_sources)
            .build()
            .unwrap();
        let mut pipeline = ParallelPipeline::builder()
            .workers(1)
            .task(Box::new(task))
            .sink(Box::new(CountingSink::new()))
            .build()
            .unwrap();

        let result = pipeline.run_with_cancellation(cancellation).unwrap();

        assert_eq!(result.items_processed, 1);
        assert_eq!(result.task_stats["cancelled_in_flight"].items_processed, 1);
    }

    #[test]
    fn panicking_task_is_reported_without_blocking_other_tasks() {
        struct PanicTask;

        impl ParallelPipelineTask for PanicTask {
            fn name(&self) -> &str {
                "panic"
            }

            fn run(self: Box<Self>, _tx: SyncSender<PipelineEvent>) {
                panic!("intentional test panic");
            }
        }

        let healthy_task = StandardParallelTaskBuilder::new("healthy")
            .parser(mock_parser_with_records(2, "h"))
            .sources(empty_sources)
            .build()
            .unwrap();
        let mut pipeline = ParallelPipeline::builder()
            .workers(2)
            .task(Box::new(PanicTask))
            .task(Box::new(healthy_task))
            .sink(Box::new(CountingSink::new()))
            .build()
            .unwrap();

        let result = pipeline.run().unwrap();

        assert_eq!(result.items_processed, 2);
        assert!(result.tasks_run.contains(&"panic".to_string()));
        assert!(result.errors.iter().any(|(task, _)| task == "panic"));
    }

    // -------------------------------------------------------------------
    // AnalysisModule tests
    // -------------------------------------------------------------------

    // A trivially-matching analyzer that collects all records.
    struct CountingAnalyzer {
        count: u64,
        // Which artifact types to declare (empty = accept all).
        artifacts: Vec<crate::artifact::Artifact>,
    }

    impl CountingAnalyzer {
        fn new() -> Self {
            Self {
                count: 0,
                artifacts: vec![],
            }
        }
        fn with_artifact(artifact: crate::artifact::Artifact) -> Self {
            Self {
                count: 0,
                artifacts: vec![artifact],
            }
        }
    }

    impl crate::pipeline::traits::Analyzer for CountingAnalyzer {
        fn name(&self) -> &str {
            "counting_analyzer"
        }
        fn supported_artifacts(&self) -> Vec<crate::artifact::Artifact> {
            self.artifacts.clone()
        }
        fn analyze(
            &mut self,
            _data: &ForensicData,
            _context: &TriageContext,
            _out: &mut Vec<Finding>,
        ) -> ForensicResult<()> {
            self.count += 1;
            Ok(())
        }
    }

    // A mock parser that advertises a specific artifact type.
    fn typed_mock_parser(
        n: usize,
        host: &str,
        artifact: crate::artifact::Artifact,
    ) -> Arc<dyn ArtifactParserFactory> {
        Arc::new(
            TestParserFactoryBuilder::new("typed_mock_parser")
                .description("typed mock")
                .version("0.1")
                .with_records(n, host, artifact.clone())
                .with_artifact(artifact)
                .build(),
        )
    }

    #[test]
    fn analysis_module_explicit_parser_skips_auto_match() {
        // Module has an explicit parser → the pool parser below must be ignored.
        let module = AnalysisModuleBuilder::new("mod")
            .analyzer(Box::new(CountingAnalyzer::new()))
            .parser(mock_parser_with_records(4, "h")) // explicit
            .sources(empty_sources)
            .build()
            .unwrap();

        let mut pipeline = ParallelPipeline::builder()
            .workers(1)
            .module(module)
            .parser(mock_parser_with_records(99, "h")) // pool — must not be used
            .sink(Box::new(CountingSink::new()))
            .build()
            .unwrap();

        let result = pipeline.run().unwrap();

        // Only the explicit parser's records arrive, not the pool's 99.
        assert_eq!(result.items_processed, 4);
    }

    #[test]
    fn analysis_module_auto_matches_parser_by_artifact() {
        // Analyzer declares Artifact::Unknown; the pool parser also declares
        // Artifact::Unknown → should be auto-matched.
        let module = AnalysisModuleBuilder::new("mod")
            .analyzer(Box::new(CountingAnalyzer::with_artifact(Artifact::Unknown)))
            .sources(empty_sources)
            .build()
            .unwrap();

        let mut pipeline = ParallelPipeline::builder()
            .workers(1)
            .module(module)
            .parser(typed_mock_parser(5, "h", Artifact::Unknown))
            .sink(Box::new(CountingSink::new()))
            .build()
            .unwrap();

        let result = pipeline.run().unwrap();
        assert_eq!(result.items_processed, 5);
    }

    #[test]
    fn analysis_module_auto_match_skips_non_overlapping_factory() {
        use crate::artifact::{RegistryArtifacts, WindowsArtifacts};

        // Analyzer only cares about Registry artifacts.
        let registry_artifact = crate::artifact::Artifact::Windows(WindowsArtifacts::Registry(
            RegistryArtifacts::AutoRuns,
        ));
        let module = AnalysisModuleBuilder::new("mod")
            .analyzer(Box::new(CountingAnalyzer::with_artifact(
                registry_artifact.clone(),
            )))
            .sources(empty_sources)
            .build()
            .unwrap();

        // One pool parser declares the registry artifact, one declares
        // Unknown — only the registry parser should be injected.
        let mut pipeline = ParallelPipeline::builder()
            .workers(1)
            .module(module)
            .parser(typed_mock_parser(3, "h", registry_artifact))
            .parser(typed_mock_parser(99, "h", Artifact::Unknown))
            .sink(Box::new(CountingSink::new()))
            .build()
            .unwrap();

        let result = pipeline.run().unwrap();
        // Only the 3 records from the registry parser should arrive.
        assert_eq!(result.items_processed, 3);
    }

    #[test]
    fn descriptor_based_matching_never_calls_open_on_unmatched_parsers() {
        use std::sync::atomic::{AtomicU64, Ordering};

        struct CountingOpenParser {
            descriptor: ParserDescriptor,
            opens: Arc<AtomicU64>,
        }
        impl ArtifactParserFactory for CountingOpenParser {
            fn descriptor(&self) -> &ParserDescriptor {
                &self.descriptor
            }
            fn open(&self, _ctx: &ParseContext<'_>) -> ForensicResult<ParserRun> {
                self.opens.fetch_add(1, Ordering::SeqCst);
                Ok(ParserRun::pull(std::iter::empty()))
            }
        }

        let opens = Arc::new(AtomicU64::new(0));
        let non_matching: Arc<dyn ArtifactParserFactory> = Arc::new(CountingOpenParser {
            descriptor: ParserDescriptor::new("non_matching", "non_matching", "d", "0.1")
                .with_artifacts(vec![Artifact::Windows(
                    crate::artifact::WindowsArtifacts::Registry(
                        crate::artifact::RegistryArtifacts::AutoRuns,
                    ),
                )]),
            opens: Arc::clone(&opens),
        });

        let module = AnalysisModuleBuilder::new("mod")
            .analyzer(Box::new(CountingAnalyzer::with_artifact(Artifact::Unknown)))
            .sources(empty_sources)
            .build()
            .unwrap();

        let mut pipeline = ParallelPipeline::builder()
            .workers(1)
            .module(module)
            .parser(non_matching)
            .sink(Box::new(CountingSink::new()))
            .build()
            .unwrap();

        let result = pipeline.run().unwrap();

        // Matching is descriptor-based — a non-matching parser is never
        // even asked to open, let alone parse.
        assert_eq!(opens.load(Ordering::SeqCst), 0);
        assert_eq!(result.items_processed, 0);
    }

    #[test]
    fn one_arc_parser_serves_two_modules() {
        use std::sync::atomic::{AtomicU64, Ordering};

        // A single factory instance, shared into two modules via `Arc::clone`
        // rather than being reconstructed per module (there is no
        // reconstruction path left to fall back to — the old per-module
        // `ParserFactory` closure is gone).
        struct CountingOpenParser {
            descriptor: ParserDescriptor,
            opens: Arc<AtomicU64>,
        }
        impl ArtifactParserFactory for CountingOpenParser {
            fn descriptor(&self) -> &ParserDescriptor {
                &self.descriptor
            }
            fn open(&self, _ctx: &ParseContext<'_>) -> ForensicResult<ParserRun> {
                self.opens.fetch_add(1, Ordering::SeqCst);
                Ok(ParserRun::pull((0..2).map(|_| {
                    Ok(ForensicData::new("h", Artifact::Unknown, crate::utils::testing::test_provenance_id()))
                })))
            }
        }

        let opens = Arc::new(AtomicU64::new(0));
        let shared: Arc<dyn ArtifactParserFactory> = Arc::new(CountingOpenParser {
            descriptor: ParserDescriptor::new("shared", "shared", "d", "0.1")
                .with_artifacts(vec![Artifact::Unknown]),
            opens: Arc::clone(&opens),
        });

        let module_a = AnalysisModuleBuilder::new("mod_a")
            .analyzer(Box::new(CountingAnalyzer::with_artifact(Artifact::Unknown)))
            .sources(empty_sources)
            .build()
            .unwrap();
        let module_b = AnalysisModuleBuilder::new("mod_b")
            .analyzer(Box::new(CountingAnalyzer::with_artifact(Artifact::Unknown)))
            .sources(empty_sources)
            .build()
            .unwrap();

        let mut pipeline = ParallelPipeline::builder()
            .workers(2)
            .module(module_a)
            .module(module_b)
            .parser(shared)
            .sink(Box::new(CountingSink::new()))
            .build()
            .unwrap();

        let result = pipeline.run().unwrap();

        // Auto-matched into both modules from the same registered `Arc`, so
        // `open()` runs once per module — 2 calls, 4 records total (2 per
        // module) — never a factory reconstructed once per module.
        assert_eq!(opens.load(Ordering::SeqCst), 2);
        assert_eq!(result.items_processed, 4);
    }

    // -------------------------------------------------------------------
    // C-8: shared, investigation-scoped ProvenanceStore
    // -------------------------------------------------------------------

    /// A parser that mints its records' provenance from the run's *own*
    /// `ParseContext`-provided store — unlike `TestParserFactoryBuilder`,
    /// whose `with_records` bakes in a throwaway store at construction
    /// time and so can never prove cross-task store sharing.
    struct MintingParser {
        descriptor: ParserDescriptor,
        host: &'static str,
        count: usize,
    }
    impl ArtifactParserFactory for MintingParser {
        fn descriptor(&self) -> &ParserDescriptor {
            &self.descriptor
        }
        fn open(&self, ctx: &ParseContext<'_>) -> ForensicResult<ParserRun> {
            let host = self.host;
            let mut records = Vec::with_capacity(self.count);
            for i in 0..self.count {
                let source = ctx.register_source(crate::provenance::SourceKey::Synthetic(
                    format!("{host}-{i}"),
                ));
                let id = source.mint(
                    crate::provenance::Acquisition::LiveApi,
                    crate::provenance::Recovery::Allocated,
                );
                records.push(Ok(ForensicData::new(host, Artifact::Unknown, id)));
            }
            Ok(ParserRun::pull(records.into_iter()))
        }
    }

    fn minting_task(name: &str, host: &'static str, count: usize) -> StandardParallelTask {
        StandardParallelTaskBuilder::new(name)
            .parser(Arc::new(MintingParser {
                descriptor: ParserDescriptor::new(name.to_string(), name.to_string(), "mints provenance", "0.1"),
                host,
                count,
            }))
            .sources(empty_sources)
            .build()
            .unwrap()
    }

    /// A sink that retains every record it sees, for post-run provenance
    /// inspection. `Arc<Mutex<..>>`-backed so a clone of the collected
    /// `Vec` stays reachable after `run()` moves the sink into the
    /// pipeline.
    #[derive(Clone)]
    struct CollectingSink {
        collected: Arc<Mutex<Vec<ForensicData>>>,
    }
    impl CollectingSink {
        fn new() -> Self {
            Self {
                collected: Arc::new(Mutex::new(Vec::new())),
            }
        }
    }
    impl TriageSink for CollectingSink {
        fn name(&self) -> &str {
            "collecting_sink"
        }
        fn on_data(&mut self, data: &ForensicData) -> ForensicResult<()> {
            self.collected.lock().unwrap().push(data.clone());
            Ok(())
        }
        fn on_finding(&mut self, _f: &Finding) -> ForensicResult<()> {
            Ok(())
        }
    }

    #[test]
    fn without_a_shared_context_the_result_carries_no_provenance_store() {
        let task = minting_task("solo", "host-a", 2);
        let mut pipeline = ParallelPipeline::builder()
            .workers(1)
            .task(Box::new(task))
            .sink(Box::new(CountingSink::new()))
            .build()
            .unwrap();
        let result = pipeline.run().unwrap();
        assert!(result.provenance_store.is_none());
    }

    #[test]
    fn records_from_both_tasks_resolve_against_the_one_shared_store() {
        // Two tasks, each on its own worker thread, minting from what would
        // — without the fix — be two independent stores. With one shared
        // `TriageContext` set on the pipeline builder, both tasks' records
        // must resolve against the *one* store the pipeline/result hand
        // back, proving the store is genuinely shared across threads, not
        // just present.
        let shared_context = TriageContext::new("WORKSTATION01", "case-42");
        // Keep an independent handle to the same underlying store, exactly
        // as a caller would: grab it before handing the context into the
        // builder (`TriageContext::clone` shares the store, so this handle
        // stays valid regardless of what the builder does with its clone).
        let store_handle = shared_context.provenance_store();

        let task_a = minting_task("mint_a", "host-a", 3);
        let task_b = minting_task("mint_b", "host-b", 2);
        let sink = CollectingSink::new();
        let collected = Arc::clone(&sink.collected);

        let mut pipeline = ParallelPipeline::builder()
            .workers(2)
            .context(shared_context)
            .task(Box::new(task_a))
            .task(Box::new(task_b))
            .sink(Box::new(sink))
            .build()
            .unwrap();

        assert!(
            pipeline.provenance_store().is_some(),
            "the shared store must be visible before run() completes, not only after"
        );

        let result = pipeline.run().unwrap();
        assert_eq!(result.items_processed, 5);
        let result_store = result
            .provenance_store
            .expect("a shared context was configured, so a store must come back");

        let records = collected.lock().unwrap();
        assert_eq!(records.len(), 5);
        // Records minted on two different worker threads all resolve
        // against both the pre-run handle and the post-run result handle —
        // the same underlying store, reached three different ways.
        for record in records.iter() {
            assert!(
                store_handle.get(record.provenance()).is_some(),
                "record did not resolve against the pre-run store handle"
            );
            assert!(
                result_store.get(record.provenance()).is_some(),
                "record did not resolve against the post-run result store"
            );
        }
    }
}
