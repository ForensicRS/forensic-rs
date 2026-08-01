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
//! to each module by intersecting `supported_artifacts()` sets:
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
//!     .parser_factory(Box::new(|| Box::new(EvtxParser::new())))
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
//! | Parser / Enricher / Analyzer inside a task | `Send + 'static` |
//! | [`TriageSources`] | **none** – created on the worker thread via the sources factory |
//! | [`TriageSink`] | **none** – only ever called from the main thread |

use std::collections::{BTreeMap, VecDeque};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::mpsc::{self, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread;

use crate::{
    bridge::CancellationToken,
    data::ForensicData,
    err::{ForensicError, ForensicResult},
    scow::SCow,
    traits::forensic::ArtifactParser,
};

use super::{
    context::TriageContext,
    finding::Finding,
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
    parser: Box<dyn ArtifactParser + Send + 'static>,
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
        let mut sources = (self.sources_factory)();
        let analyzer_artifacts: Vec<Vec<crate::artifact::Artifact>> = self
            .analyzers
            .iter()
            .map(|analyzer| analyzer.supported_artifacts())
            .collect();

        let mut items_processed: u64 = 0;
        let mut findings_count: u64 = 0;

        // Obtain the record iterator from the parser.
        let iter = match self.parser.parse(&mut sources) {
            Ok(iter) => iter,
            Err(e) => {
                let _ = tx.send(PipelineEvent::TaskError {
                    task: task_name.clone(),
                    error: e,
                });
                let _ = tx.send(PipelineEvent::TaskDone {
                    task: task_name,
                    items_processed: 0,
                    findings_count: 0,
                });
                return;
            }
        };

        'records: for item_result in iter {
            if cancellation.is_cancelled() {
                break 'records;
            }

            let mut data = match item_result {
                Ok(d) => d,
                Err(e) => {
                    let _ = tx.send(PipelineEvent::TaskError {
                        task: task_name.clone(),
                        error: e,
                    });
                    match self.error_action {
                        ErrorAction::Continue => continue 'records,
                        ErrorAction::Halt => break 'records,
                    }
                }
            };

            // Enrich the record in-place.
            for enricher in &mut self.enrichers {
                if cancellation.is_cancelled() {
                    break 'records;
                }
                if let Err(e) = enricher.enrich(&mut data, &mut context) {
                    let _ = tx.send(PipelineEvent::TaskError {
                        task: task_name.clone(),
                        error: e,
                    });
                    if self.error_action == ErrorAction::Halt {
                        break 'records;
                    }
                }
            }

            // Run matching analyzers.
            let artifact = data.artifact().clone();
            for (analyzer, supported) in self.analyzers.iter_mut().zip(&analyzer_artifacts) {
                if cancellation.is_cancelled() {
                    break 'records;
                }
                if !supported.is_empty() && !supported.contains(&artifact) {
                    continue;
                }
                match analyzer.analyze(&data) {
                    Ok(new_findings) => {
                        for f in new_findings {
                            findings_count += 1;
                            // Block if channel is full — provides backpressure.
                            if tx.send(PipelineEvent::Finding(f)).is_err() {
                                return; // receiver gone
                            }
                        }
                    }
                    Err(e) => {
                        let _ = tx.send(PipelineEvent::TaskError {
                            task: task_name.clone(),
                            error: e,
                        });
                        if self.error_action == ErrorAction::Halt {
                            break 'records;
                        }
                    }
                }
            }

            // Send the processed record to the main thread.
            if tx.send(PipelineEvent::Data(data)).is_err() {
                return; // receiver gone — stop silently
            }
            items_processed += 1;
        }

        // Finalize analyzers (aggregate / cross-record findings).
        for analyzer in &mut self.analyzers {
            match analyzer.finalize() {
                Ok(new_findings) => {
                    for f in new_findings {
                        findings_count += 1;
                        if tx.send(PipelineEvent::Finding(f)).is_err() {
                            return;
                        }
                    }
                }
                Err(e) => {
                    let _ = tx.send(PipelineEvent::TaskError {
                        task: task_name.clone(),
                        error: e,
                    });
                }
            }
        }

        let _ = tx.send(PipelineEvent::TaskDone {
            task: task_name,
            items_processed,
            findings_count,
        });
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
///     .parser(Box::new(MftParser::new()))
///     .analyzer(Box::new(MftGapAnalyzer::new()))
///     .sources(|| TriageSources::builder()
///         .vfs(Box::new(ZipVirtualFS::open("triage.zip").unwrap()))
///         .build())
///     .context(TriageContext::new("WORKSTATION01", "acme"))
///     .build()?;
/// ```
pub struct StandardParallelTaskBuilder {
    name: String,
    parser: Option<Box<dyn ArtifactParser + Send + 'static>>,
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
    pub fn parser(mut self, parser: Box<dyn ArtifactParser + Send + 'static>) -> Self {
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
                    SCow::Borrowed("StandardParallelTaskBuilder: call .parser() before .build()"),
                ))
            }
        };
        let sources_factory = match self.sources_factory {
            Some(f) => f,
            None => {
                return Err(ForensicError::missing_data(
                    "sources_factory",
                    SCow::Borrowed("StandardParallelTaskBuilder: call .sources() before .build()"),
                ))
            }
        };
        Ok(StandardParallelTask {
            name: self.name,
            parser,
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

/// A factory that creates a new parser instance on demand.
///
/// Used by [`ParallelPipelineBuilder::parser_factory`] to auto-match parsers
/// to [`AnalysisModule`]s at pipeline build time.  The factory is called once
/// per module that needs that parser type, so the same factory can serve
/// multiple modules without cloning the parser itself. When construction is
/// expensive, prefer [`ParallelPipelineBuilder::parser_factory_with_artifacts`]
/// so unmatched modules do not construct a temporary parser for metadata.
///
/// ```rust,ignore
/// builder.parser_factory(Box::new(|| Box::new(MftParser::new())))
/// ```
pub type ParserFactory = Box<dyn Fn() -> Box<dyn ArtifactParser + Send + 'static> + Send + Sync>;

struct RegisteredParserFactory {
    artifacts: Option<Vec<crate::artifact::Artifact>>,
    create: ParserFactory,
}

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
///   [`ParallelPipelineBuilder::parser_factory`].  At `build()` time the
///   pipeline intersects the analyzer's supported artifacts with each
///   factory's output and injects matching parsers.
///
/// All parsers share the same [`TriageSources`] instance (created once per
/// task on the worker thread).  The analyzer's `finalize()` is called once
/// after **all** parsers finish, enabling cross-parser aggregate detection.
///
/// Build with [`AnalysisModuleBuilder`].
pub struct AnalysisModule {
    name: String,
    analyzer: Box<dyn Analyzer + Send + 'static>,
    parsers: Vec<Box<dyn ArtifactParser + Send + 'static>>,
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
        let mut sources = (self.sources_factory)();
        let analyzer_artifacts = self.analyzer.supported_artifacts();

        let mut total_items: u64 = 0;
        let mut total_findings: u64 = 0;

        'parsers: for parser in &mut self.parsers {
            if cancellation.is_cancelled() {
                break 'parsers;
            }
            if !parser.can_parse(&sources) {
                continue 'parsers;
            }

            let iter = match parser.parse(&mut sources) {
                Ok(iter) => iter,
                Err(e) => {
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

            'records: for item_result in iter {
                if cancellation.is_cancelled() {
                    break 'parsers;
                }

                let mut data = match item_result {
                    Ok(d) => d,
                    Err(e) => {
                        let _ = tx.send(PipelineEvent::TaskError {
                            task: task_name.clone(),
                            error: e,
                        });
                        match self.error_action {
                            ErrorAction::Continue => continue 'records,
                            ErrorAction::Halt => break 'parsers,
                        }
                    }
                };

                for enricher in &mut self.enrichers {
                    if cancellation.is_cancelled() {
                        break 'parsers;
                    }
                    if let Err(e) = enricher.enrich(&mut data, &mut context) {
                        let _ = tx.send(PipelineEvent::TaskError {
                            task: task_name.clone(),
                            error: e,
                        });
                        if self.error_action == ErrorAction::Halt {
                            break 'parsers;
                        }
                    }
                }

                let artifact = data.artifact().clone();
                if cancellation.is_cancelled() {
                    break 'parsers;
                }
                if analyzer_artifacts.is_empty() || analyzer_artifacts.contains(&artifact) {
                    match self.analyzer.analyze(&data) {
                        Ok(new_findings) => {
                            for f in new_findings {
                                total_findings += 1;
                                if tx.send(PipelineEvent::Finding(f)).is_err() {
                                    return;
                                }
                            }
                        }
                        Err(e) => {
                            let _ = tx.send(PipelineEvent::TaskError {
                                task: task_name.clone(),
                                error: e,
                            });
                            if self.error_action == ErrorAction::Halt {
                                break 'parsers;
                            }
                        }
                    }
                }

                if tx.send(PipelineEvent::Data(data)).is_err() {
                    return;
                }
                total_items += 1;
            }
        }

        // Finalize once after all parsers — enables cross-parser analysis.
        match self.analyzer.finalize() {
            Ok(findings) => {
                for f in findings {
                    total_findings += 1;
                    if tx.send(PipelineEvent::Finding(f)).is_err() {
                        return;
                    }
                }
            }
            Err(e) => {
                let _ = tx.send(PipelineEvent::TaskError {
                    task: task_name.clone(),
                    error: e,
                });
            }
        }

        let _ = tx.send(PipelineEvent::TaskDone {
            task: task_name,
            items_processed: total_items,
            findings_count: total_findings,
        });
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
///     .parser(Box::new(MftParser::new()))           // explicit — overrides auto-match
///     .sources(|| TriageSources::builder()
///         .vfs(Box::new(ZipVfs::open("triage.zip")?))
///         .build())
///     .context(TriageContext::new("WORKSTATION01", "acme"))
///     .build()?;
/// ```
pub struct AnalysisModuleBuilder {
    name: String,
    analyzer: Option<Box<dyn Analyzer + Send + 'static>>,
    parsers: Vec<Box<dyn ArtifactParser + Send + 'static>>,
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
    pub fn parser(mut self, parser: Box<dyn ArtifactParser + Send + 'static>) -> Self {
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
    /// [`ParallelPipelineBuilder::build`] if parser factories are registered.
    pub fn build(self) -> ForensicResult<AnalysisModule> {
        let analyzer = match self.analyzer {
            Some(a) => a,
            None => {
                return Err(ForensicError::missing_data(
                    "analyzer",
                    SCow::Borrowed("AnalysisModuleBuilder: call .analyzer() before .build()"),
                ))
            }
        };
        let sources_factory = match self.sources_factory {
            Some(f) => f,
            None => {
                return Err(ForensicError::missing_data(
                    "sources_factory",
                    SCow::Borrowed("AnalysisModuleBuilder: call .sources() before .build()"),
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
        let mut result = ParallelPipelineResult::default();

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
    parser_factories: Vec<RegisteredParserFactory>,
    sinks: Vec<Box<dyn TriageSink>>,
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
            parser_factories: Vec::new(),
            sinks: Vec::new(),
        }
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
    /// is performed at [`build`](Self::build) time using the factories
    /// registered via [`parser_factory`](Self::parser_factory).
    pub fn module(mut self, module: AnalysisModule) -> Self {
        self.pending_modules.push(module);
        self
    }

    /// Register a parser factory for auto-matching.
    ///
    /// At [`build`](Self::build) time the pipeline intersects each factory's
    /// output artifact types with each [`AnalysisModule`]'s
    /// [`Analyzer::supported_artifacts`].  When the sets overlap the factory
    /// is called and the resulting parser is injected into that module.
    ///
    /// This compatibility API constructs a temporary parser to inspect its
    /// metadata. Prefer [`Self::parser_factory_with_artifacts`] when supported
    /// artifact metadata is available without parser construction.
    ///
    /// A factory registered here is **never** added to modules that already
    /// have explicit parsers — explicit always wins.
    ///
    /// If an analyzer's `supported_artifacts()` is empty (the "accept all"
    /// default) it receives parsers from **every** registered factory.
    pub fn parser_factory(mut self, factory: ParserFactory) -> Self {
        self.parser_factories.push(RegisteredParserFactory {
            artifacts: None,
            create: factory,
        });
        self
    }

    /// Register a parser factory with its supported artifact metadata.
    ///
    /// Unlike [`Self::parser_factory`], this avoids constructing parsers that
    /// do not match an analysis module. Use it when parser construction opens
    /// files, loads indexes, or otherwise performs meaningful work.
    pub fn parser_factory_with_artifacts(
        mut self,
        artifacts: Vec<crate::artifact::Artifact>,
        factory: ParserFactory,
    ) -> Self {
        self.parser_factories.push(RegisteredParserFactory {
            artifacts: Some(artifacts),
            create: factory,
        });
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

        // Auto-match: inject parsers into modules that have none.
        for module in &mut self.pending_modules {
            if module.parsers.is_empty() && !self.parser_factories.is_empty() {
                let analyzer_artifacts = module.analyzer.supported_artifacts();
                for factory in &self.parser_factories {
                    if let Some(parser_artifacts) = &factory.artifacts {
                        let matches = analyzer_artifacts.is_empty()
                            || parser_artifacts.is_empty()
                            || analyzer_artifacts
                                .iter()
                                .any(|a| parser_artifacts.contains(a));
                        if matches {
                            module.parsers.push((factory.create)());
                        }
                    } else {
                        // Preserve the legacy factory behavior: inspect the
                        // constructed parser and retain that same instance.
                        let parser = (factory.create)();
                        let parser_artifacts = parser.supported_artifacts();
                        let matches = analyzer_artifacts.is_empty()
                            || parser_artifacts.is_empty()
                            || analyzer_artifacts
                                .iter()
                                .any(|a| parser_artifacts.contains(a));
                        if matches {
                            module.parsers.push(parser);
                        }
                    }
                }
            }
        }

        // Box pending modules into the task list.
        let mut tasks = self.tasks;
        for module in self.pending_modules {
            tasks.push(Box::new(module));
        }

        Ok(ParallelPipeline {
            workers: self.workers,
            channel_capacity: capacity,
            tasks,
            sinks: self.sinks,
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
            finding::Finding, sinks::FindingCollector, sources::TriageSources, traits::TriageSink,
        },
    };

    // -------------------------------------------------------------------
    // Mini mock parser
    // -------------------------------------------------------------------

    struct MockParser {
        records: Vec<ForensicData>,
    }

    impl MockParser {
        fn with_records(n: usize, host: &str) -> Self {
            let records = (0..n)
                .map(|i| {
                    let mut d = ForensicData::new(host, Artifact::Unknown);
                    d.add_field("index", crate::field::Field::U64(i as u64));
                    d
                })
                .collect();
            Self { records }
        }
    }

    impl crate::traits::forensic::ArtifactParser for MockParser {
        fn name(&self) -> &str {
            "mock_parser"
        }
        fn description(&self) -> &str {
            "mock"
        }
        fn version(&self) -> &str {
            "0.1"
        }
        fn supported_artifacts(&self) -> Vec<Artifact> {
            vec![]
        }

        fn can_parse(&self, _sources: &TriageSources) -> bool {
            true
        }

        fn parse<'a>(
            &'a mut self,
            _sources: &'a mut TriageSources,
        ) -> ForensicResult<Box<dyn Iterator<Item = ForensicResult<ForensicData>> + 'a>> {
            let iter = self.records.drain(..).map(Ok);
            Ok(Box::new(iter.collect::<Vec<_>>().into_iter()))
        }
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
            .parser(Box::new(MockParser::with_records(5, "host-a")))
            .sources(empty_sources)
            .build()
            .unwrap();

        let task_b = StandardParallelTaskBuilder::new("task_b")
            .parser(Box::new(MockParser::with_records(3, "host-b")))
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
                        .parser(Box::new(MockParser::with_records(2, "h")))
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

    #[test]
    fn task_error_does_not_block_other_tasks() {
        // A parser that immediately fails.
        struct FailParser;
        impl crate::traits::forensic::ArtifactParser for FailParser {
            fn name(&self) -> &str {
                "fail_parser"
            }
            fn description(&self) -> &str {
                "always fails"
            }
            fn version(&self) -> &str {
                "0.1"
            }
            fn supported_artifacts(&self) -> Vec<Artifact> {
                vec![]
            }
            fn can_parse(&self, _: &TriageSources) -> bool {
                true
            }
            fn parse<'a>(
                &'a mut self,
                _sources: &'a mut TriageSources,
            ) -> ForensicResult<Box<dyn Iterator<Item = ForensicResult<ForensicData>> + 'a>>
            {
                Err(ForensicError::missing_data(
                    "test",
                    SCow::Borrowed("intentional failure"),
                ))
            }
        }

        let failing_task = StandardParallelTaskBuilder::new("failing")
            .parser(Box::new(FailParser))
            .sources(empty_sources)
            .build()
            .unwrap();

        let good_task = StandardParallelTaskBuilder::new("good")
            .parser(Box::new(MockParser::with_records(4, "h")))
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
    fn pre_cancelled_pipeline_skips_builtin_task_work() {
        let task = StandardParallelTaskBuilder::new("cancelled")
            .parser(Box::new(MockParser::with_records(4, "h")))
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

            fn analyze(&mut self, _data: &ForensicData) -> ForensicResult<Vec<Finding>> {
                self.cancellation.cancel();
                Ok(Vec::new())
            }
        }

        let cancellation = CancellationToken::new();
        let task = StandardParallelTaskBuilder::new("cancelled_in_flight")
            .parser(Box::new(MockParser::with_records(4, "h")))
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
            .parser(Box::new(MockParser::with_records(2, "h")))
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
        fn analyze(&mut self, _data: &ForensicData) -> ForensicResult<Vec<Finding>> {
            self.count += 1;
            Ok(vec![])
        }
    }

    // A mock parser that advertises a specific artifact type.
    struct TypedMockParser {
        records: Vec<ForensicData>,
        artifact: crate::artifact::Artifact,
    }

    impl TypedMockParser {
        fn new(n: usize, host: &str, artifact: crate::artifact::Artifact) -> Self {
            let records = (0..n)
                .map(|i| {
                    let mut d = ForensicData::new(host, artifact.clone());
                    d.add_field("index", crate::field::Field::U64(i as u64));
                    d
                })
                .collect();
            Self { records, artifact }
        }
    }

    impl crate::traits::forensic::ArtifactParser for TypedMockParser {
        fn name(&self) -> &str {
            "typed_mock_parser"
        }
        fn description(&self) -> &str {
            "typed mock"
        }
        fn version(&self) -> &str {
            "0.1"
        }
        fn supported_artifacts(&self) -> Vec<crate::artifact::Artifact> {
            vec![self.artifact.clone()]
        }
        fn can_parse(&self, _: &TriageSources) -> bool {
            true
        }
        fn parse<'a>(
            &'a mut self,
            _sources: &'a mut TriageSources,
        ) -> ForensicResult<Box<dyn Iterator<Item = ForensicResult<ForensicData>> + 'a>> {
            let items: Vec<_> = self.records.drain(..).map(Ok).collect();
            Ok(Box::new(items.into_iter()))
        }
    }

    #[test]
    fn analysis_module_explicit_parser_skips_auto_match() {
        // Module has an explicit parser → factory should NOT be called.
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::sync::Arc;

        let factory_call_count = Arc::new(AtomicU64::new(0));
        let counter_clone = Arc::clone(&factory_call_count);

        let module = AnalysisModuleBuilder::new("mod")
            .analyzer(Box::new(CountingAnalyzer::new()))
            .parser(Box::new(MockParser::with_records(4, "h"))) // explicit
            .sources(empty_sources)
            .build()
            .unwrap();

        let mut pipeline = ParallelPipeline::builder()
            .workers(1)
            .module(module)
            .parser_factory(Box::new(move || {
                counter_clone.fetch_add(1, Ordering::SeqCst);
                Box::new(MockParser::with_records(0, "h"))
            }))
            .sink(Box::new(CountingSink::new()))
            .build()
            .unwrap();

        let result = pipeline.run().unwrap();

        assert_eq!(result.items_processed, 4);
        // Factory must not have been called because explicit parsers were provided.
        assert_eq!(factory_call_count.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn analysis_module_auto_matches_parser_by_artifact() {
        // Analyzer declares Artifact::Unknown; factory produces a parser that
        // also declares Artifact::Unknown → should be auto-matched.
        let module = AnalysisModuleBuilder::new("mod")
            .analyzer(Box::new(CountingAnalyzer::with_artifact(Artifact::Unknown)))
            .sources(empty_sources)
            .build()
            .unwrap();

        let mut pipeline = ParallelPipeline::builder()
            .workers(1)
            .module(module)
            .parser_factory(Box::new(|| {
                Box::new(TypedMockParser::new(5, "h", Artifact::Unknown))
            }))
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

        // One factory produces a registry parser, one produces Unknown — only
        // the registry parser should be injected.
        let mut pipeline = ParallelPipeline::builder()
            .workers(1)
            .module(module)
            .parser_factory(Box::new(move || {
                Box::new(TypedMockParser::new(3, "h", registry_artifact.clone()))
            }))
            .parser_factory(Box::new(|| {
                // Artifact::Unknown does NOT overlap with Registry::AutoRuns
                Box::new(TypedMockParser::new(99, "h", Artifact::Unknown))
            }))
            .sink(Box::new(CountingSink::new()))
            .build()
            .unwrap();

        let result = pipeline.run().unwrap();
        // Only the 3 records from the registry parser should arrive.
        assert_eq!(result.items_processed, 3);
    }

    #[test]
    fn metadata_aware_factory_is_not_constructed_when_unmatched() {
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::sync::Arc;

        let construction_count = Arc::new(AtomicU64::new(0));
        let counter = Arc::clone(&construction_count);
        let module = AnalysisModuleBuilder::new("mod")
            .analyzer(Box::new(CountingAnalyzer::with_artifact(Artifact::Unknown)))
            .sources(empty_sources)
            .build()
            .unwrap();

        let mut pipeline = ParallelPipeline::builder()
            .workers(1)
            .module(module)
            .parser_factory_with_artifacts(
                vec![Artifact::Windows(
                    crate::artifact::WindowsArtifacts::Registry(
                        crate::artifact::RegistryArtifacts::AutoRuns,
                    ),
                )],
                Box::new(move || {
                    counter.fetch_add(1, Ordering::SeqCst);
                    Box::new(MockParser::with_records(1, "h"))
                }),
            )
            .sink(Box::new(CountingSink::new()))
            .build()
            .unwrap();

        let result = pipeline.run().unwrap();

        assert_eq!(construction_count.load(Ordering::SeqCst), 0);
        assert_eq!(result.items_processed, 0);
    }

    #[test]
    fn legacy_factory_constructs_one_parser_for_a_matching_module() {
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::sync::Arc;

        let construction_count = Arc::new(AtomicU64::new(0));
        let counter = Arc::clone(&construction_count);
        let module = AnalysisModuleBuilder::new("mod")
            .analyzer(Box::new(CountingAnalyzer::with_artifact(Artifact::Unknown)))
            .sources(empty_sources)
            .build()
            .unwrap();

        let mut pipeline = ParallelPipeline::builder()
            .workers(1)
            .module(module)
            .parser_factory(Box::new(move || {
                counter.fetch_add(1, Ordering::SeqCst);
                Box::new(TypedMockParser::new(1, "h", Artifact::Unknown))
            }))
            .sink(Box::new(CountingSink::new()))
            .build()
            .unwrap();

        let result = pipeline.run().unwrap();

        assert_eq!(construction_count.load(Ordering::SeqCst), 1);
        assert_eq!(result.items_processed, 1);
    }
}
