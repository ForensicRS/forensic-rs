//! Shared per-record processing for both the serial and parallel pipelines.
//!
//! The stage sequence (enrich -> tally anomalies -> artifact-filtered
//! analyze -> route to a destination -> count) used to be duplicated at
//! ~85 lines each in `pipeline::mod` and twice in `pipeline::parallel`, and
//! had already drifted between the three copies. [`RecordProcessor`] is the
//! one copy; it also implements [`ParserOutput`] directly, so a
//! [`ParserRun::Push`] parser costs no separate engine.

use std::sync::mpsc::SyncSender;

use crate::{
    artifact::Artifact,
    bridge::CancellationToken,
    data::ForensicData,
    err::{ForensicError, ForensicResult},
    pipeline::{
        context::TriageContext,
        finding::{AnomalyTally, Finding},
        parallel::PipelineEvent,
        traits::{Analyzer, Enricher, TriageSink},
        ErrorAction,
    },
    traits::forensic::{ArtifactStream, OutputFlow, ParserOutput},
};

/// Where a processed record and its findings go. Implemented once for the
/// serial pipeline ([`SinkDestination`], fans into `&mut [Box<dyn
/// TriageSink>]`) and once for a parallel worker ([`ChannelDestination`],
/// `tx.send(PipelineEvent::{Data,Finding})`). Any error encountered while
/// routing is returned rather than swallowed, so the processor can fold it
/// into the run's error tally without the destination needing to know about
/// [`ErrorAction`] at all.
pub(crate) trait RecordDestination {
    fn data(&mut self, data: ForensicData) -> Vec<ForensicError>;
    fn finding(&mut self, finding: Finding) -> Vec<ForensicError>;
    /// Whether this destination can no longer accept anything (e.g. the
    /// parallel channel's receiver was dropped). Checked by the processor
    /// so it stops immediately instead of doing wasted work.
    fn is_closed(&self) -> bool {
        false
    }
}

/// Fans records and findings into the serial pipeline's sinks.
pub(crate) struct SinkDestination<'s> {
    pub(crate) sinks: &'s mut [Box<dyn TriageSink>],
}

impl RecordDestination for SinkDestination<'_> {
    fn data(&mut self, data: ForensicData) -> Vec<ForensicError> {
        let mut errors = Vec::new();
        for sink in self.sinks.iter_mut() {
            if let Err(e) = sink.on_data(&data) {
                errors.push(e);
            }
        }
        errors
    }
    fn finding(&mut self, finding: Finding) -> Vec<ForensicError> {
        let mut errors = Vec::new();
        for sink in self.sinks.iter_mut() {
            if let Err(e) = sink.on_finding(&finding) {
                errors.push(e);
            }
        }
        errors
    }
}

/// Streams records and findings to the parallel pipeline's main thread over
/// its bounded channel. A closed channel (receiver dropped) is not an
/// error — it just means the run is winding down. Owns a clone of the
/// sender (cheap — `SyncSender` clones are `Arc`-based) rather than
/// borrowing it, so the caller's original `tx` stays free to send
/// `TaskError`/`TaskDone` after this destination is dropped.
pub(crate) struct ChannelDestination {
    tx: SyncSender<PipelineEvent>,
    closed: bool,
}

impl ChannelDestination {
    pub(crate) fn new(tx: SyncSender<PipelineEvent>) -> Self {
        Self { tx, closed: false }
    }
}

impl RecordDestination for ChannelDestination {
    fn data(&mut self, data: ForensicData) -> Vec<ForensicError> {
        if !self.closed && self.tx.send(PipelineEvent::Data(data)).is_err() {
            self.closed = true;
        }
        Vec::new()
    }
    fn finding(&mut self, finding: Finding) -> Vec<ForensicError> {
        if !self.closed && self.tx.send(PipelineEvent::Finding(finding)).is_err() {
            self.closed = true;
        }
        Vec::new()
    }
    fn is_closed(&self) -> bool {
        self.closed
    }
}

/// Routes one finding to `dest` and counts it. A free function (not a
/// `&mut self` method on [`RecordProcessor`]) so it can be called from
/// inside `for x in self.enrichers.iter_mut() { ... }` / `self.analyzers
/// .iter_mut()` without the borrow checker seeing a conflicting whole-`self`
/// borrow — it only touches the disjoint fields it's given.
fn route_finding<D: RecordDestination>(
    dest: &mut D,
    findings: &mut u64,
    errors: &mut Vec<ForensicError>,
    stopped: &mut bool,
    finding: Finding,
) {
    *findings += 1;
    errors.extend(dest.finding(finding));
    if dest.is_closed() {
        *stopped = true;
    }
}

/// `data`-routing counterpart to [`route_finding`], for the same reason.
fn route_data<D: RecordDestination>(
    dest: &mut D,
    items: &mut u64,
    errors: &mut Vec<ForensicError>,
    stopped: &mut bool,
    data: ForensicData,
) {
    *items += 1;
    errors.extend(dest.data(data));
    if dest.is_closed() {
        *stopped = true;
    }
}

/// What a [`RecordProcessor`] run produced, handed back to the caller via
/// [`RecordProcessor::finish`].
pub(crate) struct ProcessorOutcome {
    pub items: u64,
    pub findings: u64,
    pub errors: Vec<ForensicError>,
    /// Set when `ErrorAction::Halt` fired on a stage that respects it. The
    /// caller decides what "halt" means for its pipeline (serial: abort the
    /// whole run immediately; parallel: stop this task, still finalize).
    pub halt_error: Option<ForensicError>,
}

/// Drives one parser's records through enrich -> tally -> analyze -> route,
/// for either a [`ParserRun::Pull`] stream (via [`Self::drive_pull`]) or a
/// [`ParserRun::Push`] closure (by being passed as `&mut dyn ParserOutput`
/// directly — see the [`ParserOutput`] impl below).
///
/// Generic over the enricher/analyzer trait-object type (`En`/`An`) so the
/// exact same logic serves both the serial pipeline's `Box<dyn Enricher>`
/// and the parallel pipeline's `Box<dyn Enricher + Send + 'static>` — a
/// trait object always implements its own trait, so `En = dyn Enricher` and
/// `En = dyn Enricher + Send + 'static` both satisfy `En: ?Sized + Enricher`.
pub(crate) struct RecordProcessor<'p, D, En: ?Sized, An: ?Sized>
where
    D: RecordDestination,
{
    dest: &'p mut D,
    enrichers: &'p mut [Box<En>],
    analyzers: &'p mut [Box<An>],
    analyzer_artifacts: &'p [Vec<Artifact>],
    context: &'p mut TriageContext,
    tally: &'p mut AnomalyTally,
    cancellation: &'p CancellationToken,
    error_action: ErrorAction,
    /// Whether enricher/analyzer-stage errors respect `ErrorAction::Halt`.
    /// The serial pipeline has never checked `ErrorAction` at these stages
    /// (only at the parser-record stage); the parallel pipeline always has.
    /// Preserved as configuration rather than unified, to avoid a silent
    /// behavior change — see the module doc of `pipeline::mod` for the
    /// tracked follow-up to unify this.
    strict_halt: bool,
    parser_id: &'p str,
    items: u64,
    findings: u64,
    errors: Vec<ForensicError>,
    stopped: bool,
    halt_error: Option<ForensicError>,
}

impl<'p, D, En, An> RecordProcessor<'p, D, En, An>
where
    D: RecordDestination,
    En: ?Sized + Enricher,
    An: ?Sized + Analyzer,
{
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        dest: &'p mut D,
        enrichers: &'p mut [Box<En>],
        analyzers: &'p mut [Box<An>],
        analyzer_artifacts: &'p [Vec<Artifact>],
        context: &'p mut TriageContext,
        tally: &'p mut AnomalyTally,
        cancellation: &'p CancellationToken,
        error_action: ErrorAction,
        strict_halt: bool,
        parser_id: &'p str,
    ) -> Self {
        Self {
            dest,
            enrichers,
            analyzers,
            analyzer_artifacts,
            context,
            tally,
            cancellation,
            error_action,
            strict_halt,
            parser_id,
            items: 0,
            findings: 0,
            errors: Vec::new(),
            stopped: false,
            halt_error: None,
        }
    }

    fn process(&mut self, record: ForensicResult<ForensicData>) -> OutputFlow {
        if self.cancellation.is_cancelled() {
            self.stopped = true;
            return OutputFlow::Stop;
        }

        let mut data = match record {
            Ok(data) => data,
            Err(e) => {
                crate::warn!("Parser '{}' produced error: {}", self.parser_id, e);
                let finding = Finding::from_error(format!("parser '{}'", self.parser_id), &e);
                route_finding(self.dest, &mut self.findings, &mut self.errors, &mut self.stopped, finding);
                self.errors.push(e.clone());
                if self.error_action == ErrorAction::Halt {
                    self.halt_error = Some(e);
                    self.stopped = true;
                    return OutputFlow::Stop;
                }
                return if self.stopped { OutputFlow::Stop } else { OutputFlow::Continue };
            }
        };
        let artifact = data.artifact().clone();

        for enricher in self.enrichers.iter_mut() {
            if self.cancellation.is_cancelled() {
                self.stopped = true;
                return OutputFlow::Stop;
            }
            if let Err(e) = enricher.enrich(&mut data, &mut *self.context) {
                crate::warn!("Enricher '{}' failed: {}", enricher.name(), e);
                let finding = Finding::from_error(format!("enricher '{}'", enricher.name()), &e)
                    .with_artifact(artifact.clone());
                route_finding(self.dest, &mut self.findings, &mut self.errors, &mut self.stopped, finding);
                self.errors.push(e.clone());
                if self.strict_halt && self.error_action == ErrorAction::Halt {
                    self.halt_error = Some(e);
                    self.stopped = true;
                    return OutputFlow::Stop;
                }
                if self.stopped {
                    return OutputFlow::Stop;
                }
            }
        }

        self.tally.record(data.anomalies());

        for (analyzer, supported) in self.analyzers.iter_mut().zip(self.analyzer_artifacts.iter()) {
            if self.cancellation.is_cancelled() {
                self.stopped = true;
                return OutputFlow::Stop;
            }
            if !supported.is_empty() && !supported.contains(&artifact) {
                continue;
            }
            let mut new_findings = Vec::new();
            let outcome = analyzer.analyze(&data, &*self.context, &mut new_findings);
            for f in new_findings {
                route_finding(self.dest, &mut self.findings, &mut self.errors, &mut self.stopped, f);
                if self.stopped {
                    return OutputFlow::Stop;
                }
            }
            if let Err(e) = outcome {
                crate::warn!("Analyzer '{}' failed: {}", analyzer.name(), e);
                let finding = Finding::from_error(format!("analyzer '{}'", analyzer.name()), &e)
                    .with_artifact(artifact.clone());
                route_finding(self.dest, &mut self.findings, &mut self.errors, &mut self.stopped, finding);
                self.errors.push(e.clone());
                if self.strict_halt && self.error_action == ErrorAction::Halt {
                    self.halt_error = Some(e);
                    self.stopped = true;
                    return OutputFlow::Stop;
                }
                if self.stopped {
                    return OutputFlow::Stop;
                }
            }
        }

        route_data(self.dest, &mut self.items, &mut self.errors, &mut self.stopped, data);
        if self.stopped {
            OutputFlow::Stop
        } else {
            OutputFlow::Continue
        }
    }

    /// Drives a [`ParserRun::Pull`] stream to completion (or until stopped).
    pub(crate) fn drive_pull(&mut self, stream: ArtifactStream) {
        for record in stream {
            if self.process(record).is_stop() {
                break;
            }
        }
    }

    /// Records a parser-level failure: `open()` returned `Err` after some
    /// records may already have been emitted (only reachable from a
    /// [`ParserRun::Push`] closure — a `Pull` stream's per-record errors go
    /// through [`Self::process`] instead).
    pub(crate) fn parser_error(&mut self, e: ForensicError) {
        crate::warn!("Parser '{}' failed: {}", self.parser_id, e);
        let finding = Finding::from_error(format!("parser '{}'", self.parser_id), &e);
        route_finding(self.dest, &mut self.findings, &mut self.errors, &mut self.stopped, finding);
        self.errors.push(e.clone());
        if self.error_action == ErrorAction::Halt {
            self.halt_error = Some(e);
            self.stopped = true;
        }
    }

    /// Whether an `ErrorAction::Halt`-triggering failure occurred.
    pub(crate) fn is_halted(&self) -> bool {
        self.halt_error.is_some()
    }

    /// Whether processing stopped for any reason — a halt, cancellation, or
    /// the destination closing (e.g. the parallel channel's receiver was
    /// dropped). A caller driving several parsers in sequence should check
    /// this (not just [`Self::is_halted`]) before starting the next one.
    pub(crate) fn is_stopped(&self) -> bool {
        self.stopped
    }

    /// Runs every analyzer's `finalize()` (aggregate / cross-record
    /// findings). Never halts — finalize runs after all records from this
    /// parser have already been processed, in both pipelines, unconditionally.
    pub(crate) fn finalize_analyzers(&mut self) {
        for analyzer in self.analyzers.iter_mut() {
            let mut new_findings = Vec::new();
            let outcome = analyzer.finalize(&*self.context, &mut new_findings);
            for f in new_findings {
                route_finding(self.dest, &mut self.findings, &mut self.errors, &mut self.stopped, f);
            }
            if let Err(e) = outcome {
                crate::warn!("Analyzer '{}' finalize failed: {}", analyzer.name(), e);
                let finding =
                    Finding::from_error(format!("analyzer '{}' finalize", analyzer.name()), &e);
                route_finding(self.dest, &mut self.findings, &mut self.errors, &mut self.stopped, finding);
                self.errors.push(e);
            }
        }
    }

    /// Flushes the per-parser anomaly tally into aggregate findings — one
    /// per flag observed, not one per anomalous record.
    pub(crate) fn flush_tally(&mut self) {
        let tally = std::mem::take(self.tally);
        for finding in tally.into_findings() {
            route_finding(self.dest, &mut self.findings, &mut self.errors, &mut self.stopped, finding);
        }
    }

    pub(crate) fn finish(self) -> ProcessorOutcome {
        ProcessorOutcome {
            items: self.items,
            findings: self.findings,
            errors: self.errors,
            halt_error: self.halt_error,
        }
    }
}

impl<D, En, An> ParserOutput for RecordProcessor<'_, D, En, An>
where
    D: RecordDestination,
    En: ?Sized + Enricher,
    An: ?Sized + Analyzer,
{
    fn emit(&mut self, record: ForensicResult<ForensicData>) -> OutputFlow {
        if self.stopped {
            return OutputFlow::Stop;
        }
        self.process(record)
    }
}
