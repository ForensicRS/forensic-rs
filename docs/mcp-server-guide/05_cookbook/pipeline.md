# Cookbook: Pipeline Recipes

This cookbook provides patterns for exposing ForensicRS pipeline capabilities via MCP.

## Overview

The ForensicRS triage pipeline processes artifacts through:

```
Parsers → Enrichers → Analyzers → Sinks
```

`PipelineTaskTool` wraps pipeline components as MCP tools with automatic authorization.

## Recipe 1: Wrapping a Parser as MCP Tool

Expose an `ArtifactParserFactory` as a tool. A factory is stateless and
`&self` — one instance behind an `Arc` serves the serial pipeline, every
parallel worker, and every `AnalysisModule` that needs it. Parse-local state
(the opened registry key, in this example) lives in `open()`'s stack frame,
never in `self`.

```rust
use forensic_rs::prelude::*;

// Your parser (from examples/triage_pipeline.rs)
pub struct AutorunParser {
    descriptor: ParserDescriptor,
}

impl AutorunParser {
    pub fn new() -> Self {
        Self {
            descriptor: ParserDescriptor::new(
                "autoruns",
                "autoruns",
                "Reads Run/RunOnce registry keys",
                "0.1.0",
            )
            .with_artifacts(vec![Artifact::Windows(WindowsArtifacts::Registry(
                RegistryArtifacts::AutoRuns,
            ))]),
        }
    }
}

impl ArtifactParserFactory for AutorunParser {
    fn descriptor(&self) -> &ParserDescriptor {
        &self.descriptor
    }

    fn open(&self, ctx: &ParseContext<'_>) -> ForensicResult<ParserRun> {
        let registry = ctx.registry()
            .ok_or_else(|| ForensicError::missing_data("autoruns", "Registry required".into()))?;
        // Registered here, not injected at construction — the parser is the
        // only thing that knows what its own source key should be.
        let source = ctx.register_source(SourceKey::Live {
            host: ctx.host().to_string(),
            api: "RegistryReader".to_string(),
        });

        // `RegistryExt::key` takes a single hive-prefixed path string and
        // returns a `RegKey` RAII guard — no separate hive argument, no
        // handle to close manually (it closes when the guard drops).
        let key = registry.key(r"HKU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run")?;
        let mut results = Vec::new();

        for (name, value) in key.values()? {
            if let Ok(cmd) = String::try_from(value) {
                let provenance = source.mint(Acquisition::LiveApi, Recovery::Allocated);
                let mut data = ForensicData::new("WORKSTATION01", self.descriptor.artifacts[0].clone(), provenance);
                data.insert("autorun.name", Field::Text(Text::Owned(name)));
                data.insert("autorun.command", Field::Text(Text::Owned(cmd)));
                results.push(Ok(data));
            }
        }

        Ok(ParserRun::pull(results.into_iter()))
    }
}
```

For a reader that only hands back borrowed cursors (a nested database table,
an event-log iterator) rather than an owned `Vec`/iterator, return
`ParserRun::push(move |out| { ... })` instead — see
[`ArtifactParserFactory`](https://docs.rs/forensic-rs) for a worked example
and the trade-offs of each mode.

## Recipe 2: Wrapping an Analyzer as MCP Tool

Expose an `Analyzer` that produces findings.

```rust
use forensic_rs::prelude::*;

// Your analyzer (from examples/triage_pipeline.rs)
pub struct SuspiciousAutorunAnalyzer {
    findings: Vec<Finding>,
}

impl SuspiciousAutorunAnalyzer {
    fn new() -> Self {
        Self { findings: Vec::new() }
    }
}

impl Analyzer for SuspiciousAutorunAnalyzer {
    fn name(&self) -> &str { "suspicious_autorun" }

    fn supported_artifacts(&self) -> Vec<Artifact> {
        vec![Artifact::Windows(WindowsArtifacts::Registry(RegistryArtifacts::AutoRuns))]
    }

    fn analyze(
        &mut self,
        data: &ForensicData,
        _context: &TriageContext,
        out: &mut Vec<Finding>,
    ) -> ForensicResult<()> {
        let value = match data.field("autorun.command") {
            Some(Field::Text(t)) => t.to_string().to_lowercase(),
            _ => return Ok(()),
        };

        // Check for suspicious patterns
        let suspicious = [
            ("\\temp\\", "Autorun from temp directory"),
            ("powershell", "PowerShell in autorun"),
            ("-enc ", "Encoded command in autorun"),
            ("bitsadmin", "Bitsadmin downloader"),
        ];

        for (pattern, reason) in &suspicious {
            if value.contains(pattern) {
                let finding = Finding::new(
                    FindingSeverity::Medium,
                    FindingCategory::SuspiciousActivity,
                    format!("Suspicious autorun detected: {}", reason),
                ).with_artifact(data.artifact().clone());
                self.findings.push(finding.clone());
                out.push(finding);
            }
        }

        Ok(())
    }

    fn finalize(&mut self, _context: &TriageContext, out: &mut Vec<Finding>) -> ForensicResult<()> {
        out.extend(std::mem::take(&mut self.findings));
        Ok(())
    }
}
```

## Recipe 3: Using PipelineTaskTool

Wrap parsers/analyzers with automatic access control.

```rust
use forensic_rs::capabilities::pipeline::*;

// Create tool with access requirements
let tool = PipelineTaskTool::new(
    ToolDescriptor {
        id: "analysis.autoruns".into(),
        title: "Autorun Analysis".into(),
        description: "Analyzes autorun entries for suspicious patterns.".into(),
        input_schema: ValueSchema::object()
            .property("case_id", ValueSchema::Type(ValueType::Text))
            .required("case_id")
            .into(),
        output_schema: Some(
            ValueSchema::object()
                .property("findings", ValueSchema::Array(Box::new(ValueSchema::Type(ValueType::Text))))
                .property("total_analyzed", ValueSchema::Type(ValueType::Integer))
                .required(["findings", "total_analyzed"])
                .into(),
        ),
        hints: ToolHints {
            read_only: true,
            long_running: true,
            ..ToolHints::default()
        },
    },

    // Access requirements: what this tool needs access to
    AccessRequirements::new()
        .registry("autoruns")  // Requires registry with autorun support
        .artifact(Artifact::Windows(WindowsArtifacts::Registry(RegistryArtifacts::AutoRuns))),

    // Policy
    Arc::new(AllowAllPolicy::new()),

    // Task factory
    Arc::new(AutorunTaskFactory::new()),
);

pub struct AutorunTaskFactory;

impl AutorunTaskFactory {
    fn new() -> Self { Self }
}

impl PipelineTaskFactory for AutorunTaskFactory {
    fn create_task(
        &self,
        context: &AuthorizedPipelineContext,
        _input: CapabilityValue,
    ) -> CapabilityResult<Box<dyn PipelineTask>> {
        Ok(Box::new(AutorunTask::new(context.clone())))
    }
}

pub struct AutorunTask {
    context: AuthorizedPipelineContext,
    findings: Vec<String>,
}

impl AutorunTask {
    fn new(context: AuthorizedPipelineContext) -> Self {
        Self {
            context,
            findings: Vec::new(),
        }
    }
}

impl PipelineTask for AutorunTask {
    fn run(&mut self, sources: &mut TriageSources) -> CapabilityResult<()> {
        let registry = sources.registry()
            .ok_or_else(|| CapabilityError::new(
                CapabilityErrorKind::Unavailable,
                "Registry source required"
            ))?;

        let key = registry.key(r"HKU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run")?;

        for (name, value) in key.values()? {
            if let Ok(cmd) = String::try_from(value) {
                // Simple pattern check
                if cmd.to_lowercase().contains("powershell") {
                    self.findings.push(format!("{}: {}", name, cmd));
                }
            }
        }

        Ok(())
    }

    fn finalize(self: Box<Self>) -> CapabilityResult<ToolResult> {
        let mut map = BTreeMap::new();
        map.insert(Text::Borrowed("findings"), CapabilityValue::Array(
            self.findings.into_iter().map(CapabilityValue::from).collect()
        ));
        map.insert(Text::Borrowed("total_analyzed"), CapabilityValue::from(self.findings.len() as u64));

        Ok(ToolResult::structured(CapabilityValue::Object(map)))
    }
}
```

## Recipe 4: Custom PipelineTaskFactory

Factory that creates fresh pipeline per invocation.

```rust
use forensic_rs::capabilities::pipeline::*;

pub struct AnalysisTaskFactory {
    // `Arc`, not `Box`: `ArtifactParserFactory` is stateless and `Send + Sync`,
    // so the same instance is shared across every invocation instead of
    // being cloned or reconstructed per call.
    parser: Arc<dyn ArtifactParserFactory>,
    analyzers: Vec<Box<dyn Analyzer>>,
    sinks: Vec<Box<dyn TriageSink>>,
}

impl AnalysisTaskFactory {
    pub fn new(
        parser: Arc<dyn ArtifactParserFactory>,
        analyzers: Vec<Box<dyn Analyzer>>,
    ) -> Self {
        Self {
            parser,
            analyzers,
            sinks: vec![
                Box::new(FindingCollector::with_min_severity(FindingSeverity::Low)),
            ],
        }
    }
}

impl PipelineTaskFactory for AnalysisTaskFactory {
    fn create_task(
        &self,
        context: &AuthorizedPipelineContext,
        _input: CapabilityValue,
    ) -> CapabilityResult<Box<dyn PipelineTask>> {
        // Create fresh pipeline for this invocation
        let pipeline = TriagePipeline::builder()
            .context(TriageContext::new("WORKSTATION01", "ACME-Corp"))
            .parser(Arc::clone(&self.parser))
            .sinks(std::mem::take(&mut self.sinks.clone()))  // Clone sinks
            .build()
            .map_err(|e| CapabilityError::new(CapabilityErrorKind::Internal, e.to_string()))?;

        Ok(Box::new(AnalysisTask {
            pipeline,
            findings: Vec::new(),
        }))
    }
}

pub struct AnalysisTask {
    pipeline: TriagePipeline,
    findings: Vec<Finding>,
}

impl PipelineTask for AnalysisTask {
    fn run(&mut self, sources: &mut TriageSources) -> CapabilityResult<()> {
        // Run the pipeline
        let result = self.pipeline.run(sources)
            .map_err(|e| CapabilityError::new(CapabilityErrorKind::Internal, e.to_string()))?;

        // Collect findings
        self.findings = result.findings;

        Ok(())
    }

    fn finalize(self: Box<Self>) -> CapabilityResult<ToolResult> {
        let finding_strings: Vec<_> = self.findings.iter()
            .map(|f| format!("{:?}: {}", f.severity, f.message))
            .collect();

        let mut map = BTreeMap::new();
        map.insert(Text::Borrowed("findings"), CapabilityValue::Array(
            finding_strings.into_iter().map(CapabilityValue::from).collect()
        ));
        map.insert(Text::Borrowed("total_findings"), CapabilityValue::from(self.findings.len() as u64));

        Ok(ToolResult::structured(CapabilityValue::Object(map)))
    }
}
```

## Recipe 5: Access Requirements Declaration

Declare what resources a pipeline tool needs.

```rust
use forensic_rs::capabilities::pipeline::*;

let requirements = AccessRequirements::new()
    // Registry access
    .registry("autoruns")
    .registry("shimcache")

    // VFS access
    .virtual_file_system("case-evidence")
    .artifact(Artifact::Windows(WindowsArtifacts::Registry(RegistryArtifacts::AutoRuns)))
    .artifact(Artifact::Windows(WindowsArtifacts::Registry(RegistryArtifacts::ShimCache)))

    // Parser/analyzer requirements
    .parser("windows.evtx")
    .parser("windows.registry")
    .analyzer("windows.event_gap")
    .analyzer("windows.autorun_suspicious");

// The registry will verify access before creating the pipeline
let tool = PipelineTaskTool::new(
    descriptor,
    requirements,
    policy,
    factory,
);
```

## Summary: Pipeline Patterns

| Pattern | Use When |
|---------|----------|
| Parser wrapper | Need to expose raw artifact parsing |
| Analyzer wrapper | Need to expose analysis with findings |
| PipelineTaskTool | Need automatic access control |
| Custom factory | Need per-invocation state |
| AccessRequirements | Need to declare resource dependencies |
