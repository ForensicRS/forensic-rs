# Cookbook: Pipeline Recipes

This cookbook provides patterns for exposing ForensicRS pipeline capabilities via MCP.

## Overview

The ForensicRS triage pipeline processes artifacts through:

```
Parsers → Enrichers → Analyzers → Sinks
```

`PipelineTaskTool` wraps pipeline components as MCP tools with automatic authorization.

## Recipe 1: Wrapping a Parser as MCP Tool

Expose an `ArtifactParser` as a tool.

```rust
use forensic_rs::prelude::*;

// Your parser (from examples/triage_pipeline.rs)
pub struct AutorunParser;

impl ArtifactParser for AutorunParser {
    fn name(&self) -> &str { "autoruns" }
    fn description(&self) -> &str { "Reads Run/RunOnce registry keys" }
    fn version(&self) -> &str { "0.1.0" }

    fn supported_artifacts(&self) -> Vec<Artifact> {
        vec![Artifact::Windows(WindowsArtifacts::Registry(RegistryArtifacts::AutoRuns))]
    }

    fn parse<'a>(&'a mut self, sources: &'a mut TriageSources)
        -> ForensicResult<Box<dyn Iterator<Item = ForensicResult<ForensicData>> + 'a>>
    {
        let registry = sources.registry()
            .ok_or_else(|| ForensicError::missing_data("autoruns", "Registry required"))?;

        let handle = registry.open_key(HKU, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run")?;
        let mut results = Vec::new();

        registry.enumerate_values(&handle, &mut |name| {
            let value = registry.read_value(&handle, name)?;
            if let Ok(cmd) = String::try_from(&value) {
                let mut data = ForensicData::new("WORKSTATION01", self.supported_artifacts()[0].clone());
                data.insert("autorun.name", Field::Text(Text::Owned(name.to_string())));
                data.insert("autorun.command", Field::Text(Text::Owned(cmd)));
                results.push(Ok(data));
            }
            Ok(RegistryVisit::Continue)
        })?;

        Ok(Box::new(results.into_iter()))
    }
}
```

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

    fn analyze(&mut self, data: &ForensicData) -> ForensicResult<Vec<Finding>> {
        let mut findings = Vec::new();

        let value = match data.field("autorun.command") {
            Some(Field::Text(t)) => t.to_string().to_lowercase(),
            _ => return Ok(findings),
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
                findings.push(Finding::new(
                    FindingSeverity::Medium,
                    FindingCategory::SuspiciousActivity,
                    format!("Suspicious autorun detected: {}", reason),
                ).with_artifact(data.artifact().clone()));
            }
        }

        self.findings.extend(findings.clone());
        Ok(findings)
    }

    fn finalize(&mut self) -> ForensicResult<Vec<Finding>> {
        Ok(std::mem::take(&mut self.findings))
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

        let handle = registry.open_key(HKU, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run")?;

        registry.enumerate_values(&handle, &mut |name| {
            let value = registry.read_value(&handle, name)?;
            if let Ok(cmd) = String::try_from(&value) {
                // Simple pattern check
                if cmd.to_lowercase().contains("powershell") {
                    self.findings.push(format!("{}: {}", name, cmd));
                }
            }
            Ok(RegistryVisit::Continue)
        })?;

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
    parser: Box<dyn ArtifactParser>,
    analyzers: Vec<Box<dyn Analyzer>>,
    sinks: Vec<Box<dyn TriageSink>>,
}

impl AnalysisTaskFactory {
    pub fn new(
        parser: Box<dyn ArtifactParser>,
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
            .parser(self.parser.box_clone())
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
