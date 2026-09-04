---
name: forensic-rs-tool-review
description: This skill should be used when the user asks to "review this against forensic-rs", "check forensic soundness", "is this idiomatic for forensic-rs", "build a Registry/FileSystem/ArtifactParserFactory backend", implements a forensic-rs trait (Registry, FileSystem, SqlStatement, EventLogReader, ArtifactParserFactory), or is writing an analyzer/parser that produces Finding/Anomalies output for a tool depending on the forensic-rs crate.
version: 0.1.0
---

# forensic-rs Tool Review

Apply this skill when reviewing or writing code in a crate that depends on [`forensic-rs`](https://github.com/ForensicRS/forensic-rs) — not `forensic-rs` itself. `forensic-rs` ships zero artifact parsers by design: every real capability (registry/filesystem/SQL/event-log backends, artifact parsers, analyzers, GUI/EDR/MCP integrations) lives downstream, implementing its traits. The code-quality bar for that downstream code *is* the framework's actual product, and because the output feeds a case report or automated detection, treat this as both a Rust-engineering review and a forensic-examiner review — a quality bug here doesn't just crash, it can misinform an investigation.

Defer to the forensic-rs repo's own `AGENTS.md`/`README.md` for exact trait signatures and conventions — this skill applies those conventions, it does not replace them, and the framework's APIs evolve (deprecations, breaking changes across versions).

## Architectural contract to check

forensic-rs uses a four-layer pattern (Core → Ext → Capability → Factory) across Registry, FileSystem, SQL, and EventLog domains.

- Confirm a backend implements only the minimal core trait (`Registry`, `FileSystem`, `SqlStatement`, `EventLogReader`). Flag any hand-rolled reimplementation of an `Ext` convenience method (`RegistryExt::key()`/`value()`, `FileSystemExt::read_all()`/`exists()`/`walk()`/`glob()`) — those are blanket-impl'd for every implementor, and a duplicate implementation drifts from the framework's error-mapping and edge-case handling over time.
- Keep core traits object-safe: `&self`-based, `Send + Sync`, no generics. That is what lets `Arc<dyn Registry>`/`Arc<dyn FileSystem>` be shared across worker threads. Flag `&mut self` or generic methods introduced into a core trait implementation.
- Respect `RegKey`'s `!Send`/`!Sync`, lifetime-tied nature — it mirrors a thread-confined live handle, enforced at compile time. Flag any attempt to stash one past its borrow or move it across a thread boundary.
- Prefer composing existing primitives (`ChRootFileSystem`, `MountTable`/`OverlayFs`, `ByteReader`/`FromBytes`) over a parallel reimplementation of path remapping, layered filesystems, or structured binary parsing.

## Forensic soundness rules (non-negotiable)

These have no equivalent in ordinary application code — the output is evidence, not just data.

**Never fabricate evidence.** A missing or unsupported timestamp stays `None` (`VMetadata::created_opt()`/`accessed_opt()`/`modified_opt()`). Flag any substitution of the Unix epoch or "now" for a missing value — that turns absence of data into a false data point, which is worse than no value in a case report.

**Treat divergence as evidence, not a bug to silence.** When two sources disagree, or a checksum fails, route it through `Anomalies`/`Finding`. Flag `unwrap_or_default()`, silently picking one source, or averaging — each discards exactly the signal an analyst needs.

**Preserve provenance and precision.** Use `ForensicTimestamp`'s source/precision flags and, where the crate exposes them, `Tracked<T>`/`Parsed<T>`/`ProvenanceStore`. Flag collapsing a sourced, nanosecond-precision timestamp into a bare `u64` when the consumer can carry the richer type through.

**Enforce the three-way split** — route every notable signal through this table:

| If… | Route it to… |
|---|---|
| an analyst would want it in the case report | a `Finding` (or an `Anomaly` on the value it describes) |
| only an engineer debugging the tool cares | a log macro (`warn!`, `debug!`, …) |
| the tool literally cannot proceed | a `ForensicError` |

There is no fourth channel. Flag `warn!("suspicious: …")` or similar log-only surfacing of anything an analyst needed to see in the report — it belongs in a `Finding` with a `FindingSeverity`/`FindingCategory`.

**Require read-only evidence access.** Flag any write path added to a trait meant for read access to a registry hive, disk image, or log file — it breaks the chain-of-custody guarantee the framework is built around.

**Require deterministic output.** Field and record ordering should be reproducible run-to-run (the framework stores fields in `BTreeMap`, not `HashMap`, for this reason). Flag nondeterministic iteration order leaking into timeline or report output.

## Treat corrupted/adversarial input as the normal case

DFIR tools parse data that may be corrupted by accident or deliberately manipulated as anti-forensics — review this as a security lens, not just a robustness one.

- Flag `.unwrap()`, `.expect()`, `panic!`, or un-checked slice indexing on bytes sourced from evidence. Require `ensure_buffer_size!`/`ensure_buffer_range!`/`ensure_format!` or the fallible `read_u32_le_at`-style helpers instead of raw offset arithmetic on untrusted input.
- For any structure with more than a couple of fields, prefer `ByteReader`+`FromBytes` over manual offset math — the cursor tracks position and composes across nested structs, catching boundary cases hand-rolled arithmetic tends to miss.
- Check decompression call sites (`decompress()` with LZNT1/Xpress/Xpress+Huffman) for missing output-size bounds when input is attacker-influenced — an unbounded decompression is a realistic DoS vector against a triage tool ingesting untrusted images.
- Require that a malformed or truncated artifact degrades to a `Finding`/`ForensicError`, never a crash. A parser that panics on bad input means evidence went unexamined — promote that failure into a `ProcessingError` finding (`Finding::from_error`) instead of losing it silently.

## Code-quality conformance checklist

- Naming: traits are concept nouns with an `Ext` suffix for the ergonomic layer (`FileSystem`/`FileSystemExt`); structs/enums are `PascalCase`; constants are `SCREAMING_SNAKE_CASE`; functions/macros are `snake_case`.
- String discipline: `Text::Borrowed` for static field names, `Text::Owned` for runtime strings; `CompactString::const_new(...)` for static messages, `.into()`/`From` for dynamic content.
- Field naming: populate `ForensicData` using the ECS constants in `forensic_rs::dictionary` rather than ad hoc string literals — this is what lets output from unrelated downstream tools line up in the same timeline or SIEM index.
- Testing: use the framework's own test doubles (`TestingRegistry`, `InMemoryVirtualFileSystem`, `TestingEventLogReader`/`basic_event_log()`, `testing_logger_dummy()`) instead of a mocking library or the live OS.

Check the anti-pattern quick table and version-specific gotchas in `references/anti-patterns.md` before finishing a review.

## Additional resources

### Reference files

- **`references/anti-patterns.md`** — smell-to-bug quick table, forensic-rs v0.14 breaking-change traps, and EVTX-parser-specific notes.
