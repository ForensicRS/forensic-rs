# forensic-rs Downstream Anti-Pattern Reference

## Quick smell table

| Smell | Why it's wrong here |
|---|---|
| Epoch/zero substitution for a missing timestamp | Fabricates evidence that didn't exist |
| `.unwrap()` / `panic!` on parsed evidence bytes | Crash-on-corrupt-input; DoS against triage of hostile data |
| `warn!("suspicious: …")` instead of pushing a `Finding` | Analyst-relevant signal hidden in engineer-only logs |
| Reimplementing `read_all`/`walk`/`key`/`value` on a backend | Duplicates `Ext` blanket impls; drifts from framework semantics |
| `HashMap` for report/timeline field storage | Breaks run-to-run reproducible ordering |
| Silently averaging or picking one value on source disagreement | Discards evidence of tampering, clock skew, or a bad source |
| A registry/VFS backend exposing a write method "for convenience" | Breaks the read-only chain-of-custody contract |
| A parser storing `Option<Reader>` + `&mut self` to fake lazy init | Self-referential-struct workaround for the old `ArtifactParser` shape — no longer needed, see the v0.14.0 parser-factory trap below |
| `.into_iter().flatten()` over a fallible accessor | Silently drops the whole result set on `Err` instead of surfacing one failed record |

## v0.14.0 breaking-change traps

Don't "fix" downstream code back to the pre-0.14 shape when reviewing an older diff, a stale example, or an agent's suggestion trained on older forensic-rs code:

- `IntoTimeline`/`IntoActivity` iterators yield `ForensicResult<T>`, not bare `T` — a per-record failure shouldn't abort the whole stream.
- `TryInto` on `&Field` returns `ForensicError`, not `&'static str`.
- `VMetadata` timestamps are `Option<ForensicTimestamp>`, not `Option<usize>` — an absent value is `None`, never an epoch substitute (ties back to the "never fabricate evidence" rule in `SKILL.md`).
- `ArtifactParser` (the `&mut self`, `parse<'a>(&'a mut self, sources: &'a mut TriageSources) -> ForensicResult<Box<dyn Iterator<...> + 'a>>` trait) is gone — replaced by `ArtifactParserFactory` (`&self`, `Send + Sync`, one `open(&self, ctx: &ParseContext<'_>) -> ForensicResult<ParserRun>`). Don't "fix" a factory back into the old shape, and don't reintroduce `Option<Reader>` self-mutation — a parser that discovers and opens its own reader now does so as a plain local inside `open()`, or inside a `ParserRun::Push` closure if the reader only returns borrowed cursors. `SourceHandle`/`Acquisition` are no longer constructor parameters — mint them from `ParseContext::register_source()`/`acquisition()` inside `open()`, against the pipeline's own `ProvenanceStore` (a caller-injected handle risked minting against the wrong store).

## EVTX parser work

forensic-rs's current first-party milestone is a `.evtx` reader behind an optional `evtx` Cargo feature, wrapping `omerbenamram/evtx` rather than reimplementing Binary XML, implementing `ArtifactParserFactory`, and mapping fields into `forensic_rs::dictionary` ECS constants. When reviewing or extending EVTX-adjacent work specifically:

- Event-ID gaps and record-ID discontinuities are `Finding`s (`FindingCategory::MissingData`), not log lines — a gap can mean log rotation *or* an attacker clearing partial history (`FindingCategory::AntiForensics`); surface the raw gap either way and let the analyst judge which.
- EVTX timestamps arrive as Windows FILETIME — construct via `ForensicTimestamp::from_win_filetime(...)`, don't hand-roll the FILETIME-to-Unix math.
- A single corrupt record inside an otherwise-readable `.evtx` file should surface as one failed item in the fallible iterator, not abort the whole file's processing.
