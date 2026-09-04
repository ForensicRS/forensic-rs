# MCP Capability Coverage & Roadmap

This page is a snapshot, not a tutorial. It exists for two audiences:

- **MCP server developers** building on forensic-rs, who need to know what's ready to
  use, what exists in the library but isn't demonstrated anywhere, and what they'd have
  to build themselves.
- **Forensic analysts** who end up on the client side of a forensic-rs-based MCP
  server, who need to know what they can rely on today and what's still missing from
  the evidentiary picture a tool hands back to them.

It reflects the state of the crate at the time of writing. Re-check file:line
references against the current source before relying on them — this page will drift.

## At a Glance

| Capability | Status | Where | Note |
|---|---|---|---|
| Tools | ✅ Implemented & demonstrated | `src/capabilities/tools.rs`, `examples/mcp_stdio_server.rs` | `tools/list`/`tools/call` fully wired end to end. |
| Resources | ✅ Implemented & demonstrated | `src/capabilities/resources.rs`, `src/bridge/providers.rs`, `examples/mcp_stdio_server.rs` | The example registers a chrooted `VfsProvider` and serves `resources/list`/`resources/read` over `forensic://{provider}/{path}` URIs, including lazy on-demand mounting into nested containers (zip-style) — see "Nested/Cross-Family Resource Design" below. |
| Node actions | ✅ Implemented, no example wiring | `ResourceProvider::actions()`, `ScopedCapabilityRegistry::list_node_actions()` (`src/capabilities/registry.rs`), `ProviderHook::action_ids()`/`virtual_action_ids()` (`src/bridge/hooks.rs`) | Discovery link from a resource node to already-registered tool IDs that apply to it — see [Node Actions](./04_tutorial/06_resources.md#node-actions-linking-resources-to-tools). Rust-API-level only; no MCP method for it exists, so `examples/mcp_stdio_server.rs` doesn't wire it into a JSON-RPC verb. |
| Progress notifications | ✅ Implemented & demonstrated | `src/capabilities/tools.rs` (`ProgressReporter`) | Real `notifications/progress` emission in the example. |
| Cancellation | ✅ Implemented & demonstrated | `src/bridge/mod.rs` (`CancellationToken`), `examples/mcp_stdio_server.rs` | `tools/call` runs on a worker thread; `notifications/cancelled` (keyed by `requestId`, per spec) reaches and cancels the matching in-flight call. |
| Resource templates | ❌ Not implemented | — | No URI-template concept; navigation is `children()`-based only. |
| Prompts | ❌ Not implemented | — | No `Prompt` type, no `prompts/list`/`prompts/get`. |
| Sampling (`createMessage`) | ❌ Not implemented | — | See dedicated section below. |
| Roots | ❌ Not implemented | — | No client-exposed-roots concept anywhere. |
| Logging (MCP protocol-level) | ❌ Not implemented | — | The crate's own `log`-crate integration is unrelated; no `notifications/message`/`logging/setLevel`. |
| Elicitation | ❌ Not implemented | — | No occurrences anywhere in source, examples, or docs. |
| Completion | ❌ Not implemented | — | No `completion/complete` argument-autocomplete support. |

## Developer Perspective

### What you get for free today

The `src/capabilities/` module is a protocol-neutral substrate: `ForensicTool` +
`CapabilityRegistry`/`ScopedCapabilityRegistry` + `AccessPolicy` + `CapabilityValue`
give you working tool discovery, invocation, schema validation, and per-caller
authorization without depending on an MCP SDK or an async runtime. `PipelineTaskTool`/
`PipelineTaskFactory` (`src/capabilities/pipeline.rs`) let a tool run a fresh
`TriagePipeline`/`ParallelPipeline` per invocation with pre-authorized sources. This is
a solid foundation — `examples/mcp_stdio_server.rs` shows it working end to end for
tools.

### Resources and cancellation are wired in

**Resources.** `ResourceProvider` (`src/capabilities/resources.rs`) and four concrete,
tested implementations — `RegistryProvider`, `VfsProvider`, `EventLogProvider`,
`DatabaseProvider` (`src/bridge/providers.rs`) — are library-level building blocks.
`examples/mcp_stdio_server.rs` now registers a `VfsProvider` wrapping a
`ChRootFileSystem` scoped to the crate's own working directory (not the raw host
root — a real deployment would chroot to an actual evidence/triage directory
instead), advertises `"resources": {}` in `initialize`, and serves `resources/list`
(root call lists registered providers; a `uri` param drills into `children()`) and
`resources/read` over a `forensic://{provider}/{path}` URI scheme — the same scheme
already used for `ToolContent::ResourceReference`. See
[Resources Tutorial](./04_tutorial/06_resources.md) for the provider-side API this is
built on.

**A note on nesting.** The base MCP spec's `resources/list`/`resources/read` pair is
flat — there's no "list this resource's children" primitive; that's what Resource
Templates (which this crate doesn't implement) are officially for. The `uri`-param
drilldown on `resources/list` above is a pragmatic, non-standard convention: it only
helps a client that specifically knows to pass a previously-seen `uri` back into
another `list` call, which a generic MCP client has no reason to do. What a generic
client *will* naturally do is call `resources/read` on any URI it discovered — so
`resources/read` falls back to returning a resource's children (as a JSON manifest,
via the same `list_resources` call, `handle`'s `"resources/read"` arm) whenever the
underlying provider can't read it as content (i.e. it's a container — a directory, a
registry key, ...). This means nested browsing works through plain `resources/read`
alone, without any client needing to know this server's `uri`-drilldown convention.

**Cancellation.** `tools/call` now runs on a dedicated worker thread spawned from
`main()`, so the main `stdin` read loop stays free to receive and dispatch a
`notifications/cancelled` notification while a call is in flight — the previous
version's core problem, where the next line couldn't even be *read* until the running
call returned, is gone. `Server` holds a `CancellationToken` registry keyed by the
stringified JSON-RPC request id; `handle_tools_call` registers a fresh token before
invoking and removes it afterward, and the `"notifications/cancelled"` handler looks
up its `requestId` (the correct field per the MCP spec — the previous version
incorrectly read `progressToken`) and calls `.cancel()` on the matching token. One
worker thread per call, no pool — an acceptable simplification for a trusted-local
reference example, not a production concurrency model.

### What's still missing, and how hard it'd be to add

Prompts, resource templates, roots, and protocol-level logging would all extend
naturally in the same shape as the existing registry pattern: a `Prompt`/
`PromptProvider` trait alongside `ForensicTool`/`ResourceProvider`; a
`ResourceTemplate` concept layered onto the existing `ResourceProvider::children`
navigation; a `roots` capability negotiated at `initialize` time; a `log`-crate
integration that also emits `notifications/message`. None of these require the crate
to become async or depend on an MCP SDK.

**Sampling and elicitation don't fit that pattern** — see the dedicated section below.

## Forensic Analyst Perspective

### What already serves you

Case-summary style tools and long-running scans with progress reporting and real
cancellation are working today.

### What's available to you now

Evidence browsing — not just curated tool summaries — is available in the reference
server: `resources/list`/`resources/read` let you walk a filesystem tree directly
(the example scopes this to its own working directory; a real deployment would scope
it to an actual evidence/triage directory). The same `ResourceProvider` mechanism
covers registry hives, event log channels, and database tables (`RegistryProvider`,
`EventLogProvider`, `DatabaseProvider`) if your server operator registers those
sources too. Long-running scans can also now be cancelled mid-flight and have that
cancellation actually take effect, instead of running to completion regardless.

### The gap that matters most for your work

**Confidence and provenance aren't surfaced in tool output at all.** forensic-rs has a
dedicated module (`src/provenance/`) for exactly the question that matters most in
forensics: how much should you trust a given fact? `Confidence`
(`src/provenance/confidence.rs`) is ordered `Unknown < Low < Medium < High` — a value
carved from slack space is `Low`, a live registry read is `Medium`, an allocated record
read from a static image is `High` — and it's folded across an entire derivation chain
to the *weakest* link, so a value derived from something shaky stays shaky.
`AnomalyFlags`/`Anomalies` (`src/provenance/anomalies.rs`) track cross-cutting red
flags like `CHECKSUM_MISMATCH`, `REFERENCE_CYCLE`, or `TIMESTAMP_DIVERGENCE`. This
machinery is fully exercised inside the pipeline —
`ForensicData::confidence(&ProvenanceStore)` is a real, tested call
(`src/pipeline/mod.rs`, exercised by `should_flow_provenance_through_real_pipeline`) —
but **there is no `CapabilityValue` conversion for `Confidence` or `Anomalies`**.
Contrast this with `ForensicData` itself, which does have one
(`impl From<&ForensicData> for CapabilityValue`, `src/capabilities/value.rs:87-99`).
The practical effect: even a tool that runs a complete pipeline today can tell you
*that* something happened, but has no built-in way to tell you *how much to trust*
that it happened the way it's described. `Finding` (`src/pipeline/finding.rs:97-106` —
severity, category, title, description, source artifact, related data) has the same
gap: no `CapabilityValue` conversion, so a server author wanting to return pipeline
findings from a tool has to hand-roll that mapping themselves.

### What sampling would give you

If a server author added it, sampling would let a tool pause mid-analysis and ask the
LLM for a second opinion on ambiguous evidence — e.g. "does this registry value's
binary blob look like a known persistence technique?" — before finishing its response.
It isn't there today; see the next section for why.

## Sampling: An External-Adapter Concern

MCP's `sampling/createMessage` is fundamentally different from every other capability
on this page: it's the *server* initiating a request *to the client*, and blocking for
a response, in the middle of handling a `tools/call`. Every other capability in
forensic-rs today is a plain, synchronous, one-directional call:
`ForensicTool::invoke(&self, input, context) -> CapabilityResult<ToolResult>` returns
once, from the tool outward. Sampling needs the opposite: the tool calls *out*,
mid-invocation, and waits.

This doesn't fit forensic-rs core, and that's by design, not an oversight. The crate's
own architecture doc is explicit that it deliberately depends on no MCP SDK, no
JSON-RPC transport, and no async runtime — those are left to whoever builds the actual
server. Adding sampling as a first-class capability would mean either making
`ForensicTool::invoke` async (a breaking, ecosystem-wide change) or threading a
blocking callback through `InvocationContext` that somehow speaks MCP — both of which
push protocol concerns into a crate that has otherwise stayed strictly protocol-neutral.

**The pattern a server author can use today, without any change to forensic-rs:**
`InvocationContext` already demonstrates the right shape — it carries a
`ProgressReporter` that a tool calls into without knowing anything about JSON-RPC. A
server author who wants sampling can do the same thing with their own context type:

```rust
// Illustrative only — not part of forensic-rs. A server author's own code.
trait SamplingClient: Send + Sync {
    fn ask(&self, prompt: &str) -> Result<String, SamplingError>;
}

struct MyInvocationContext {
    inner: InvocationContext,       // forensic-rs's context, unchanged
    sampling: Arc<dyn SamplingClient>, // the server's own addition
}
```

The tool calls `context.sampling.ask(...)`; the server's `SamplingClient`
implementation is the only thing that knows it's actually sending
`sampling/createMessage` over JSON-RPC and blocking on the client's reply.
forensic-rs never needs to know sampling exists.

## Nested/Cross-Family Resource Design

A real evidence set nests: a ZIP containing a triage collection, containing a
registry hive file, containing a regkey. Two categorically different mechanisms
cover this:

- **Same-family virtual structure** (a *value* recovered from one provider secretly
  contains more structure — shellbags packed inside a binary registry value):
  `ProviderHook` (`src/bridge/hooks.rs`). Injects virtual children under a
  `[hookname]` path segment, still inside the *same* provider, still speaking the
  *same* generic `BridgeValue` model. Already wired through to the MCP-facing
  `ResourceProvider` surface. `virtual_children()`/`read_virtual()` both support real
  multi-level nesting below `[hookname]` — a hook self-routes on the full remaining
  sub-path it's handed, not just a single flat level. `RegistryProvider` dispatches
  through the `[hookname]` marker as before; `VfsProvider` now dispatches its hooks
  too (previously registered but never consulted) using a marker-free convention — a
  recognized file's own path "becomes" the hook's children, since a file has no real
  children of its own to collide with.
- **Cross-family containment/interpretation/embedding** (a *file* that, opened,
  turns out to be a whole different kind of source — a zip, an E01, a registry
  hive, a database, a structured object's embedded children): one unified
  `FormatFactory` trait (`src/traits/format.rs`), covering all three
  relationships through a single `probe()`/`mount()` contract and a `Mounted`
  result (`FileSystem`/`Registry`/`Database`/`EventLog`/`Object`/`File`). A
  successful mount produces a brand new, independent `Arc<dyn FileSystem>` /
  `Arc<dyn Registry>` / etc. with no automatic path-composition to the outer
  one — composition is the resolver's job, described below, not the factory's.

**Eager/static pre-mounting (walk the whole evidence tree at startup, mount
everything mountable) doesn't work.** It requires exhaustively signature-checking
every file against every registered `FormatFactory` before the server can even
answer `initialize`. A real evidence set can be hundreds of thousands of files —
that's unbounded startup latency and wasted I/O on files nobody will ever ask about,
and it cuts against the crate's own lazy-everywhere design (`read_dir` is a lazy
iterator, `FileSystemExt::walk()` is a real streaming DFS, precisely to avoid this
kind of unbounded upfront work).

**What's implemented instead: lazy, on-demand mount-and-cache**, via
`MountResolver` (`src/core/resolver.rs`), used from `examples/mcp_stdio_server.rs`.
A container is sniffed and mounted only the first time something actually reads
into it, then cached:

- `MountResolver` holds every registered `Arc<dyn FormatFactory>` (probed in
  order, deterministic winner: highest `ProbeScore`, tied broken by factory
  name — never registration order, so output never depends on wiring) and a
  cache keyed by `EvidenceLocator` (`src/core/locator.rs`), a structured chain
  of typed hops — not a flat string path. This matters: a string cache keyed on
  the container's path string can represent only one level of nesting, because
  locating a nested marker within an already-nested path is ambiguous over
  plain text. `EvidenceLocator` has no such ceiling — each hop is its own cache
  entry, correctly scoped by the exact chain of containers above it, so
  `Server::mounted_filesystem` resolves an arbitrary depth of `[mount]` markers
  by mounting one hop at a time and accumulating the locator as it goes (see
  `tests/nesting.rs` for the multi-hop proof, and the
  `nested_mount_tests` module in `examples/mcp_stdio_server.rs` for the
  server-level regression tests this bug fix is pinned by).
- `resources/read` on an ordinary file whose bytes match a registered factory's
  format gets a `mount_uri` hint alongside its normal content — the read still
  returns the real bytes; the hint is generated by
  `MountResolver::probe_only()`, which runs the real registered `probe()`
  implementations without mounting, caching, or charging any resource budget.
- A path containing a `[mount]` marker (`.../case.frtriage/[mount]/README.txt`,
  or `.../a.zip/[mount]/b.zip/[mount]/x` for a nested container) is resolved
  directly against the mounted filesystem — bypassing the
  `ResourceProvider`/`CapabilityRegistry` layer entirely, since a lazily-mounted
  filesystem isn't (and doesn't need to be) a registered provider.
- `Limits` (`src/core/limits.rs`) bound nesting depth, total expanded bytes,
  entry count, and expansion ratio across the *whole* resolution (not
  per-container), so a chain of small containers can't each individually pass a
  check and still sum to an unbounded expansion — relevant here because a
  container file is, by definition, attacker-influenced input.
- The example ships `MiniArchiveFactory`, a **toy** `FormatFactory` for a
  trivial text-based container format (see `examples/sample_triage.frtriage`) —
  forensic-rs ships no real zip/E01/OLE parser (that needs a dependency the crate
  deliberately doesn't take on). A real deployment registers a real factory instead;
  the resolver and `[mount]`-path mechanism around it is unchanged.

This is why it wins on both audiences: developers write one reusable piece of
machinery (`MountResolver` + the `mount_uri` hint step) that scales to any
container/interpretation/embedding a `FormatFactory` is registered for, with no
`CapabilityRegistry` mutation and no eager cost; users/LLMs get uniform
`resources/read` browsing no matter how deep, paying a bit of extra latency only
on a container's first access.

The file→registry crossing (a hive file → registry keys) now follows the
*identical* mechanism as file→file, because `FormatFactory`/`Mounted` cover both:
a factory that `yields() -> MountKind::Registry` mounts a hive file the same way
one that `yields() -> MountKind::FileSystem` mounts a zip. What the example
doesn't yet wire up is a second marker (e.g. `[registry]`) in its own
`resources/read` handler to route reads into a mounted `Registry` rather than a
mounted `FileSystem` — the resolver-level machinery is generic across `Mounted`'s
variants; only that one server-side dispatch arm is unbuilt.

## Prioritized Recommendations

Ranked for whenever implementation work on this is taken up — not committed to any
timeline:

1. ~~Wire Resources into the reference example.~~ **Done** — the example registers a
   chrooted `VfsProvider` and serves `resources/list`/`resources/read`.
2. ~~Fix cancellation routing in the reference example~~ — **Done** — `tools/call`
   runs on a worker thread, and `notifications/cancelled` (keyed by `requestId`)
   actually reaches and cancels the matching in-flight invocation.
3. ~~Add `CapabilityValue` conversions for `Finding` and for `Confidence`/
   `Anomalies`~~ — **Done**, in `src/capabilities/value.rs`. This was the
   highest-value item for forensic analysts specifically — it's what makes
   evidentiary trust visible in tool output at all.
3.5. ~~Lazy on-demand mount-and-cache for nested containers (file→file, e.g.
   zip→triage)~~ — **Done**, in `examples/mcp_stdio_server.rs`. See "Nested/
   Cross-Family Resource Design" above. The file→registry crossing (hive→regkey)
   follows the same pattern but isn't built yet.
3.6. ~~Node-scoped commands: let a resource node advertise which registered tools
   apply to it~~ — **Done**, `ResourceProvider::actions()`/
   `ScopedCapabilityRegistry::list_node_actions()`, plus `ProviderHook::action_ids()`/
   `virtual_action_ids()` so a parser/analyzer can attach commands to matched nodes the
   same way hooks already inject virtual children. See
   [Node Actions](./04_tutorial/06_resources.md#node-actions-linking-resources-to-tools).
   Closes the tool↔resource link in the direction `ToolContent::ResourceReference`
   didn't cover (resource → applicable tools). Discovery only — invocation still goes
   through the existing `invoke_tool()`, and no MCP method exists for "list actions on
   a resource", so it isn't wired into `examples/mcp_stdio_server.rs`'s JSON-RPC
   surface.
4. **Consider new `ResourceProvider`-shaped extension points** for prompts, resource
   templates, roots, and protocol-level logging — each fits the existing registry
   pattern without requiring async or an MCP SDK dependency. Not currently
   recommended as a next step: roots is a domain mismatch (forensic evidence sources
   are chosen server-side under access control, not client-designated like an
   editor's open folders), and prompts/resource templates/completion/elicitation are
   generic MCP conveniences that don't touch this crate's actual differentiators
   (evidence access, provenance, access control). Protocol-level logging is the one
   with some merit, but the existing `AccessAuditSink` + local `log` integration
   already cover most of the need. (Node actions, item 3.6 above, was the one
   resource-shaped extension that *did* touch a real differentiator — evidence
   access — which is why it was built ahead of this list rather than left on it.)
5. **Leave sampling and elicitation to server authors**, per the section above — no
   core crate change recommended.
