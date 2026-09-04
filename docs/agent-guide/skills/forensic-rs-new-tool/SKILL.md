---
name: forensic-rs-new-tool
description: This skill should be used when the user asks to "start a new forensic-rs tool", "scaffold a forensic-rs crate", "create a new artifact parser repo", "what does a forensic-rs tool need", or is setting up a brand-new repository that will depend on the forensic-rs crate (a Registry/FileSystem/SqlStatement/EventLogReader backend, an ArtifactParserFactory, or an analyzer).
version: 0.1.0
---

# Scaffolding a New forensic-rs Tool

Apply this skill when setting up a brand-new repository that implements one or more `forensic-rs` traits (`Registry`, `FileSystem`, `SqlStatement`/`ForensicDb`, `EventLogReader`, `ArtifactParserFactory`) or otherwise depends on the crate. The goal is a repo that fits into the forensic-rs ecosystem cleanly from the first commit, not a generic Rust crate that happens to import forensic-rs.

Copy the templates in `assets/` and fill in the `{{...}}` placeholders rather than writing these files from scratch — they already match this ecosystem's conventions.

## What a new repo needs, and why

**`Cargo.toml`** — depend on `forensic-rs`; keep `edition`/`rust-version` compatible with the framework (`edition = "2024"`, `rust-version = "1.85"` as of forensic-rs 0.14.0 — verify against the current `Cargo.toml` before relying on this, since it will drift). State clearly in the crate description which trait(s) it implements.

**`README.md`** (`assets/README.md.template`) — state which trait(s) the crate implements and the decoupling story: does an analyzer built against it run unmodified on a live system, a parsed image, and a mock? That is the framework's core value proposition, and a downstream README that doesn't lead with it loses the main reason to depend on forensic-rs instead of writing bespoke access code.

**`CHANGELOG.md`** (`assets/CHANGELOG.md.template`) — Keep a Changelog format plus Semantic Versioning, matching forensic-rs's own `CHANGELOG.md` header exactly, so anyone auditing the ecosystem's release history reads the same format everywhere.

**`AGENTS.md`** (`assets/AGENTS.md.template`) — a per-repo agent guide analogous to forensic-rs's own `AGENTS.md`: module map, error-handling conventions inherited from `ForensicResult`/`ForensicError`, naming conventions, testing patterns. Point it at the `forensic-rs-tool-review` skill explicitly, so forensic-soundness review discipline carries over automatically once that skill is copied in — don't duplicate that skill's content inside the new repo's `AGENTS.md`.

**CI workflow** (`assets/ci-rust.yml.template`) — `cargo test --verbose` across `ubuntu-latest`/`windows-latest`/`macos-latest`, matching the spirit of forensic-rs's own `.github/workflows/rust.yml` (updated to non-deprecated actions — see the template's header comment). Registry- and filesystem-backed tools especially benefit from testing on all three OSes, since path and case-sensitivity semantics differ across them.

**Tests** — use `forensic_rs::utils::testing` doubles (`TestingRegistry`, `InMemoryVirtualFileSystem`, `TestingEventLogReader`/`basic_event_log()`) instead of a mocking library or the live OS. These doubles already model realistic hierarchies and are what the rest of the ecosystem's tests are written against.

**Optional, but note for community-facing tools:** a `LICENSE` (MIT is the ecosystem convention — forensic-rs and its known downstream libraries all use it), and `CONTRIBUTING.md`/`CODE_OF_CONDUCT.md` if the repo will take outside contributions.

## Last step: adopt the review skill

Copy `docs/agent-guide/skills/forensic-rs-tool-review/` from the forensic-rs repo into the new repo's own `.claude/skills/forensic-rs-tool-review/`. This gives every future review or PR in the new repo the forensic-soundness lens (fabricated timestamps, swallowed source disagreement, Finding/log/error discipline, adversarial-input handling) without re-deriving it each time.

## Additional resources

### Asset templates

- **`assets/README.md.template`** — README skeleton stating the trait(s) implemented and the decoupling story
- **`assets/CHANGELOG.md.template`** — Keep a Changelog / SemVer skeleton
- **`assets/AGENTS.md.template`** — per-repo agent guide skeleton, pre-wired to point at the review skill
- **`assets/ci-rust.yml.template`** — three-OS `cargo test` GitHub Actions workflow
