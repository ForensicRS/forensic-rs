# forensic-rs Agent Guide

Guidance and Claude Code Skills for developers building tools **on top of** `forensic-rs` — not for agents working inside this repo (see this repo's own [`AGENTS.md`](../../AGENTS.md) for that).

## Why this exists

`forensic-rs` ships zero artifact parsers by design — every real capability (registry/filesystem/SQL/event-log backends, artifact parsers, analyzers, GUI/EDR/MCP integrations) lives in a downstream crate that implements its traits. This directory packages the review discipline and scaffolding conventions that keep those downstream tools idiomatic *and* forensically sound, as two Claude Code Skills.

## Adopting a skill

Skills here are templates — they are not active in this repo. To use one in your own downstream repo:

```bash
cp -r docs/agent-guide/skills/<skill-name> /path/to/your-repo/.claude/skills/<skill-name>
```

Claude Code auto-discovers any `.claude/skills/*/SKILL.md` in your repo and loads it when its trigger conditions match.

## Available skills

| Skill | Use when |
|---|---|
| [`forensic-rs-tool-review`](./skills/forensic-rs-tool-review/SKILL.md) | Reviewing or writing code in an existing tool that depends on forensic-rs — code quality *and* forensic soundness (fabricated timestamps, swallowed source disagreement, Finding/log/error discipline, adversarial-input handling). |
| [`forensic-rs-new-tool`](./skills/forensic-rs-new-tool/SKILL.md) | Starting a brand-new repo that will implement a forensic-rs trait — what files it needs (README, CHANGELOG, AGENTS.md, CI workflow) and why, with copyable templates. |

## Related docs

- [`docs/mcp-server-guide/`](../mcp-server-guide/README.md) — building an MCP server on top of forensic-rs's capability layer
- This repo's own [`AGENTS.md`](../../AGENTS.md) and [`README.md`](../../README.md) — canonical trait signatures and conventions; the skills here summarize and apply them, they don't replace them
