---
name: verigate-orchestrator
description: >-
  Vendor-neutral 6-stage AI-Native SDLC workflow for greenfield products and
  features across any LLM or coding agent. Pairs local agent guide rails
  (SHA-256 intent.md/spec.md checks, real exit-code-0 test/IaC verification)
  with hard CI/PR merge gates in GitHub Actions and Azure Pipelines.
---

# Universal 6-Stage AI-SDLC Orchestrator

Works with any repo and any tool — **humans, Claude, Antigravity, Codex, Cursor, Windsurf, Copilot, Gemini CLI, or multi-agent swarms** — because VeriGate v3.0 gates at **Git `pre-commit`/`pre-push`**, the **pinned PR pipeline (`verigate ci-check`)**, and **PR `CODEOWNERS`**, with AI-tool hooks as optional early-feedback adapters.

> **Control Boundary**: Optional local AI hooks provide edit-time feedback. Core enforcement runs across three layers: (1) **Git `pre-commit` & `pre-push`** (enforcing required change folders on `verigate.json` / `.sdlc/config.json` `gated_paths` and fresh commit-bound `verify-result.json`), (2) **Pinned PR Pipeline (`verigate ci-check`)** running from a pinned release tag and recomputing all checks from scratch without trusting laptop artifacts, and (3) **Git branch protection + GitHub `CODEOWNERS` / Azure DevOps Required Reviewers on `.sdlc/changes/**`** for authoritative human approval.

## Step 1: Inspect `gated_paths`, Select Per-Change Folder & Render Stage Dispatch Table
- Inspect `verigate.json` / `.sdlc/config.json` (`gated_paths`, `require_change_folder_for_gated_paths`, `fail_on_missing_tool`, `change_id.branch_pattern`).
- For multi-developer / multi-branch isolation, VeriGate resolves the active change ID from `--change <ticket>`, `VERIGATE_CHANGE`, `.sdlc/active-change` (protected governance file), or automatically from the **git branch name** (e.g., `feature/PROJ-123-auth` → `.sdlc/changes/PROJ-123/`) so artifacts never collide on root `.sdlc/`.
- Run `python3 .sdlc/bin/verigate.py dispatch "<user prompt>"` (or let an optional `PreInvocation` / `UserPromptSubmit` hook render it automatically; use `python` on Windows).

## Step 2: Phase A — Left-Side Specification & SHA-256 Approval Consistency (`S1` + `S2`)
1. **`verigate-requirements`**: Draft `intent.md` (`>= 200` chars, **Scope**, **Constraints / Edge Cases / Non-Goals**, and at least **`AC-1` + `AC-2`**) in `.sdlc/changes/<ticket>/intent.md` (or `.sdlc/intent.md`).
2. **`verigate-architect`**: Draft `spec.md` (`>= 250` chars, **Architecture / Module Boundaries / Contracts**, **Security & Guardrails**, and a **Verification Matrix** referencing `AC-1` and aligned with `gated_paths[].verify`) in `.sdlc/changes/<ticket>/spec.md` (or `.sdlc/spec.md`).
3. Run artifact consistency validation & record SHA-256 content hashes (standalone commands, no shell chaining; real human approval is enforced via PR `CODEOWNERS` / Required Reviewers on `.sdlc/changes/**`):
   - `python3 .sdlc/bin/verigate.py validate --project . --change <ticket>`
   - `python3 .sdlc/bin/verigate.py approve --project . --change <ticket> --stage S1_S2`

## Step 3: Phase B — Build, Verify (`verigate verify`) & Governed Code Review (`S3`–`S6`)
1. **`verigate-builder`**: Implement modular code matching approved `intent.md` and `spec.md` (delegate to subagents if supported by your host agent, or execute sequentially in single-agent tools).
2. **`verigate-verifier`**: Run **`python3 .sdlc/bin/verigate.py verify --project . --change <ticket>`** to execute configured `gated_paths[].verify` commands directly, fail closed on missing tools (`fail_on_missing_tool: true`), and write commit-bound **`verify-result.json`** (`head_commit` + `tree_digest`) required by Git `pre-push`. Also run any additional test/lint/IaC checks needed to cover every `AC-*` (placeholder echoes, `pip install pytest`, `pytest || true`, or subagent-only runs do not count). If genuinely blocked by a missing runtime, request a logged waiver:
   `python3 .sdlc/bin/verigate.py waive --project . --change <ticket> --stage S4_TEST --reason "<exact blocker>"`
3. **`verigate-reviewer` + `verigate-sentinel`**: Audit diffs against `.sdlc/REVIEW.md` and `gated_paths`, write `review-findings.json` + `review-report.md` in the active change folder, and present the **Executive Review Scorecard**.
4. **Stage 6 Dual-Action Triage**: Ask the user simultaneously (1) whether to raise issues in **GitHub Issues** or **Azure DevOps Boards** (`python3 .sdlc/bin/issue_bridge.py create ...`), and (2) which `REV-*` findings to fix immediately before pushing to the **pinned PR pipeline (`verigate ci-check`)**.
