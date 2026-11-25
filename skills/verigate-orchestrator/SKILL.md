---
name: verigate-orchestrator
description: >-
  Vendor-neutral 6-stage AI-Native SDLC workflow for greenfield products and
  features across any LLM or coding agent. Pairs local agent guide rails
  (SHA-256 intent.md/spec.md checks, real exit-code-0 test/IaC verification)
  with hard CI/PR merge gates in GitHub Actions and Azure Pipelines.
---

# Universal 6-Stage AI-SDLC Orchestrator

Works across **Antigravity, Claude Code, OpenAI Codex, Cursor, GitHub Copilot, Windsurf, Gemini CLI, Windows/macOS/Linux, and CI/CD**.

> **Control Boundary**: Local hooks act as cooperative **agent guide rails** on the developer workstation. In regulated/enterprise environments, actual hard enforcement lives in **Git branch protection, human PR approval, and CI/CD pipeline gates** (`.github/workflows/verigate-gate.yml` / `azure-pipelines.yml`).

## Step 1: Select Per-Change Folder & Render Stage Dispatch Table
- For multi-developer / multi-branch isolation, pass `--change <ticket>` (e.g., `--change PROJ-123`) or set `VERIGATE_CHANGE=PROJ-123` (or `.sdlc/active-change`) so all artifacts live under `.sdlc/changes/<ticket>/` instead of colliding on root `.sdlc/`.
- Run `python3 .sdlc/bin/verigate.py dispatch "<user prompt>"` (or let the active `PreInvocation` / `UserPromptSubmit` hook render it automatically; use `python` on Windows).

## Step 2: Phase A — Left-Side Specification & SHA-256 Human Approval (`S1` + `S2`)
1. **`verigate-requirements`**: Draft `intent.md` (`>= 200` chars, **Scope**, **Constraints / Edge Cases / Non-Goals**, and at least **`AC-1` + `AC-2`**) in `.sdlc/changes/<ticket>/intent.md` (or `.sdlc/intent.md`).
2. **`verigate-architect`**: Draft `spec.md` (`>= 250` chars, **Architecture / Module Boundaries / Contracts**, **Security & Guardrails**, and a **Verification Matrix** referencing `AC-1`) in `.sdlc/changes/<ticket>/spec.md` (or `.sdlc/spec.md`).
3. Validate & request Human Validator SHA-256 content approval (standalone commands, no shell chaining):
   - `python3 .sdlc/bin/verigate.py validate --project . --change <ticket>`
   - `python3 .sdlc/bin/verigate.py approve --project . --change <ticket> --stage S1_S2`

## Step 3: Phase B — Build, Verify & Governed Code Review (`S3`–`S6`)
1. **`verigate-builder`**: Implement modular code matching approved `intent.md` and `spec.md` (delegate to subagents if supported by your host agent, or execute sequentially in single-agent tools).
2. **`verigate-verifier`**: Run **real** automated tests or Terraform/IaC checks (`terraform validate`, `terraform fmt -check`, `terraform test`, `tflint`, `checkov`, `tfsec`, `conftest test`, `opa test`) returning exit code `0` per `AC-*` (placeholder echoes or subagent-only runs do not count). If blocked by a missing tool/runtime, request a logged waiver:
   `python3 .sdlc/bin/verigate.py waive --project . --change <ticket> --stage S4_TEST --reason "<exact blocker>"`
3. **`verigate-reviewer` + `verigate-sentinel`**: Audit diffs against `.sdlc/REVIEW.md`, write `review-findings.json` + `review-report.md` in the active change folder, and present the **Executive Review Scorecard**.
4. **Stage 6 Dual-Action Triage**: Ask the user simultaneously (1) whether to raise issues in **GitHub Issues** or **Azure DevOps Boards** (`python3 .sdlc/bin/issue_bridge.py create ...`), and (2) which `REV-*` findings to fix immediately.
