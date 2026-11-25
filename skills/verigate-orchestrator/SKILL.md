---
name: verigate-orchestrator
description: >-
  Vendor-neutral 6-stage AI-Native SDLC workflow for greenfield products and
  features across any LLM or coding agent. Enforces SHA-256 content-approved
  .sdlc/intent.md and .sdlc/spec.md gates, automated test loops, and governed
  code review with GitHub / Azure DevOps triage.
---

# Universal 6-Stage AI-SDLC Orchestrator

Works identically across **Antigravity, Claude Code, OpenAI Codex, Cursor, GitHub Copilot, Windsurf, Gemini CLI, and CI/CD**.

## Step 1: Render Stage Dispatch Table
Run `python3 .sdlc/bin/verigate.py dispatch "<user prompt>"` (or let the active `PreInvocation` / `UserPromptSubmit` hook render it automatically).

## Step 2: Phase A — Left-Side Specification & SHA-256 Human Approval (`S1` + `S2`)
1. **`verigate-requirements`**: Draft `.sdlc/intent.md` with scope, constraints, edge cases, and `AC-1..AC-N`.
2. **`verigate-architect`**: Draft `.sdlc/spec.md` with module boundaries, schemas/contracts, and the Verification Matrix.
3. Validate & request Human Validator SHA-256 content approval (standalone command, no shell chaining):
   - `python3 .sdlc/bin/verigate.py validate --project .`
   - `python3 .sdlc/bin/verigate.py approve --project . --stage S1_S2`

## Step 3: Phase B — Build, Verify & Governed Code Review (`S3`–`S6`)
1. **`verigate-builder`**: Implement modular code matching approved `.sdlc/intent.md` and `.sdlc/spec.md` (delegate to subagents if supported by your host agent, or execute sequentially in single-agent tools).
2. **`verigate-verifier`**: Run automated tests per `AC-*`. Remediate failures before proceeding; if blocked by a missing tool/runtime, request a logged waiver:
   `python3 .sdlc/bin/verigate.py waive --project . --stage S4_TEST --reason "<exact blocker>"`
3. **`verigate-reviewer` + `verigate-sentinel`**: Audit diffs against `.sdlc/REVIEW.md`, write `.sdlc/review-findings.json` + `.sdlc/review-report.md`, and present the **Executive Review Scorecard**.
4. **Stage 6 Dual-Action Triage**: Ask the user simultaneously (1) whether to raise issues in **GitHub Issues** or **Azure DevOps Boards** (`python3 .sdlc/bin/issue_bridge.py create ...`), and (2) which `REV-*` findings to fix immediately.
