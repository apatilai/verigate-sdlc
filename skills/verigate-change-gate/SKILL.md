---
name: verigate-change-gate
description: >-
  Vendor-neutral AI-SDLC Continuous Change Gate (Stages 3-6) for bugfixes,
  refactors, and incremental edits across any LLM or IDE.
---

# VeriGate AI-SDLC Change Gate (Stages 3–6)

Use on every incremental edit, bugfix, or refactor:

1. **Dispatch**: Run `python3 .sdlc/bin/verigate.py dispatch "<prompt>"` if not already rendered by a hook.
2. **S3 Surgical Edit (`verigate-builder`)**: Inspect blast radius and apply minimal, scoped code changes.
3. **S4 Verification (`verigate-verifier`)**: Run unit/integration tests and linters (`PASS` or logged waiver via `python3 .sdlc/bin/verigate.py waive`).
4. **S5 Governed Review (`verigate-reviewer` + `verigate-sentinel`)**: Write `.sdlc/review-findings.json` and `.sdlc/review-report.md`.
5. **S6 Simultaneous Ticket + Fix Prompt**: Present findings and ask the user in one step whether to raise issues in **GitHub / Azure DevOps** AND apply immediate fixes.
