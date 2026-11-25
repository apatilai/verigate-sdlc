---
name: verigate-change-gate
description: >-
  Vendor-neutral AI-SDLC Continuous Change Gate (Stages 3-6) for bugfixes,
  refactors, and incremental edits across any LLM, OS, or IDE.
---

# VeriGate AI-SDLC Change Gate (Stages 3–6)

Use on every incremental edit, bugfix, or refactor (scoped to `.sdlc/changes/<ticket>/` via `--change <ticket>`, `VERIGATE_CHANGE`, `.sdlc/active-change`, or automatically from a ticket branch like `feature/PROJ-123-...`):

1. **Dispatch**: Run `python3 .sdlc/bin/verigate.py dispatch "<prompt>"` (or `python` on Windows) if not already rendered by a local hook.
2. **S3 Surgical Edit (`verigate-builder`)**: Inspect blast radius and apply minimal, scoped code changes without touching secrets, `.sdlc/active-change`, or `.sdlc/approvals*`.
3. **S4 Verification (`verigate-verifier`)**: Run real unit/integration tests, linters, or Terraform/IaC checks (`terraform validate`, `terraform fmt -check`, `tflint`, `checkov`, `tfsec`, `conftest test`, `opa test`) returning exit code `0` without error-swallowing fallbacks (`|| true`) (`PASS` or logged waiver via `python3 .sdlc/bin/verigate.py waive --project . --stage S4_TEST --reason "<blocker>"`).
4. **S5 Governed Review (`verigate-reviewer` + `verigate-sentinel`)**: Write `review-findings.json` and `review-report.md` in `.sdlc/changes/<ticket>/` (or `.sdlc/`).
5. **S6 Simultaneous Ticket + Fix Prompt**: Present findings and ask the user in one step whether to raise issues in **GitHub / Azure DevOps** AND apply immediate fixes before submitting to PR-scoped CI consistency checks (`validate` / `merge-check`) and human PR approval (**branch protection + `CODEOWNERS` / Required Reviewers on `.sdlc/changes/**`**).
