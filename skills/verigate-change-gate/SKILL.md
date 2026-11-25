---
name: verigate-change-gate
description: >-
  Vendor-neutral AI-SDLC Continuous Change Gate (Stages 3-6) for bugfixes,
  refactors, and incremental edits across any LLM, OS, or IDE.
---

# VeriGate AI-SDLC Change Gate (Stages 3–6)

Use on every incremental edit, bugfix, or refactor (optionally scoped with `--change <ticket>` / `VERIGATE_CHANGE` to isolate `.sdlc/changes/<ticket>/`):

1. **Dispatch**: Run `python3 .sdlc/bin/verigate.py dispatch "<prompt>"` (or `python` on Windows) if not already rendered by a local hook.
2. **S3 Surgical Edit (`verigate-builder`)**: Inspect blast radius and apply minimal, scoped code changes without touching secrets or `.sdlc/approvals*`.
3. **S4 Verification (`verigate-verifier`)**: Run real unit/integration tests, linters, or Terraform/IaC checks (`terraform validate`, `terraform fmt -check`, `tflint`, `checkov`, `tfsec`, `conftest test`, `opa test`) returning exit code `0` (`PASS` or logged waiver via `python3 .sdlc/bin/verigate.py waive --project . --stage S4_TEST --reason "<blocker>"`).
4. **S5 Governed Review (`verigate-reviewer` + `verigate-sentinel`)**: Write `review-findings.json` and `review-report.md` in `.sdlc/changes/<ticket>/` (or `.sdlc/`).
5. **S6 Simultaneous Ticket + Fix Prompt**: Present findings and ask the user in one step whether to raise issues in **GitHub / Azure DevOps** AND apply immediate fixes before submitting to PR/CI merge gates.
