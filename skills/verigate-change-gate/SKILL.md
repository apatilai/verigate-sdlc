---
name: verigate-change-gate
description: >-
  Vendor-neutral AI-SDLC Continuous Change Gate (Stages 3-6) for bugfixes,
  refactors, and incremental edits across any LLM, OS, or IDE.
---

# VeriGate AI-SDLC Change Gate (Stages 3–6)

Use on every incremental edit, bugfix, or refactor (scoped to `.sdlc/changes/<ticket>/` via `--change <ticket>`, `VERIGATE_CHANGE`, `.sdlc/active-change`, or automatically from a ticket branch like `feature/PROJ-123-...`):

1. **Dispatch & Gated Paths Check**: Run `python3 .sdlc/bin/verigate.py dispatch "<prompt>"` (or `python` on Windows) if not already rendered by an optional local hook. Check `verigate.json` / `.sdlc/config.json` `gated_paths` — if editing gated paths when `require_change_folder_for_gated_paths` is enabled, ensure `.sdlc/changes/<ticket>/{intent.md,spec.md}` exists and is approved so Git `pre-commit` and PR `ci-check` pass.
2. **S3 Surgical Edit (`verigate-builder`)**: Inspect blast radius and apply minimal, scoped code changes without touching secrets, `.sdlc/active-change`, or `.sdlc/approvals*`.
3. **S4 Verification (`verigate-verifier` + `verigate verify`)**: Run **`python3 .sdlc/bin/verigate.py verify --project .`** (adding `--change <ticket>` when using a per-change folder) to execute configured `gated_paths[].verify` commands directly, fail closed on missing tools (`fail_on_missing_tool: true`), and write commit-bound **`verify-result.json`** (`head_commit` + `tree_digest`) required by Git `pre-push`. Also run any additional unit/integration/IaC checks returning exit code `0` without error-swallowing fallbacks (`|| true`) (`PASS` or logged waiver via `python3 .sdlc/bin/verigate.py waive --project . --stage S4_TEST --reason "<blocker>"`).
4. **S5 Governed Review (`verigate-reviewer` + `verigate-sentinel`)**: Write `review-findings.json` and `review-report.md` in `.sdlc/changes/<ticket>/` (or `.sdlc/`).
5. **S6 Simultaneous Ticket + Fix Prompt**: Present findings and ask the user in one step whether to raise issues in **GitHub / Azure DevOps** AND apply immediate fixes before submitting to the **pinned PR pipeline (`verigate ci-check`**, which recomputes all checks from scratch) and human PR approval (**branch protection + `CODEOWNERS` / Required Reviewers on `.sdlc/changes/**`**).
