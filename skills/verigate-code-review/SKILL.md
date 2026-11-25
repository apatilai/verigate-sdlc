---
name: verigate-code-review
description: >-
  Runs Stage 5–6 Closed-Loop Code Review -> Fix -> Policy Check
  (Ready to merge) plus simultaneous GitHub Issues / Azure DevOps Work Items
  triage across any LLM.
---

# VeriGate Closed-Loop Code Review, Fix & Merge Policy Gate

Implements the **Review ⇄ Fix ➔ Policy Check (Ready to merge)** loop governed by `.sdlc/REVIEW.md` and `.sdlc/policy.json`, backed by hard server-side PR/CI gates (`.github/workflows/verigate-gate.yml` and `azure-pipelines.yml`):

1. **Detect Remote Tracker**:
   `python3 .sdlc/bin/issue_bridge.py detect --repo .`
2. **Stage 5 — Governed Code Review (`verigate-reviewer`)**:
   Audit diffs against `.sdlc/REVIEW.md` and the active `spec.md`, persisting `review-findings.json` and `review-report.md` in `.sdlc/changes/<ticket>/` (resolved from `--change <ticket>`, `VERIGATE_CHANGE`, `.sdlc/active-change`, or git branch name such as `feature/PROJ-123-...`) or `.sdlc/`.
3. **Simultaneous Dual-Action Triage**:
   Display the **Executive Review Scorecard** (`REV-001..REV-N`) and ask the user **both questions simultaneously**:
   - **Action A — Tracker**: Raise Critical/High or ALL findings in **GitHub Issues** (`gh`) or **Azure DevOps Work Items** (`az boards`) via `python3 .sdlc/bin/issue_bridge.py create ...`, or keep local report only.
   - **Action B — Recursive Review ⇄ Fix Loop**: Fix findings via `verigate-builder`, re-run real tests / IaC checks (`verigate-verifier`), and **re-run `verigate-reviewer`** iteratively (`2 findings -> fix -> 1 finding -> fix -> 0 findings ✓`, up to `max_review_fix_cycles` in `.sdlc/policy.json`).
4. **Stage 6 — Artifact Consistency Pre-Check & Server-Side PR Gate (`Ready to merge`)**:
   Once `verigate-reviewer` reaches **`0 open findings`** (`APPROVE`), run:
   `python3 .sdlc/bin/verigate.py merge-check --project .` (adding `--change <ticket>` when using a per-change folder).
   `validate` and `merge-check` are **artifact consistency & completeness checks** (confirming zero blocking findings, minimum quality score, and matching `S1/S2` SHA-256 hashes, scoped in CI to PR-touched `.sdlc/changes/<ticket>/` folders). Real human approval is enforced by **branch protection + GitHub `CODEOWNERS` / Azure DevOps Required Reviewers on `.sdlc/changes/**`** alongside the CI workflows (`.github/workflows/verigate-gate.yml` and `azure-pipelines.yml`).
