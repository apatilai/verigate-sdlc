---
name: verigate-code-review
description: >-
  Runs Stage 5–6 Closed-Loop Code Review -> Fix -> Policy Check
  (Ready to merge) plus simultaneous GitHub Issues / Azure DevOps Work Items
  triage across any LLM.
---

# VeriGate Closed-Loop Code Review, Fix & Merge Policy Gate

Implements the **Review ⇄ Fix ➔ Verify ➔ Policy Check (Ready to merge)** loop governed by `.sdlc/REVIEW.md`, `.sdlc/policy.json`, and `verigate.json` / `.sdlc/config.json` (`gated_paths`), backed by Git `pre-commit`/`pre-push` and the **pinned PR pipeline (`verigate ci-check`)** in `.github/workflows/verigate-gate.yml` and `azure-pipelines.yml`:

1. **Detect Remote Tracker**:
   `python3 .sdlc/bin/issue_bridge.py detect --repo .`
2. **Stage 5 — Governed Code Review (`verigate-reviewer`)**:
   Audit diffs (especially files matching `gated_paths` in `verigate.json` / `.sdlc/config.json`) against `.sdlc/REVIEW.md` and the active `spec.md`, persisting `review-findings.json` and `review-report.md` in `.sdlc/changes/<ticket>/` (resolved from `--change <ticket>`, `VERIGATE_CHANGE`, `.sdlc/active-change`, or git branch name via `change_id.branch_pattern`, e.g. `feature/PROJ-123-...`) or `.sdlc/`.
3. **Simultaneous Dual-Action Triage**:
   Display the **Executive Review Scorecard** (`REV-001..REV-N`) and ask the user **both questions simultaneously**:
   - **Action A — Tracker**: Raise Critical/High or ALL findings in **GitHub Issues** (`gh`) or **Azure DevOps Work Items** (`az boards`) via `python3 .sdlc/bin/issue_bridge.py create ...`, or keep local report only.
   - **Action B — Recursive Review ⇄ Fix Loop**: Fix findings via `verigate-builder`, re-run **`python3 .sdlc/bin/verigate.py verify --project .`** (`verigate-verifier`) to refresh commit-bound `verify-result.json`, and **re-run `verigate-reviewer`** iteratively (`2 findings -> fix -> 1 finding -> fix -> 0 findings ✓`, up to `max_review_fix_cycles` in `.sdlc/policy.json`).
4. **Stage 6 — Local Pre-Check & Pinned PR Pipeline (`Ready to merge`)**:
   Once `verigate-reviewer` reaches **`0 open findings`** (`APPROVE`), run:
   - `python3 .sdlc/bin/verigate.py verify --project .` (produces commit-bound `verify-result.json` for Git `pre-push`)
   - `python3 .sdlc/bin/verigate.py merge-check --project .` (adding `--change <ticket>` when using a per-change folder)
   In CI, the **pinned PR pipeline** executes **`verigate ci-check`** from a pinned release tag (never from the untrusted PR branch), **recomputes all configured `gated_paths` verify commands from scratch** without trusting laptop `verify-result.json`, and validates `.sdlc/changes/<ticket>/` consistency. Real human approval is enforced by **branch protection + GitHub `CODEOWNERS` / Azure DevOps Required Reviewers on `.sdlc/changes/**`**.
