---
name: verigate-code-review
description: >-
  Runs Stage 5–6 Closed-Loop Code Review -> Fix -> Team Policy Approval
  (Ready to merge) plus simultaneous GitHub Issues / Azure DevOps Work Items
  triage across any LLM.
---

# VeriGate Closed-Loop Code Review, Fix & Merge Policy Gate

Implements the **Review ⇄ Fix ➔ Approve (Ready to merge)** loop governed by `.sdlc/REVIEW.md` and `.sdlc/policy.json`:

1. **Detect Remote Tracker**:
   `python3 .sdlc/bin/issue_bridge.py detect --repo .`
2. **Stage 5 — Governed Code Review (`verigate-reviewer`)**:
   Audit diffs against `.sdlc/REVIEW.md` and `.sdlc/spec.md`, persisting `.sdlc/review-findings.json` and `.sdlc/review-report.md`.
3. **Simultaneous Dual-Action Triage**:
   Display the **Executive Review Scorecard** (`REV-001..REV-N`) and ask the user **both questions simultaneously**:
   - **Action A — Tracker**: Raise Critical/High or ALL findings in **GitHub Issues** (`gh`) or **Azure DevOps Work Items** (`az boards`) via `python3 .sdlc/bin/issue_bridge.py create ...`, or keep local report only.
   - **Action B — Recursive Review ⇄ Fix Loop**: Fix findings via `verigate-builder`, re-run tests (`verigate-verifier`), and **re-run `verigate-reviewer`** iteratively (`2 findings -> fix -> 1 finding -> fix -> 0 findings ✓`, up to `max_review_fix_cycles` in `.sdlc/policy.json`).
4. **Stage 6 — Deterministic Team Policy Approval (`Ready to merge`)**:
   Once `verigate-reviewer` reaches **`0 open findings`** (`APPROVE`), run:
   `python3 .sdlc/bin/verigate.py merge-check --project .`
   Verifies zero blocking findings, minimum quality score, and valid `S1/S2` SHA-256 approvals, logging `MERGE_POLICY_APPROVED` and emitting **`READY_TO_MERGE ✅`**.
