# VeriGate AI-SDLC (`verigate-sdlc` v3.2)

**Works with any repo and any tool — humans, Claude, Antigravity, Codex, Cursor, or multi-agent swarms — because VeriGate gates at Git commit/push and the PR pipeline, not inside an AI tool.**

VeriGate v3.2 is a zero-dependency, config-driven **6-Stage AI-SDLC Framework** anchored in **Git hooks (`pre-commit` / `pre-push`)**, a **pinned PR CI pipeline (`verigate ci-check`)**, and **PR reviewer approval** (GitHub `CODEOWNERS` / Azure Repos Automatically Included Reviewers). Optional AI-tool hooks can be added for earlier edit-time feedback, while full enforcement works even with **zero AI hooks installed**.

---

## Three-Layer Control Architecture

VeriGate separates local developer workflow gates from authoritative server-side compliance controls:

| Layer | Mechanism | What It Enforces | Control Boundary |
| :--- | :--- | :--- | :--- |
| **1. Git `pre-commit` & `pre-push`** | `.githooks/pre-commit` (`git-pre-commit`) and `.githooks/pre-push` (`git-pre-push`) | **`pre-commit`** blocks commits touching configured `gated_paths` without a required change folder (`.sdlc/changes/<ticket>/{intent.md,spec.md}`) and valid `S1_S2` SHA-256 approvals, plus blocks secret files. **`pre-push`** blocks pushes unless `<art_dir>/verify-result.json` has `passed: true`, matches current `head_commit`, and matches the current `tree_digest` of gated files (or a logged waiver exists). | **Local workflow gate** (works for humans and every AI tool without IDE plugins; advisory in regulated audits because local hooks can be bypassed with `--no-verify`). |
| **2. Pinned PR Pipeline (`verigate ci-check`)** | `.github/workflows/verigate-gate.yml` (PR trigger) and `azure-pipelines.yml` (`pr: none`, attached via Azure Repos **Branch Policies → Build Validation**) checking out a **pinned release tag** (`VERIGATE_REF`, e.g. `v3.2.0`) | Runs VeriGate from the **pinned release checkout** (never executing `.sdlc/bin/verigate.py` from the untrusted PR branch) and **loads `verigate.json` / `.sdlc/config.json` / `.sdlc/policy.json` from the target base branch (`--base`)** so a PR cannot weaken its own rules. Inspects PR-touched files against `gated_paths`, enforces required change folders and `HEAD` SHA-256 spec approvals, **recomputes all matching `verify` commands from scratch** (never trusting laptop `verify-result.json`), fails closed when a required tool is missing (`fail_on_missing_tool: true`), and requires `review-findings.json` (`require_review_in_ci: true` by default) to pass `merge-check`. | **Authoritative automated gate** at the CI/CD pipeline boundary. |
| **3. PR Approval (`CODEOWNERS` / Azure Repos Automatically Included Reviewers)** | GitHub `CODEOWNERS` + Branch Protection / Azure Repos **Branch Policies → Automatically Included Reviewers (`/.sdlc/changes/*`)** | Requires named human reviewer sign-off on `.sdlc/changes/<ticket>/{intent.md,spec.md}` before merge. | **Authoritative human approval boundary** for SOC 2, PCI-DSS, and regulated/banking audits. |

### Honest Pipeline & Human Approval Framing (`CODEOWNERS` Required)

`verigate.py validate`, `verigate.py merge-check`, and `verigate.py ci-check` verify **artifact consistency, completeness, and freshly recomputed check results** — proving that `intent.md`, `spec.md`, SHA-256 hashes in `approvals.json`, review artifacts, and configured verification commands all pass on the PR commit. Because any developer or agent with branch commit access can run `verigate.py approve` locally, CLI hashes alone **do not** prove a specific human clicked approve.

Configure **GitHub `CODEOWNERS`** or **Azure DevOps Required Reviewers** on `.sdlc/changes/**` with **branch protection** so a named human reviewer must approve the plan on the PR:

```text
# .github/CODEOWNERS (or Azure DevOps Branch Policy -> Automatically Included Reviewers)
/.sdlc/changes/**    @org/tech-leads @org/security-reviewers
```

---

## Per-Repo Declarative Config (`verigate.json` / `.sdlc/config.json`)

Configure gating rules per repository in repo-root **`verigate.json`** (or **`.sdlc/config.json`** as fallback). Customer-defined `gated_paths` control which paths require a change folder and which real verification commands run for each path:

```json
{
  "version": "3.0.0",
  "require_spec_approval": true,
  "require_change_folder_for_gated_paths": true,
  "fail_on_missing_tool": true,
  "change_id": {
    "branch_pattern": "([A-Z][A-Z0-9]{1,10}-\\d+)"
  },
  "gated_paths": [
    {
      "pattern": "terraform/**",
      "verify": ["terraform fmt -check", "terraform validate", "tflint"],
      "cwd": "terraform"
    },
    {
      "pattern": "services/**",
      "verify": ["pytest -q"],
      "cwd": "."
    },
    {
      "pattern": "src/**",
      "verify": ["python3 -m unittest discover -s tests"],
      "cwd": "."
    }
  ],
  "approvers": {
    "codeowners_paths": [".sdlc/changes/**"],
    "required_reviewers": ["@org/tech-leads", "@org/security-reviewers"]
  },
  "tracker": {
    "provider": "auto",
    "min_severity": "High"
  }
}
```

### Key Config Fields

- **`gated_paths`**: List of `{ "pattern", "verify", "cwd" }` rules using normalized glob patterns (`**`, `*`, `?`). Each `verify` entry may be a command string (Windows paths like `C:\Python314\python.exe -m unittest` are preserved via non-POSIX splitting) **or** a list of argv strings. Use the portable **`{python}`** token (e.g. `["{python}", "-m", "pytest", "-q", "-o", "pythonpath=src"]`) so `verigate.json` resolves to `sys.executable` automatically across Windows, macOS, and Linux without hardcoding machine-specific paths. Non-gated paths (e.g., `docs/notes.md`) are not blocked by gated-path rules. If omitted, VeriGate falls back to matching non-meta project files (and retains backward compatibility with `terraform_dirs`).
- **`require_change_folder_for_gated_paths`**: Defaults to `true` when `gated_paths` is configured or `require_spec_approval` is `true`. Touching any gated path without `.sdlc/changes/<ticket>/{intent.md,spec.md}` **fails closed** in `git-pre-commit` and `ci-check` — omitting a change folder is never a bypass.
- **`fail_on_missing_tool`**: Defaults to `true`. If a configured `verify` binary is missing (`FileNotFoundError` / exit `127`), verification **fails closed** instead of silently passing. Set to `false` only if you intentionally want missing binaries recorded as `skipped_missing_tool: true`.
- **`change_id.branch_pattern`**: Regex used to auto-derive the ticket/change ID from the Git branch name (e.g., `feature/PROJ-123-auth` → `PROJ-123`).
- **`approvers`**: Documents `codeowners_paths` (default `[".sdlc/changes/**"]`) and `required_reviewers` for PR review policy alignment.
- **`tracker`**: Default issue tracker settings (`provider`: `auto` | `github` | `azdo`, `min_severity`: `Critical` | `High` | `Medium` | `Low`).

---

## Real Execution & Commit-Bound Proof (`verigate verify`)

Instead of scraping chat logs or trusting subagent claims, **`verigate verify`** executes configured commands directly and binds the result to the exact repository state:

```bash
# Run all configured gated_paths verification commands
python3 .sdlc/bin/verigate.py verify --project .

# Scope to a specific change ID or specific changed files
python3 .sdlc/bin/verigate.py verify --project . --change PROJ-123 --files services/api.py,src/app.py
```

How `verigate verify` works:
1. Matches changed/staged/specified files (or all rules when `--files` is omitted) against `gated_paths` in `verigate.json` / `.sdlc/config.json`.
2. Runs each configured `verify` command directly with `subprocess.run(..., shell=False)` in the rule's `cwd` and captures the **real OS exit code**.
3. **Fails closed on missing tools**: If a required binary is not installed, marks `missing_tool: true` and fails (`exit 1`) whenever `fail_on_missing_tool: true`.
4. Writes commit-bound **`<art_dir>/verify-result.json`** containing:
   - `head_commit`: current `git rev-parse HEAD` (or `"UNCOMMITTED"`)
   - `tree_digest`: SHA-256 digest over sorted `(rel_path, file_sha256)` of all gated/target files
   - `passed`, `change_id`, `fail_on_missing_tool`, `timestamp`, and per-command `results` (`pattern`, `command`, `cwd`, `exit_code`, `missing_tool`, `passed`, `duration_ms`, `stdout_tail`, `stderr_tail`).
5. **Verified at `git push`**: `.githooks/pre-push` checks pushed files (or `<merge-base>..HEAD` against `origin/main` / `main` on new branches with no upstream yet) and rejects pushes if `verify-result.json` is missing, `passed` is `false`, `head_commit` does not match `HEAD`, or any gated file changed after verification (`tree_digest` mismatch). If `review-findings.json` exists (or `require_review_in_pre_push: true` is set in `.sdlc/policy.json`), `.githooks/pre-push` also enforces the Stage 5 review policy (0 open findings, substantive summary, and matching `reviewed_tree_digest`). `install_verigate.py` automatically adds `verify-result.json` to `.gitignore` so running `verigate verify` after committing never dirties the working tree.

### Verify Your Gate Works (Deliberate-Break Smoke Test)

A gate is only as trustworthy as its `verify` command. A common setup trap in Python or monorepo projects is running tests against a globally installed copy of the package instead of the repository's own `src/` tree (so breaking `src/` still passes). After installing VeriGate and configuring `verigate.json`:

1. Prefer `["{python}", "-m", "pytest", "-q", "-o", "pythonpath=src"]` (or your language's equivalent local-source test invocation) so tests always import the working tree's code.
2. **Prove the gate catches a real break**: temporarily introduce a deliberate syntax or logic error in a gated file under `src/`, run `verigate verify`, and confirm it exits non-zero before reverting the break.

---

## Pinned PR Pipeline (`verigate ci-check`)

CI workflows generated by `install_verigate.py` (`--targets ci` or `--targets azdo-ci`) **never execute `.sdlc/bin/verigate.py` from the untrusted PR branch**. Instead, they check out VeriGate from a **pinned release tag** (`VERIGATE_REF`, default `v3.2.0`) into an isolated runner temp directory and invoke `ci-check`:

```bash
python3 "$VERIGATE_BIN/verigate.py" ci-check --project . --base "origin/$BASE"
```

What `verigate ci-check` enforces on every PR:
1. **Loads `verigate.json` / `.sdlc/config.json` and `.sdlc/policy.json` from the target base branch (`--base`)** via `git show <base>:...`, preventing a PR from removing `gated_paths` or loosening policy on itself. **Fails closed** if `--base` cannot be resolved or if the base branch's config/policy JSON is malformed; falls back to the working tree (`working_tree_fallback`) **only** when `--base` resolves cleanly and has no config file yet (first-adoption PR).
2. Computes PR-touched files (`git diff --name-only <base>...HEAD`) and matches them against `gated_paths`.
3. **Never trusts laptop `verify-result.json`** — even if a PR commits a forged `"passed": true` file, CI **recomputes every matching `verify` command from scratch** on the CI runner, failing closed on missing tools (`fail_on_missing_tool: true`) and on gated path rules with an empty `verify` list (unless `"allow_empty_verify": true` is explicitly set).
4. Enforces the required change folder (`.sdlc/changes/<ticket>/{intent.md,spec.md}`) whenever gated paths are touched and `require_change_folder_for_gated_paths` is `true`.
5. Validates `intent.md` and `spec.md` content standards and `HEAD` SHA-256 approval consistency.
6. Enforces `review-findings.json` presence and `merge-check` policy consistency (`require_review_in_ci: true` by default in `.sdlc/policy.json`; omitting `review-findings.json` fails `ci-check`).

---

## Quick Start (Drop Into Any New or Existing Repository)

```bash
git clone https://github.com/apatilai/verigate-sdlc.git

# Preview every file that would be created, updated, or backed up (writes nothing)
python3 verigate-sdlc/install_verigate.py \
  --target /path/to/your-project \
  --targets git,ci \
  --verigate-ref v3.2.0 \
  --dry-run

# Minimal core install (Git pre-commit + pre-push + Pinned CI workflows — zero AI hooks needed)
python3 verigate-sdlc/install_verigate.py \
  --target /path/to/your-project \
  --targets git,ci \
  --verigate-ref v3.2.0 \
  --activate-git-hooks

# Full install (Core Git + Pinned CI + optional AI-tool early-feedback adapters)
python3 verigate-sdlc/install_verigate.py \
  --target /path/to/your-project \
  --targets all \
  --verigate-ref v3.2.0 \
  --activate-git-hooks
```

### Safe Upgrades, Pinning & Cross-Platform Notes

- **Pinned CI release flags**: Pass `--verigate-ref <tag-or-sha>` (default `v3.2.0`) and `--verigate-repo <git-url>` to control which trusted VeriGate release GitHub Actions (`.github/workflows/verigate-gate.yml`) and Azure Pipelines (`azure-pipelines.yml` or `.azure-pipelines/verigate-gate.yml`) check out.
- **No `sh -c` dependency**: Optional AI hook configs invoke Python directly (`python` on Windows, `python3` on macOS/Linux) so they work natively on Windows PowerShell/CMD without Git Bash or WSL. Pass `--python-cmd <path>` to pin a specific interpreter.
- **Subdirectory-safe paths**: `.githooks/pre-commit` and `.githooks/pre-push` resolve `git rev-parse --show-toplevel`; `.claude/settings.json` uses `"$CLAUDE_PROJECT_DIR/.sdlc/bin/verigate.py"`.
- **Backups & fail-closed JSON merge**: Pre-existing files are backed up to `.sdlc/backups/<UTC-timestamp>/<rel_path>` before modification (use `--no-backup` to opt out). Malformed JSON in existing `.claude/settings.json` or `.agents/hooks.json` **fails closed** instead of overwriting user settings.

---

## Optional Early-Feedback Adapters (AI-Tool Hooks & Rules)

Full VeriGate gating works with **zero AI hooks installed** because enforcement happens at **Git `pre-commit`/`pre-push` + Pinned PR Pipeline (`ci-check`) + `CODEOWNERS`**. Teams using AI coding tools can optionally install tool-specific adapters (`--targets all` or individual targets) to catch mistakes earlier at **edit time** rather than waiting for commit or push:

| Optional Adapter | Generated Files | Early-Feedback Behavior |
| :--- | :--- | :--- |
| **Claude Code** (`claude`) | `CLAUDE.md`, `.claude/settings.json`, `.claude/agents/*`, `.claude/skills/*` | Edit-time `UserPromptSubmit`, `PreToolUse` (`Write\|Edit\|MultiEdit\|NotebookEdit\|Bash\|PowerShell`), `PostToolUse` (`...\|Agent\|Task`), and non-trapping `Stop` guide rails via `$CLAUDE_PROJECT_DIR`. |
| **Google Antigravity & Gemini CLI** (`antigravity`, `gemini`) | `GEMINI.md`, `AGENTS.md`, `.agents/hooks.json`, `.agents/skills/*` | Edit-time `PreInvocation`, `PreToolUse`, `PostToolUse`, `Stop` guide rails (direct Python invocation, no `sh -c`). |
| **OpenAI Codex** (`codex`) | `AGENTS.md`, `.agents/skills/*` | Repo-level instructions and skills paired with Git `pre-commit`/`pre-push` + Pinned CI. |
| **Cursor & Windsurf** (`cursor`, `windsurf`) | `.cursor/rules/verigate.mdc`, `.windsurfrules`, `AGENTS.md` | Always-on editor rules paired with Git `pre-commit`/`pre-push` + Pinned CI. |
| **GitHub Copilot** (`copilot`) | `.github/copilot-instructions.md` | Copilot repo instructions paired with Git `pre-commit`/`pre-push` + Pinned CI. |
| **Humans / Any Other LLM / Multi-Agent Swarms** (`git,ci`) | `.githooks/pre-commit`, `.githooks/pre-push`, CI workflow templates, `.sdlc/bin/verigate.py` | Full 3-layer Git + Pinned CI + `CODEOWNERS` enforcement with **zero AI hooks required**. |

- **Live hook payload debugging (`VERIGATE_DEBUG_HOOK=1`)**: Export `VERIGATE_DEBUG_HOOK=1` to append sanitized hook event metadata to `hook_debug.jsonl` in VeriGate's local state directory.
- **Claude Code `Stop` reminder notice**: When the optional Claude Code `Stop` adapter reminds an agent to run `verigate verify` or review before finishing, Claude Code displays the message under its built-in `"Stop hook error occurred"` header prefixed with **`[VeriGate Guide Rail — Not a crash]`**. This is an intentional, non-trapping 1-intercept reminder (with a logged circuit breaker), not a hook crash.

### Known Limits (Advisory Local Hooks)

Optional local AI-tool hooks (and shell/PowerShell write detection heuristics) are **cooperative early-feedback guide rails** rather than an OS sandbox. Lightweight quote-aware regex checks avoid false alarms on read-only commands (such as `git log --format="%h -> %s"` or `python -c "print(1>0)"`), and intentionally do **not** intercept every possible script or binary write path, including:

- Arbitrary scripts or binaries performing file I/O (e.g., `python gen.py`)
- Inline Python `pathlib` writes (e.g., `Path.write_text(...)`)
- Patch application commands (`git apply`)
- PowerShell `New-Item`
- Network download-to-file commands (`curl -o`)

This is why local AI hooks are strictly optional early-feedback adapters, while authoritative enforcement lives in **Git `pre-commit`/`pre-push` + Pinned PR Pipeline (`verigate ci-check`) + `CODEOWNERS` / Branch Protection**.

---

## Per-Change Ticket Folders (`.sdlc/changes/<ticket>/`) & Branch Auto-Detection

To prevent merge conflicts across concurrent branches, scope all VeriGate artifacts (`intent.md`, `spec.md`, `approvals.json`, `verify-result.json`, `waivers.jsonl`, `review-findings.json`, `review-report.md`) to a per-change folder.

VeriGate resolves the active change ID in this order:
1. Explicit `--change <ticket>` CLI flag
2. `VERIGATE_CHANGE` environment variable
3. `.sdlc/active-change` file (protected governance file)
4. **Git branch name auto-derivation**: matches `change_id.branch_pattern` from `verigate.json` / `.sdlc/config.json` (default `([A-Z][A-Z0-9]{1,10}-\d+)`, e.g., `feature/PROJ-123-auth` → `.sdlc/changes/PROJ-123/`, skipping `main`, `master`, and detached `HEAD`).

---

## Specification Content Standards (v3.0)

`verigate.py validate` and `verigate.py ci-check` enforce structural completeness and SHA-256 approval integrity:

- **`intent.md`** (`.sdlc/changes/<ticket>/intent.md` or `.sdlc/intent.md`):
  - At least **200 characters**
  - Includes a **Scope / Goal / Problem** section
  - Includes a **Constraints / Edge Cases / Non-Goals** section
  - Includes at least **`AC-1` and `AC-2`** (numbered, machine-testable acceptance criteria)
- **`spec.md`** (`.sdlc/changes/<ticket>/spec.md` or `.sdlc/spec.md`):
  - At least **250 characters**
  - Includes an **Architecture / Module Boundaries / Contracts** section
  - Includes a **Security & Guardrails** section
  - Includes a **Verification Matrix** referencing `AC-1` (mapping all `AC-*` to concrete automated checks)

---

## Core Portable CLI Commands (`.sdlc/bin/`)

```bash
# 1. Print 6-stage agent dispatch plan for any prompt
python3 .sdlc/bin/verigate.py dispatch "Build a multi-tenant billing API"

# 2. Validate intent.md + spec.md & record S1_S2 SHA-256 hashes (per ticket)
python3 .sdlc/bin/verigate.py validate --project . --change PROJ-123
python3 .sdlc/bin/verigate.py approve --project . --change PROJ-123 --stage S1_S2 --approver "tech-lead"

# 3. Execute configured gated_paths verify commands & write commit-bound verify-result.json
python3 .sdlc/bin/verigate.py verify --project . --change PROJ-123

# 4. Record a logged waiver when a tool or environment is genuinely unavailable
python3 .sdlc/bin/verigate.py waive --project . --change PROJ-123 --stage S4_TEST --reason "Database container offline"

# 5. Bind review-findings.json to the reviewed gated files & run merge-policy check
python3 .sdlc/bin/verigate.py stamp-review --project . --change PROJ-123
python3 .sdlc/bin/verigate.py merge-check --project . --change PROJ-123

# 6. Run full PR pipeline gate (recomputes verify commands from scratch; used by pinned CI)
python3 .sdlc/bin/verigate.py ci-check --project . --base origin/main --change PROJ-123

# 7. Preview or create GitHub Issues / Azure DevOps Work Items from review-findings.json
python3 .sdlc/bin/issue_bridge.py detect --repo .
python3 .sdlc/bin/issue_bridge.py preview --findings .sdlc/changes/PROJ-123/review-findings.json --provider auto
python3 .sdlc/bin/issue_bridge.py create --findings .sdlc/changes/PROJ-123/review-findings.json --provider auto --min-severity High
```
