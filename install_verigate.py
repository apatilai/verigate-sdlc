#!/usr/bin/env python3
"""Idempotent, Non-Destructive Multi-LLM Bootstrapper for the VeriGate AI-SDLC Framework.

Safely upserts `<!-- VERIGATE:START -->...<!-- VERIGATE:END -->` blocks into existing Markdown files,
deep-merges JSON hook configs (failing closed on malformed JSON), creates automatic timestamped
backups under `.sdlc/backups/`, and supports `--dry-run` previews without writing to disk.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
import re
import shutil
import stat
import subprocess
import sys
from pathlib import Path

KIT_ROOT = Path(__file__).resolve().parent
MARKER_START = "<!-- VERIGATE:START -->"
MARKER_END = "<!-- VERIGATE:END -->"
AZDO_VERIGATE_MARKER = "# VeriGate AI-SDLC Policy Gate"
DEFAULT_VERIGATE_REF = "v3.1.0"
DEFAULT_VERIGATE_REPO = "https://github.com/apatilai/verigate-sdlc.git"

CLAUDE_PRE_TOOL_MATCHER = "Write|Edit|MultiEdit|NotebookEdit|Bash|PowerShell"
CLAUDE_POST_TOOL_MATCHER = "Write|Edit|MultiEdit|NotebookEdit|Bash|PowerShell|Agent|Task"


def _default_python_cmd() -> str:
    return "python" if os.name == "nt" else "python3"


def _hook_cmd(script_rel: str, adapter: str, event: str, python_cmd: str | None = None) -> str:
    py = (python_cmd or _default_python_cmd()).strip()
    py_tok = f'"{py}"' if " " in py and not (py.startswith('"') and py.endswith('"')) else py
    return f"{py_tok} {script_rel} hook --adapter {adapter} --event {event}"


def _clean_ci_param(value: str, label: str) -> str:
    cleaned = value.strip()
    if not cleaned or "\n" in cleaned or "\r" in cleaned:
        raise ValueError(f"Invalid {label}: must be a non-empty single-line string.")
    return cleaned


def _yaml_dq(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _yaml_sq(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


UNIVERSAL_RULE_BODY = """# Enterprise AI-Native SDLC v3.0 (Git + Pinned PR Pipeline + Optional AI Hooks)

This repository uses the **6-Stage VeriGate AI-Native Software Development Lifecycle (AI-SDLC v3.0)**. VeriGate works with any tool — humans, Claude, Antigravity, Codex, Cursor, Windsurf, Copilot, or multi-agent swarms — because **core enforcement lives at Git commit/push and the PR pipeline**, not inside an AI tool:

- **Layer 1 — Git Hooks (`.githooks/pre-commit` & `.githooks/pre-push`)**: Blocks commits touching configured `gated_paths` without a required `.sdlc/changes/<ticket>/` folder and approved plan, and blocks pushes without a fresh commit-bound `verify-result.json` (`head_commit` + `tree_digest`).
- **Layer 2 — Pinned PR Pipeline (`verigate ci-check`)**: Runs VeriGate from a **pinned release tag** (never from the untrusted PR branch) and **recomputes all configured verification commands from scratch** — never trusting laptop `verify-result.json`, enforcing required change folders for touched gated paths, and failing closed when a required tool is missing.
- **Layer 3 — PR Human Approval (`CODEOWNERS` on `.sdlc/changes/**`)**: Enforces named human reviewer sign-off via GitHub branch protection or Azure DevOps branch policies.
- **Optional AI Tool Hooks (Early-Feedback Adapters)**: IDE/CLI lifecycle hooks (Claude Code, Antigravity/Gemini) catch honest mistakes early at edit time, while full gating works even with zero AI hooks installed.

## 1. Six Stages, Artifacts & Control Layers

| Stage | Role | Verified Artifact | Control Layer / Policy Gate |
| :--- | :--- | :--- | :--- |
| **S1: Plan** | `verigate-requirements` | `.sdlc/changes/<ticket>/intent.md` (or `.sdlc/intent.md`) (`AC-1..AC-N`) | Required change folder + SHA-256 content approval enforced by Git `pre-commit` & PR `ci-check` |
| **S2: Design** | `verigate-architect` | `.sdlc/changes/<ticket>/spec.md` (or `.sdlc/spec.md`) (Contracts & Matrix) | SHA-256 content approval verified against `approvals.json` + committed `HEAD` |
| **S3: Build** | `verigate-builder` | Modular source / IaC code matching `gated_paths` | Secret files (`.env`, `*.pem`, `*.key`) blocked at `pre-commit` and optional AI hooks |
| **S4: Verify** | `verigate-verifier` | Commit-bound `verify-result.json` or Logged Waiver | Run `python3 .sdlc/bin/verigate.py verify --project .` before push; Git `pre-push` checks fresh proof and CI `ci-check` recomputes all checks from scratch |
| **S5: Review** | `verigate-reviewer` + `verigate-sentinel` | `review-findings.json` + `review-report.md` | Governed 6-pillar code review against `.sdlc/REVIEW.md` |
| **S6: Triage** | `issue_bridge.py` + Human | GitHub Issues / Azure DevOps + Fix | Simultaneous prompt to raise tickets (`gh` / `az boards`) AND fix selected findings; pinned PR `ci-check` + branch protection + `CODEOWNERS` on `.sdlc/changes/**` enforces merge readiness |

## 2. Declarative Config & Per-Change Isolation

- Configure repo-specific `gated_paths`, per-path `verify` commands, `change_id.branch_pattern`, `require_change_folder_for_gated_paths`, and `fail_on_missing_tool` in `.sdlc/config.json` (or repo-root `verigate.json`).
- Isolate artifacts per ticket under `.sdlc/changes/<ticket>/` (`intent.md`, `spec.md`, `approvals.json`, `verify-result.json`, `waivers.jsonl`, `review-findings.json`, `review-report.md`) using `--change <ticket>`, branch naming (e.g. `feature/PROJ-123-...`), `VERIGATE_CHANGE=<ticket>`, or `.sdlc/active-change`.

## 3. Mandatory Operating Protocol (Any LLM / Agent)

1. **Stage Dispatch First**: On every new feature, product, or change prompt, display the 6-stage dispatch plan (`python3 .sdlc/bin/verigate.py dispatch "<prompt>"` if not already rendered by an optional hook).
2. **Content-Hash Approval Before Coding (Gated Paths)**:
   - Draft `intent.md` (`>=200` chars, Scope, Constraints, `AC-1`, `AC-2+`) and `spec.md` (`>=250` chars, Architecture, Security/Guardrails, Verification Matrix referencing `AC-1`).
   - Present a summary to the user and run standalone:
     `python3 .sdlc/bin/verigate.py approve --project . --stage S1_S2` (add `--change <ticket>` when using per-change folders).
   - Any edit to `intent.md` or `spec.md` invalidates the SHA-256 hash (`STALE APPROVAL`) and requires re-approval.
3. **Commit-Bound Verification (`verigate verify`) & Logged Waivers**:
   - After modifying code or IaC under `gated_paths`, run:
     `python3 .sdlc/bin/verigate.py verify --project .` (add `--change <ticket>` when applicable) to execute configured verification commands, capture real OS exit codes, and write commit-bound `verify-result.json` (`head_commit` + `tree_digest`) required by `.githooks/pre-push`.
   - Also complete governed code review (`S5` -> `review-findings.json` & `review-report.md`).
   - If a required test tool or runtime is unavailable locally, never loop — explain the blocker and run standalone:
     `python3 .sdlc/bin/verigate.py waive --project . --stage S4_TEST --reason "<exact blocker>"`
4. **Simultaneous GitHub / Azure DevOps + Immediate Fix Prompt**:
   - Whenever Stage 5 surfaces findings (`REV-001..REV-N`), present the **Executive Review Scorecard** and ask the user **both questions at the same time**:
     1. Raise issues in **GitHub Issues** (`gh`) or **Azure DevOps Work Items** (`az boards`) via `python3 .sdlc/bin/issue_bridge.py create ...`?
     2. Fix Critical/High or ALL findings right now and re-verify?"""


def _render_github_actions_ci(
    verigate_ref: str = DEFAULT_VERIGATE_REF,
    verigate_repo: str = DEFAULT_VERIGATE_REPO,
) -> str:
    ref = _clean_ci_param(verigate_ref, "verigate_ref")
    repo = _clean_ci_param(verigate_repo, "verigate_repo")
    return f"""# VeriGate AI-SDLC v3.0 Pinned PR Pipeline Gate (GitHub Actions)
# Security: Checks out a pinned VeriGate release into $RUNNER_TEMP/verigate instead of
# running any checker script from the untrusted PR branch.
# `verigate ci-check` recomputes all configured verification commands from scratch (never
# trusting laptop verify-result.json), enforces required change folders for touched gated
# paths, and fails closed if a required tool is missing.
# Enforce human approval via GitHub branch protection + required CODEOWNERS reviewer on `.sdlc/changes/**`.
name: VeriGate AI-SDLC Policy Gate
on: [pull_request, push]
env:
  VERIGATE_REPO: {_yaml_dq(repo)}
  VERIGATE_REF: {_yaml_dq(ref)}
jobs:
  verigate-verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      - name: Checkout Pinned VeriGate Release
        run: |
          set -e
          VERIGATE_DIR="${{RUNNER_TEMP:-/tmp}}/verigate"
          rm -rf "$VERIGATE_DIR"
          if ! git clone --depth 1 --branch "$VERIGATE_REF" "$VERIGATE_REPO" "$VERIGATE_DIR" 2>/dev/null; then
            git init "$VERIGATE_DIR"
            git -C "$VERIGATE_DIR" remote add origin "$VERIGATE_REPO"
            git -C "$VERIGATE_DIR" fetch --depth 1 origin "$VERIGATE_REF"
            git -C "$VERIGATE_DIR" checkout --detach FETCH_HEAD
          fi
      - name: VeriGate Pinned PR Verification & Policy Gate (ci-check)
        run: |
          set -e
          VERIGATE_BIN="${{RUNNER_TEMP:-/tmp}}/verigate/bin"
          if [ "${{{{ github.event_name }}}}" = "pull_request" ]; then
            BASE="${{{{ github.base_ref }}}}"
            git fetch --no-tags origin "$BASE" 2>/dev/null || true
            python3 "$VERIGATE_BIN/verigate.py" ci-check --project . --base "origin/$BASE"
          else
            python3 "$VERIGATE_BIN/verigate.py" ci-check --project . --base "HEAD~1"
          fi
"""


def _render_azure_pipelines_ci(
    verigate_ref: str = DEFAULT_VERIGATE_REF,
    verigate_repo: str = DEFAULT_VERIGATE_REPO,
) -> str:
    ref = _clean_ci_param(verigate_ref, "verigate_ref")
    repo = _clean_ci_param(verigate_repo, "verigate_repo")
    return f"""{AZDO_VERIGATE_MARKER} (Azure Pipelines - Pinned Release v3.1)
# Security: Checks out a pinned VeriGate release into $(Agent.TempDirectory)/verigate instead of
# running any checker script from the untrusted PR branch.
# `verigate ci-check` loads config/policy from the target branch, recomputes all configured
# verification commands from scratch (never trusting laptop verify-result.json), requires a
# change folder and review report for touched gated paths, and fails closed on missing tools.
#
# Azure Repos Governance Setup (Azure Repos does not use GitHub CODEOWNERS):
#   1. PR Trigger: Enable this pipeline under Branch Policies -> Build Validation on your target branch.
#   2. Human Sign-off: Add required reviewers under Branch Policies -> Automatically included reviewers
#      with path filter `/.sdlc/changes/*`.
trigger:
  - main
pr: none

variables:
  VERIGATE_REPO: {_yaml_sq(repo)}
  VERIGATE_REF: {_yaml_sq(ref)}

pool:
  vmImage: 'ubuntu-latest'

steps:
  - checkout: self
    fetchDepth: 0

  - task: UsePythonVersion@0
    inputs:
      versionSpec: '3.12'
    displayName: 'Use Python 3.12'

  - script: |
      set -e
      VERIGATE_DIR="$(Agent.TempDirectory)/verigate"
      rm -rf "$VERIGATE_DIR"
      if ! git clone --depth 1 --branch "$(VERIGATE_REF)" "$(VERIGATE_REPO)" "$VERIGATE_DIR" 2>/dev/null; then
        git init "$VERIGATE_DIR"
        git -C "$VERIGATE_DIR" remote add origin "$(VERIGATE_REPO)"
        git -C "$VERIGATE_DIR" fetch --depth 1 origin "$(VERIGATE_REF)"
        git -C "$VERIGATE_DIR" checkout --detach FETCH_HEAD
      fi
    displayName: 'Checkout Pinned VeriGate Release'

  - script: |
      set -e
      VERIGATE_BIN="$(Agent.TempDirectory)/verigate/bin"
      if [ "$(Build.Reason)" = "PullRequest" ]; then
        BASE="$(System.PullRequest.TargetBranchName)"
        git fetch --no-tags origin "$BASE" 2>/dev/null || true
        python3 "$VERIGATE_BIN/verigate.py" ci-check --project . --base "origin/$BASE"
      else
        python3 "$VERIGATE_BIN/verigate.py" ci-check --project . --base "HEAD~1"
      fi
    displayName: 'VeriGate Pinned PR Verification & Policy Gate (ci-check)'
"""


GITHUB_ACTIONS_CI_YML = _render_github_actions_ci()
AZURE_PIPELINES_CI_YML = _render_azure_pipelines_ci()


class _InstallTx:
    """Tracks planned/applied creates, updates, and automatic backups with dry-run support."""

    def __init__(self, target_dir: Path, dry_run: bool, backup: bool) -> None:
        self.target_dir = target_dir
        self.dry_run = dry_run
        self.backup = backup
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        backups_parent = target_dir / ".sdlc" / "backups"
        candidate = backups_parent / ts
        if not dry_run and candidate.exists():
            ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
            candidate = backups_parent / ts
        self.backup_dir = candidate
        self.backup_dir_rel = f".sdlc/backups/{ts}"
        self.created: list[str] = []
        self.updated: list[str] = []
        self.backed_up: list[str] = []
        self._seen_backups: set[str] = set()

    def _rel(self, path: Path) -> str:
        return path.relative_to(self.target_dir).as_posix()

    def record_and_backup(self, path: Path) -> bool:
        rel = self._rel(path)
        existed = path.is_file()
        if existed:
            if rel not in self.updated:
                self.updated.append(rel)
            if self.backup and rel not in self._seen_backups:
                self._seen_backups.add(rel)
                backup_dst = self.backup_dir / rel
                self.backed_up.append(f"{self.backup_dir_rel}/{rel}")
                if not self.dry_run:
                    backup_dst.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(path, backup_dst)
        else:
            if rel not in self.created:
                self.created.append(rel)
        return existed

    def write_text(self, path: Path, content: str, executable: bool = False) -> None:
        self.record_and_backup(path)
        if self.dry_run:
            return
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        if executable:
            _make_executable(path)

    def copy_file(self, src: Path, dst: Path, executable: bool = False) -> None:
        self.record_and_backup(dst)
        if self.dry_run:
            return
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        if executable:
            _make_executable(dst)

    def copy_tree(self, src_dir: Path, dst_dir: Path) -> None:
        for src_file in sorted(src_dir.rglob("*")):
            if src_file.is_file():
                rel = src_file.relative_to(src_dir)
                self.copy_file(src_file, dst_dir / rel)


def _load_json_object(path: Path) -> dict:
    """Fail closed if an existing JSON config file is malformed or not a JSON object."""
    if not path.is_file():
        return {}
    raw = path.read_text(encoding="utf-8")
    try:
        parsed = json.loads(raw)
    except ValueError as exc:
        raise ValueError(
            f"Refusing to overwrite malformed JSON in {path}: {exc}. "
            "Fix or remove the file before re-running install_verigate.py."
        ) from exc
    if not isinstance(parsed, dict):
        raise ValueError(
            f"Refusing to overwrite non-object JSON in {path}: expected a JSON object, got {type(parsed).__name__}."
        )
    return parsed


def _upsert_markdown_block(path: Path, body: str, frontmatter: str = "", tx: _InstallTx | None = None) -> None:
    block = f"{MARKER_START}\n{body.strip()}\n{MARKER_END}\n"
    if not path.exists():
        prefix = f"{frontmatter.rstrip()}\n\n" if frontmatter else ""
        content = prefix + block
    else:
        existing = path.read_text(encoding="utf-8")
        pattern = re.compile(re.escape(MARKER_START) + r".*?" + re.escape(MARKER_END) + r"\n?", re.DOTALL)
        if pattern.search(existing):
            content = pattern.sub(block, existing, count=1)
        else:
            sep = "\n\n" if existing and not existing.endswith("\n\n") else ("\n" if existing and not existing.endswith("\n") else "")
            content = existing + sep + block

    if tx is not None:
        tx.write_text(path, content)
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")


def _merge_claude_settings(settings_path: Path, aisdlc_hooks: dict, tx: _InstallTx | None = None) -> None:
    data = _load_json_object(settings_path)
    hooks_obj = data.setdefault("hooks", {})
    if not isinstance(hooks_obj, dict):
        raise ValueError(
            f"Refusing to overwrite {settings_path}: expected 'hooks' to be a JSON object."
        )
    for event_name, new_entries in aisdlc_hooks.items():
        cur_list = [
            item
            for item in (hooks_obj.get(event_name) or [])
            if not re.search(r'verigate\.py\\?["\']?\s+hook\b', json.dumps(item))
        ]
        cur_list.extend(new_entries)
        hooks_obj[event_name] = cur_list

    serialized = json.dumps(data, indent=2) + "\n"
    if tx is not None:
        tx.write_text(settings_path, serialized)
    else:
        settings_path.parent.mkdir(parents=True, exist_ok=True)
        settings_path.write_text(serialized, encoding="utf-8")


def _merge_antigravity_hooks(hooks_path: Path, ag_hooks: dict, tx: _InstallTx | None = None) -> None:
    data = _load_json_object(hooks_path)
    data.update(ag_hooks)
    serialized = json.dumps(data, indent=2) + "\n"
    if tx is not None:
        tx.write_text(hooks_path, serialized)
    else:
        hooks_path.parent.mkdir(parents=True, exist_ok=True)
        hooks_path.write_text(serialized, encoding="utf-8")


def _make_executable(p: Path) -> None:
    try:
        p.chmod(p.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    except OSError:
        pass


def _resolve_azdo_pipeline_path(target_dir: Path) -> Path:
    """Return azure-pipelines.yml unless a non-VeriGate azure-pipelines.yml already exists."""
    root_azdo = target_dir / "azure-pipelines.yml"
    if root_azdo.is_file():
        existing = root_azdo.read_text(encoding="utf-8", errors="replace")
        if AZDO_VERIGATE_MARKER not in existing:
            return target_dir / ".azure-pipelines" / "verigate-gate.yml"
    return root_azdo


def _upsert_gitignore(tx: _InstallTx, target_dir: Path) -> None:
    gi_path = target_dir / ".gitignore"
    start = "# VERIGATE:START"
    end = "# VERIGATE:END"
    entries = (
        f"{start}\n"
        ".sdlc/verify-result.json\n"
        ".sdlc/changes/*/verify-result.json\n"
        ".sdlc/audit.jsonl\n"
        ".sdlc/waivers.jsonl\n"
        ".sdlc/changes/*/waivers.jsonl\n"
        ".sdlc/backups/\n"
        f"{end}\n"
    )
    if not gi_path.exists():
        tx.write_text(gi_path, entries)
        return
    existing = gi_path.read_text(encoding="utf-8")
    pat = re.compile(re.escape(start) + r".*?" + re.escape(end) + r"\n?", re.DOTALL)
    if pat.search(existing):
        updated = pat.sub(entries, existing, count=1)
    else:
        sep = "\n\n" if existing and not existing.endswith("\n\n") else ("\n" if existing and not existing.endswith("\n") else "")
        updated = existing + sep + entries
    tx.write_text(gi_path, updated)


def _git_hook_script(adapter: str) -> str:
    return (
        "#!/usr/bin/env sh\n"
        "set -e\n"
        'REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"\n'
        "PY=python3\n"
        "command -v python3 >/dev/null 2>&1 || PY=python\n"
        f'exec "$PY" "$REPO_ROOT/.sdlc/bin/verigate.py" hook --adapter {adapter}\n'
    )


def install(
    target_dir: Path,
    targets: set[str],
    activate_git_hooks: bool,
    require_spec: bool,
    *,
    python_cmd: str | None = None,
    verigate_ref: str = DEFAULT_VERIGATE_REF,
    verigate_repo: str = DEFAULT_VERIGATE_REPO,
    dry_run: bool = False,
    backup: bool = True,
) -> dict:
    use_all = "all" in targets
    py_cmd = (python_cmd or _default_python_cmd()).strip()
    clean_ref = _clean_ci_param(verigate_ref, "verigate_ref")
    clean_repo = _clean_ci_param(verigate_repo, "verigate_repo")

    # Fail-closed pre-flight validation on existing JSON hook configs before touching disk
    if use_all or "claude" in targets:
        _load_json_object(target_dir / ".claude" / "settings.json")
    if use_all or "antigravity" in targets or "gemini" in targets:
        _load_json_object(target_dir / ".agents" / "hooks.json")

    tx = _InstallTx(target_dir=target_dir, dry_run=dry_run, backup=backup)
    installed: list[str] = []

    if not dry_run:
        target_dir.mkdir(parents=True, exist_ok=True)

    # 1. Core .sdlc/bin + config + REVIEW.md
    sdlc_bin = target_dir / ".sdlc" / "bin"
    for script_name in ("verigate.py", "issue_bridge.py"):
        dst = sdlc_bin / script_name
        tx.copy_file(KIT_ROOT / "bin" / script_name, dst, executable=True)
        installed.append(dst.relative_to(target_dir).as_posix())

    init_files = (
        target_dir / ".sdlc" / "config.json",
        target_dir / ".sdlc" / "policy.json",
        target_dir / ".sdlc" / "REVIEW.md",
    )
    for init_file in init_files:
        if not init_file.exists():
            rel = init_file.relative_to(target_dir).as_posix()
            if rel not in tx.created:
                tx.created.append(rel)

    if not dry_run:
        subprocess.run(
            [sys.executable, str(sdlc_bin / "verigate.py"), "init", "--project", str(target_dir)]
            + (["--require-spec"] if require_spec else []),
            check=True,
            capture_output=True,
        )
    installed.extend([".sdlc/config.json", ".sdlc/policy.json", ".sdlc/REVIEW.md"])

    # 2. Universal AGENTS.md & Codex skills
    if use_all or "universal" in targets or "codex" in targets:
        _upsert_markdown_block(target_dir / "AGENTS.md", UNIVERSAL_RULE_BODY, tx=tx)
        installed.append("AGENTS.md")
    if use_all or "codex" in targets:
        for sk in sorted((KIT_ROOT / "skills").iterdir()):
            if sk.is_dir():
                tx.copy_tree(sk, target_dir / ".codex" / "skills" / sk.name)
        installed.append(".codex/skills/*")

    # 3. Claude Code (CLAUDE.md + .claude/settings.json + .claude/agents + .claude/skills)
    if use_all or "claude" in targets:
        _upsert_markdown_block(target_dir / "CLAUDE.md", UNIVERSAL_RULE_BODY, tx=tx)
        claude_dir = target_dir / ".claude"
        for ag in sorted((KIT_ROOT / "agents").glob("*.md")):
            tx.copy_file(ag, claude_dir / "agents" / ag.name)
        for sk in sorted((KIT_ROOT / "skills").iterdir()):
            if sk.is_dir():
                tx.copy_tree(sk, claude_dir / "skills" / sk.name)
        claude_script = '"$CLAUDE_PROJECT_DIR/.sdlc/bin/verigate.py"'
        claude_hooks = {
            "UserPromptSubmit": [{"hooks": [{"type": "command", "command": _hook_cmd(claude_script, "claude", "UserPromptSubmit", py_cmd)}]}],
            "PreToolUse": [{"matcher": CLAUDE_PRE_TOOL_MATCHER, "hooks": [{"type": "command", "command": _hook_cmd(claude_script, "claude", "PreToolUse", py_cmd)}]}],
            "PostToolUse": [{"matcher": CLAUDE_POST_TOOL_MATCHER, "hooks": [{"type": "command", "command": _hook_cmd(claude_script, "claude", "PostToolUse", py_cmd)}]}],
            "Stop": [{"hooks": [{"type": "command", "command": _hook_cmd(claude_script, "claude", "Stop", py_cmd)}]}],
        }
        _merge_claude_settings(claude_dir / "settings.json", claude_hooks, tx=tx)
        installed.extend(["CLAUDE.md", ".claude/settings.json", ".claude/agents/*", ".claude/skills/*"])

    # 4. Antigravity & Gemini CLI (GEMINI.md + .agents/hooks.json + .agents/skills)
    if use_all or "antigravity" in targets or "gemini" in targets:
        _upsert_markdown_block(target_dir / "GEMINI.md", UNIVERSAL_RULE_BODY, tx=tx)
        ag_dir = target_dir / ".agents"
        for sk in sorted((KIT_ROOT / "skills").iterdir()):
            if sk.is_dir():
                tx.copy_tree(sk, ag_dir / "skills" / sk.name)
        ag_hooks = {
            "verigate-router": {
                "PreInvocation": [{"type": "command", "command": _hook_cmd("../.sdlc/bin/verigate.py", "antigravity", "PreInvocation", py_cmd), "timeout": 5}]
            },
            "verigate-gatekeeper": {
                "PreToolUse": [{"matcher": "write_file|edit_file|run_command", "hooks": [{"type": "command", "command": _hook_cmd("../.sdlc/bin/verigate.py", "antigravity", "PreToolUse", py_cmd), "timeout": 5}]}]
            },
            "verigate-tracker": {
                "PostToolUse": [{"matcher": "write_file|edit_file|invoke_subagent|run_command", "hooks": [{"type": "command", "command": _hook_cmd("../.sdlc/bin/verigate.py", "antigravity", "PostToolUse", py_cmd), "timeout": 5}]}]
            },
            "verigate-stop": {
                "Stop": [{"type": "command", "command": _hook_cmd("../.sdlc/bin/verigate.py", "antigravity", "Stop", py_cmd), "timeout": 5}]
            },
        }
        _merge_antigravity_hooks(ag_dir / "hooks.json", ag_hooks, tx=tx)
        installed.extend(["GEMINI.md", ".agents/hooks.json", ".agents/skills/*"])

    # 5. Cursor IDE (.cursor/rules/verigate.mdc)
    if use_all or "cursor" in targets:
        cur_dir = target_dir / ".cursor" / "rules"
        _upsert_markdown_block(
            cur_dir / "verigate.mdc",
            UNIVERSAL_RULE_BODY,
            frontmatter="---\ndescription: Enterprise 6-Stage AI-SDLC v3.0 (Git + Pinned PR Pipeline + Optional AI Hooks)\nalwaysApply: true\n---",
            tx=tx,
        )
        installed.append(".cursor/rules/verigate.mdc")

    # 6. Windsurf (.windsurfrules)
    if use_all or "windsurf" in targets:
        _upsert_markdown_block(target_dir / ".windsurfrules", UNIVERSAL_RULE_BODY, tx=tx)
        installed.append(".windsurfrules")

    # 7. GitHub Copilot (.github/copilot-instructions.md)
    if use_all or "copilot" in targets:
        gh_dir = target_dir / ".github"
        _upsert_markdown_block(gh_dir / "copilot-instructions.md", UNIVERSAL_RULE_BODY, tx=tx)
        installed.append(".github/copilot-instructions.md")

    # 8. Pinned-Release CI Gates (GitHub Actions + Azure Pipelines)
    if use_all or "ci" in targets:
        gh_wf = target_dir / ".github" / "workflows" / "verigate-gate.yml"
        tx.write_text(gh_wf, _render_github_actions_ci(clean_ref, clean_repo))
        installed.append(".github/workflows/verigate-gate.yml")

    if use_all or "ci" in targets or "azdo-ci" in targets:
        azdo_path = _resolve_azdo_pipeline_path(target_dir)
        tx.write_text(azdo_path, _render_azure_pipelines_ci(clean_ref, clean_repo))
        installed.append(azdo_path.relative_to(target_dir).as_posix())

    # 9. Universal Git Pre-Commit & Pre-Push Hooks (POSIX sh with repo-root resolution + python3 || python fallback)
    if use_all or "git" in targets:
        pre_commit = target_dir / ".githooks" / "pre-commit"
        tx.write_text(
            pre_commit,
            _git_hook_script("git-pre-commit"),
            executable=True,
        )
        installed.append(".githooks/pre-commit")

        pre_push = target_dir / ".githooks" / "pre-push"
        tx.write_text(
            pre_push,
            _git_hook_script("git-pre-push"),
            executable=True,
        )
        installed.append(".githooks/pre-push")

        if not dry_run and activate_git_hooks and (target_dir / ".git").exists():
            subprocess.run(["git", "-C", str(target_dir), "config", "core.hooksPath", ".githooks"], check=False)

    # Keep commit-bound local verify-result.json & logs git-ignored so committing never stales verify proof
    _upsert_gitignore(tx, target_dir)
    installed.append(".gitignore")

    result: dict = {
        "target": str(target_dir),
        "dry_run": dry_run,
        "python_cmd": py_cmd,
        "verigate_ref": clean_ref,
        "verigate_repo": clean_repo,
        "installed": installed,
        "created": tx.created,
        "updated": tx.updated,
        "backed_up": tx.backed_up,
    }
    if tx.backed_up:
        result["backup_dir"] = tx.backup_dir_rel
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Bootstrap VeriGate AI-SDLC v3.0 into any project")
    parser.add_argument("--target", required=True, help="Target project directory")
    parser.add_argument(
        "--targets",
        default="all",
        help="Comma-separated surfaces: all,universal,codex,claude,antigravity,gemini,cursor,windsurf,copilot,ci,azdo-ci,git",
    )
    parser.add_argument("--activate-git-hooks", action="store_true")
    parser.add_argument("--require-spec", action="store_true")
    parser.add_argument(
        "--python-cmd",
        default=None,
        help="Python executable command for generated JSON hooks (defaults to 'python' on Windows, 'python3' on POSIX)",
    )
    parser.add_argument(
        "--verigate-ref",
        default=DEFAULT_VERIGATE_REF,
        help=f"Pinned VeriGate Git tag or commit SHA checked out by generated CI pipelines (default: {DEFAULT_VERIGATE_REF})",
    )
    parser.add_argument(
        "--verigate-repo",
        default=DEFAULT_VERIGATE_REPO,
        help=f"VeriGate Git repository URL checked out by generated CI pipelines (default: {DEFAULT_VERIGATE_REPO})",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Compute and print JSON summary of files that would be created, updated, or backed up without writing to disk",
    )
    parser.add_argument(
        "--no-backup",
        action="store_true",
        help="Disable automatic backups under .sdlc/backups/<UTC-timestamp>/ before overwriting existing files",
    )
    args = parser.parse_args()

    chosen = {x.strip().lower() for x in args.targets.split(",") if x.strip()}
    try:
        result = install(
            Path(os.path.realpath(args.target)),
            chosen,
            args.activate_git_hooks,
            args.require_spec,
            python_cmd=args.python_cmd,
            verigate_ref=args.verigate_ref,
            verigate_repo=args.verigate_repo,
            dry_run=args.dry_run,
            backup=not args.no_backup,
        )
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
