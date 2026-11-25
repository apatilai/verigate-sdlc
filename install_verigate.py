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

CLAUDE_PRE_TOOL_MATCHER = "Write|Edit|MultiEdit|NotebookEdit|Bash|PowerShell"
CLAUDE_POST_TOOL_MATCHER = "Write|Edit|MultiEdit|NotebookEdit|Bash|PowerShell|Agent|Task"


def _default_python_cmd() -> str:
    return "python" if os.name == "nt" else "python3"


def _hook_cmd(script_rel: str, adapter: str, event: str, python_cmd: str | None = None) -> str:
    py = (python_cmd or _default_python_cmd()).strip()
    py_tok = f'"{py}"' if " " in py and not (py.startswith('"') and py.endswith('"')) else py
    return f"{py_tok} {script_rel} hook --adapter {adapter} --event {event}"


UNIVERSAL_RULE_BODY = """# Enterprise AI-Native SDLC (Local Agent Guide Rails + CI/PR Policy Gates)

This repository uses the **6-Stage VeriGate AI-Native Software Development Lifecycle (AI-SDLC)** combining **local agent guide rails** with **CI/PR policy gates**:

- **Local Agent Guide Rails**: Cooperative lifecycle hooks, SHA-256 content-hash spec tracking, shell/PowerShell write checks, real test/IaC runner exit-code verification, and non-trapping Stop reminders catch honest mistakes early in your local IDE/CLI session.
- **Hard Enterprise Controls (CI/PR Boundary)**: Local hooks are developer guide rails — NOT a substitute for bank-grade access controls. Hard enforcement remains in **Git branch protection, human PR approvals, and CI/CD policy gates** (`.github/workflows/verigate-gate.yml` / `azure-pipelines.yml`).

## 1. Six Stages, Artifacts & Control Layers

| Stage | Role | Verified Artifact | Guide Rail / Policy Gate |
| :--- | :--- | :--- | :--- |
| **S1: Plan** | `verigate-requirements` | `.sdlc/intent.md` or `.sdlc/changes/<ticket>/intent.md` (`AC-1..AC-N`) | SHA-256 content approval checked before `src/*` edits on Greenfield/Feature work |
| **S2: Design** | `verigate-architect` | `.sdlc/spec.md` or `.sdlc/changes/<ticket>/spec.md` (Contracts & Matrix) | SHA-256 content approval verified against `approvals.json` + shadow/HEAD ledger |
| **S3: Build** | `verigate-builder` | Modular source / IaC code | Secret files (`.env`, `*.pem`, `*.key`), `.sdlc/bin/*`, and `.sdlc/approvals*` edits blocked by local hooks |
| **S4: Verify** | `verigate-verifier` | Executed tests/IaC checks or Logged Waiver | Stop / Commit gate requires a real test/IaC command exit code `0` or a `verigate.py waive` audit entry |
| **S5: Review** | `verigate-reviewer` + `verigate-sentinel` | `review-findings.json` + `review-report.md` | Governed 6-pillar code review against `.sdlc/REVIEW.md` |
| **S6: Triage** | `issue_bridge.py` + Human | GitHub Issues / Azure DevOps + Fix | Simultaneous prompt to raise tickets (`gh` / `az boards`) AND fix selected findings; CI/PR gate verifies merge readiness |

## 2. Per-Change Isolation (`.sdlc/changes/<ticket>/`)

- For parallel branches or multi-ticket work, isolate artifacts per ticket with `--change <ticket>` (or set `VERIGATE_CHANGE=<ticket>` / `.sdlc/active-change`):
  - Artifacts live under `.sdlc/changes/<ticket>/` (`intent.md`, `spec.md`, `approvals.json`, `waivers.jsonl`, `review-findings.json`, `review-report.md`).
- When no change ID is active, VeriGate falls back to root `.sdlc/` for single-stream compatibility.

## 3. Mandatory Operating Protocol (Any LLM / Agent)

1. **Stage Dispatch First**: On every new feature, product, or change prompt, display the 6-stage dispatch plan (`python3 .sdlc/bin/verigate.py dispatch "<prompt>"` if not already rendered by a lifecycle hook).
2. **Content-Hash Approval Before Coding (Greenfield & Features)**:
   - Draft `intent.md` (`>=200` chars, Scope, Constraints, `AC-1`, `AC-2+`) and `spec.md` (`>=250` chars, Architecture, Security/Guardrails, Verification Matrix referencing `AC-1`).
   - Present a summary to the user and run standalone:
     `python3 .sdlc/bin/verigate.py approve --project . --stage S1_S2` (add `--change <ticket>` when using per-change folders).
   - Any edit to `intent.md` or `spec.md` invalidates the SHA-256 hash (`STALE APPROVAL`) and requires re-approval.
3. **Real Verification & Logged Waivers**:
   - After modifying source or Terraform/IaC files, run real test/validation commands (`S4`, e.g., `pytest`, `unittest`, `npm test`, `terraform fmt -check`, `terraform validate`, `tflint`) and governed code review (`S5` -> `review-findings.json` & `review-report.md`).
   - If a test tool or runtime is unavailable, never loop—explain the blocker and run standalone:
     `python3 .sdlc/bin/verigate.py waive --project . --stage S4_TEST --reason "<exact blocker>"`
4. **Simultaneous GitHub / Azure DevOps + Immediate Fix Prompt**:
   - Whenever Stage 5 surfaces findings (`REV-001..REV-N`), present the **Executive Review Scorecard** and ask the user **both questions at the same time**:
     1. Raise issues in **GitHub Issues** (`gh`) or **Azure DevOps Work Items** (`az boards`) via `python3 .sdlc/bin/issue_bridge.py create ...`?
     2. Fix Critical/High or ALL findings right now and re-verify?"""


GITHUB_ACTIONS_CI_YML = """# VeriGate AI-SDLC Policy Gate (GitHub Actions)
name: VeriGate AI-SDLC Policy Gate
on: [pull_request, push]
jobs:
  verigate-verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      - name: Verify VeriGate Spec Approvals & Team Merge Policy
        run: |
          if [ -f .sdlc/intent.md ]; then
            python3 .sdlc/bin/verigate.py validate --project .
          fi
          if [ -f .sdlc/review-findings.json ]; then
            python3 .sdlc/bin/verigate.py merge-check --project .
          fi
          if [ -d .sdlc/changes ]; then
            for d in .sdlc/changes/*; do
              [ -d "$d" ] || continue
              cid="$(basename "$d")"
              if [ -f "$d/intent.md" ]; then
                python3 .sdlc/bin/verigate.py validate --project . --change "$cid"
              fi
              if [ -f "$d/review-findings.json" ]; then
                python3 .sdlc/bin/verigate.py merge-check --project . --change "$cid"
              fi
            done
          fi
      - name: Optional Terraform / IaC Validation
        run: |
          if find . -maxdepth 4 -name '*.tf' -not -path './.git/*' -not -path './.terraform/*' | grep -q .; then
            if command -v terraform >/dev/null 2>&1; then
              terraform fmt -check -recursive
              terraform init -backend=false
              terraform validate
            else
              echo "Terraform files detected; install terraform in CI runner to enforce fmt/validate."
            fi
          fi
"""


AZURE_PIPELINES_CI_YML = f"""{AZDO_VERIGATE_MARKER} (Azure Pipelines)
trigger:
  - main
pr:
  - main

pool:
  vmImage: 'ubuntu-latest'

steps:
  - task: UsePythonVersion@0
    inputs:
      versionSpec: '3.12'
    displayName: 'Use Python 3.12'

  - script: |
      set -e
      if [ -f .sdlc/intent.md ]; then
        python3 .sdlc/bin/verigate.py validate --project .
      fi
      if [ -f .sdlc/review-findings.json ]; then
        python3 .sdlc/bin/verigate.py merge-check --project .
      fi
      if [ -d .sdlc/changes ]; then
        for d in .sdlc/changes/*; do
          [ -d "$d" ] || continue
          cid="$(basename "$d")"
          if [ -f "$d/intent.md" ]; then
            python3 .sdlc/bin/verigate.py validate --project . --change "$cid"
          fi
          if [ -f "$d/review-findings.json" ]; then
            python3 .sdlc/bin/verigate.py merge-check --project . --change "$cid"
          fi
        done
      fi
    displayName: 'Verify VeriGate Spec Approvals & Team Merge Policy'

  - script: |
      set -e
      if find . -maxdepth 4 -name '*.tf' -not -path './.git/*' -not -path './.terraform/*' | grep -q .; then
        if command -v terraform >/dev/null 2>&1; then
          terraform fmt -check -recursive
          terraform init -backend=false
          terraform validate
        else
          echo "Terraform files detected; install terraform in CI agent to enforce fmt/validate."
        fi
      fi
    displayName: 'Optional Terraform / IaC Validation'
"""


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
            if "verigate.py hook" not in json.dumps(item)
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


def install(
    target_dir: Path,
    targets: set[str],
    activate_git_hooks: bool,
    require_spec: bool,
    *,
    python_cmd: str | None = None,
    dry_run: bool = False,
    backup: bool = True,
) -> dict:
    use_all = "all" in targets
    py_cmd = (python_cmd or _default_python_cmd()).strip()

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
        claude_hooks = {
            "UserPromptSubmit": [{"hooks": [{"type": "command", "command": _hook_cmd(".sdlc/bin/verigate.py", "claude", "UserPromptSubmit", py_cmd)}]}],
            "PreToolUse": [{"matcher": CLAUDE_PRE_TOOL_MATCHER, "hooks": [{"type": "command", "command": _hook_cmd(".sdlc/bin/verigate.py", "claude", "PreToolUse", py_cmd)}]}],
            "PostToolUse": [{"matcher": CLAUDE_POST_TOOL_MATCHER, "hooks": [{"type": "command", "command": _hook_cmd(".sdlc/bin/verigate.py", "claude", "PostToolUse", py_cmd)}]}],
            "Stop": [{"hooks": [{"type": "command", "command": _hook_cmd(".sdlc/bin/verigate.py", "claude", "Stop", py_cmd)}]}],
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
            frontmatter="---\ndescription: Enterprise 6-Stage AI-SDLC (Local Guide Rails + CI/PR Policy Gates)\nalwaysApply: true\n---",
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

    # 8. CI Gates (GitHub Actions + Azure Pipelines)
    if use_all or "ci" in targets:
        gh_wf = target_dir / ".github" / "workflows" / "verigate-gate.yml"
        tx.write_text(gh_wf, GITHUB_ACTIONS_CI_YML)
        installed.append(".github/workflows/verigate-gate.yml")

    if use_all or "ci" in targets or "azdo-ci" in targets:
        azdo_path = _resolve_azdo_pipeline_path(target_dir)
        tx.write_text(azdo_path, AZURE_PIPELINES_CI_YML)
        installed.append(azdo_path.relative_to(target_dir).as_posix())

    # 9. Universal Git Pre-Commit Hook (POSIX sh with python3 || python fallback)
    if use_all or "git" in targets:
        pre_commit = target_dir / ".githooks" / "pre-commit"
        tx.write_text(
            pre_commit,
            "#!/usr/bin/env sh\nset -e\nPY=python3\ncommand -v python3 >/dev/null 2>&1 || PY=python\nexec \"$PY\" .sdlc/bin/verigate.py hook --adapter git-pre-commit\n",
            executable=True,
        )
        installed.append(".githooks/pre-commit")
        if not dry_run and activate_git_hooks and (target_dir / ".git").exists():
            subprocess.run(["git", "-C", str(target_dir), "config", "core.hooksPath", ".githooks"], check=False)

    result: dict = {
        "target": str(target_dir),
        "dry_run": dry_run,
        "python_cmd": py_cmd,
        "installed": installed,
        "created": tx.created,
        "updated": tx.updated,
        "backed_up": tx.backed_up,
    }
    if tx.backed_up:
        result["backup_dir"] = tx.backup_dir_rel
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Bootstrap VeriGate AI-SDLC into any project")
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
            dry_run=args.dry_run,
            backup=not args.no_backup,
        )
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
