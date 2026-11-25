#!/usr/bin/env python3
"""Idempotent, Non-Destructive Multi-LLM Bootstrapper for the VeriGate AI-SDLC Framework.

Safely upserts `<!-- VERIGATE:START -->...<!-- VERIGATE:END -->` blocks into existing Markdown files
and deep-merges JSON hook configs without erasing existing repository instructions, permissions, or MCP configs.
"""

from __future__ import annotations

import argparse
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


def _hook_cmd(script_rel: str, adapter: str, event: str) -> str:
    return (
        f'sh -c \'PY=python3; command -v python3 >/dev/null 2>&1 || PY=python; '
        f'exec "$PY" {script_rel} hook --adapter {adapter} --event {event}\''
    )

UNIVERSAL_RULE_BODY = """# Enterprise AI-Native SDLC (Universal Multi-LLM Control Plane)

This repository enforces a **6-Stage Deterministic AI-Native Software Development Lifecycle (AI-SDLC)** across all LLMs, coding agents, IDEs, and Git commits.

## 1. Six Deterministic Stages & Artifacts

| Stage | Role | Verified Artifact | Deterministic Enforcement |
| :--- | :--- | :--- | :--- |
| **S1: Plan** | `verigate-requirements` | `.sdlc/intent.md` (`AC-1..AC-N`) | SHA-256 content approval required before `src/*` edits on Greenfield/Feature work |
| **S2: Design** | `verigate-architect` | `.sdlc/spec.md` (Contracts & Matrix) | SHA-256 content approval verified against `.sdlc/approvals.json` + shadow/HEAD ledger |
| **S3: Build** | `verigate-builder` | Modular source code | Secret files (`.env`, `*.pem`, `*.key`), `.sdlc/bin/*`, and `.sdlc/approvals*` tampering blocked |
| **S4: Verify** | `verigate-verifier` | Executed tests or Logged Waiver | Stop / Commit gate requires passing tests or `verigate.py waive` audit entry |
| **S5: Review** | `verigate-reviewer` + `verigate-sentinel` | `.sdlc/review-findings.json` + `report.md` | Governed 6-pillar code review against `.sdlc/REVIEW.md` |
| **S6: Triage** | `issue_bridge.py` + Human | GitHub Issues / Azure DevOps + Fix | Simultaneous prompt to raise tickets (`gh` / `az boards`) AND fix selected findings |

## 2. Mandatory Operating Protocol (Any LLM / Agent)

1. **Stage Dispatch First**: On every new feature, product, or change prompt, display the 6-stage dispatch plan (`python3 .sdlc/bin/verigate.py dispatch "<prompt>"` if not already rendered by a lifecycle hook).
2. **Content-Hash Approval Before Coding (Greenfield & Features)**:
   - Draft `.sdlc/intent.md` (`AC-1..AC-N`) and `.sdlc/spec.md` (contracts + Verification Matrix).
   - Present a summary to the user and run standalone:
     `python3 .sdlc/bin/verigate.py approve --project . --stage S1_S2`
   - Any edit to `.sdlc/intent.md` or `.sdlc/spec.md` invalidates the SHA-256 hash (`STALE APPROVAL`) and requires re-approval.
3. **Non-Trapping Verification & Logged Waivers**:
   - After modifying source files, run tests (`S4`) and governed code review (`S5` -> `.sdlc/review-findings.json` & `.sdlc/review-report.md`).
   - If a test tool or runtime is unavailable, never loop—explain the blocker and run standalone:
     `python3 .sdlc/bin/verigate.py waive --project . --stage S4_TEST --reason "<exact blocker>"`
4. **Simultaneous GitHub / Azure DevOps + Immediate Fix Prompt**:
   - Whenever Stage 5 surfaces findings (`REV-001..REV-N`), present the **Executive Review Scorecard** and ask the user **both questions at the same time**:
     1. Raise issues in **GitHub Issues** (`gh`) or **Azure DevOps Work Items** (`az boards`) via `python3 .sdlc/bin/issue_bridge.py create ...`?
     2. Fix Critical/High or ALL findings right now and re-verify?"""


def _upsert_markdown_block(path: Path, body: str, frontmatter: str = "") -> None:
    block = f"{MARKER_START}\n{body.strip()}\n{MARKER_END}\n"
    if not path.exists():
        prefix = f"{frontmatter.rstrip()}\n\n" if frontmatter else ""
        path.write_text(prefix + block, encoding="utf-8")
        return

    existing = path.read_text(encoding="utf-8")
    pattern = re.compile(re.escape(MARKER_START) + r".*?" + re.escape(MARKER_END) + r"\n?", re.DOTALL)
    if pattern.search(existing):
        updated = pattern.sub(block, existing, count=1)
    else:
        sep = "\n\n" if existing and not existing.endswith("\n\n") else ("\n" if existing and not existing.endswith("\n") else "")
        updated = existing + sep + block
    path.write_text(updated, encoding="utf-8")


def _merge_claude_settings(settings_path: Path, aisdlc_hooks: dict) -> None:
    data: dict = {}
    if settings_path.is_file():
        try:
            data = json.loads(settings_path.read_text(encoding="utf-8"))
        except ValueError:
            data = {}
    hooks_obj = data.setdefault("hooks", {})
    for event_name, new_entries in aisdlc_hooks.items():
        cur_list = [
            item
            for item in (hooks_obj.get(event_name) or [])
            if "verigate.py hook" not in json.dumps(item)
        ]
        cur_list.extend(new_entries)
        hooks_obj[event_name] = cur_list
    settings_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def _merge_antigravity_hooks(hooks_path: Path, ag_hooks: dict) -> None:
    data: dict = {}
    if hooks_path.is_file():
        try:
            data = json.loads(hooks_path.read_text(encoding="utf-8"))
        except ValueError:
            data = {}
    data.update(ag_hooks)
    hooks_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def _make_executable(p: Path) -> None:
    try:
        p.chmod(p.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    except OSError:
        pass


def install(target_dir: Path, targets: set[str], activate_git_hooks: bool, require_spec: bool) -> dict:
    target_dir.mkdir(parents=True, exist_ok=True)
    installed: list[str] = []
    use_all = "all" in targets

    # 1. Core .sdlc/bin + config + REVIEW.md
    sdlc_bin = target_dir / ".sdlc" / "bin"
    sdlc_bin.mkdir(parents=True, exist_ok=True)
    for script_name in ("verigate.py", "issue_bridge.py"):
        dst = sdlc_bin / script_name
        shutil.copy2(KIT_ROOT / "bin" / script_name, dst)
        _make_executable(dst)
        installed.append(str(dst.relative_to(target_dir)))

    subprocess.run(
        [sys.executable, str(sdlc_bin / "verigate.py"), "init", "--project", str(target_dir)]
        + (["--require-spec"] if require_spec else []),
        check=True,
        capture_output=True,
    )
    installed.extend([".sdlc/config.json", ".sdlc/policy.json", ".sdlc/REVIEW.md"])

    # 2. Universal AGENTS.md & Codex skills
    if use_all or "universal" in targets or "codex" in targets:
        _upsert_markdown_block(target_dir / "AGENTS.md", UNIVERSAL_RULE_BODY)
        installed.append("AGENTS.md")
    if use_all or "codex" in targets:
        for sk in (KIT_ROOT / "skills").iterdir():
            if sk.is_dir():
                shutil.copytree(sk, target_dir / ".codex" / "skills" / sk.name, dirs_exist_ok=True)
        installed.append(".codex/skills/*")

    # 3. Claude Code (CLAUDE.md + .claude/settings.json + .claude/agents + .claude/skills)
    if use_all or "claude" in targets:
        _upsert_markdown_block(target_dir / "CLAUDE.md", UNIVERSAL_RULE_BODY)
        claude_dir = target_dir / ".claude"
        (claude_dir / "agents").mkdir(parents=True, exist_ok=True)
        for ag in (KIT_ROOT / "agents").glob("*.md"):
            shutil.copy2(ag, claude_dir / "agents" / ag.name)
        for sk in (KIT_ROOT / "skills").iterdir():
            if sk.is_dir():
                shutil.copytree(sk, claude_dir / "skills" / sk.name, dirs_exist_ok=True)
        claude_hooks = {
            "UserPromptSubmit": [{"hooks": [{"type": "command", "command": _hook_cmd(".sdlc/bin/verigate.py", "claude", "UserPromptSubmit")}]}],
            "PreToolUse": [{"matcher": "Write|Edit|MultiEdit|Bash", "hooks": [{"type": "command", "command": _hook_cmd(".sdlc/bin/verigate.py", "claude", "PreToolUse")}]}],
            "PostToolUse": [{"matcher": "Write|Edit|MultiEdit|Bash|Task", "hooks": [{"type": "command", "command": _hook_cmd(".sdlc/bin/verigate.py", "claude", "PostToolUse")}]}],
            "Stop": [{"hooks": [{"type": "command", "command": _hook_cmd(".sdlc/bin/verigate.py", "claude", "Stop")}]}],
        }
        _merge_claude_settings(claude_dir / "settings.json", claude_hooks)
        installed.extend(["CLAUDE.md", ".claude/settings.json", ".claude/agents/*", ".claude/skills/*"])

    # 4. Antigravity & Gemini CLI (GEMINI.md + .agents/hooks.json + .agents/skills)
    if use_all or "antigravity" in targets or "gemini" in targets:
        _upsert_markdown_block(target_dir / "GEMINI.md", UNIVERSAL_RULE_BODY)
        ag_dir = target_dir / ".agents"
        ag_dir.mkdir(parents=True, exist_ok=True)
        for sk in (KIT_ROOT / "skills").iterdir():
            if sk.is_dir():
                shutil.copytree(sk, ag_dir / "skills" / sk.name, dirs_exist_ok=True)
        ag_hooks = {
            "verigate-router": {
                "PreInvocation": [{"type": "command", "command": _hook_cmd("../.sdlc/bin/verigate.py", "antigravity", "PreInvocation"), "timeout": 5}]
            },
            "verigate-gatekeeper": {
                "PreToolUse": [{"matcher": "write_file|edit_file|run_command", "hooks": [{"type": "command", "command": _hook_cmd("../.sdlc/bin/verigate.py", "antigravity", "PreToolUse"), "timeout": 5}]}]
            },
            "verigate-tracker": {
                "PostToolUse": [{"matcher": "write_file|edit_file|invoke_subagent|run_command", "hooks": [{"type": "command", "command": _hook_cmd("../.sdlc/bin/verigate.py", "antigravity", "PostToolUse"), "timeout": 5}]}]
            },
            "verigate-stop": {
                "Stop": [{"type": "command", "command": _hook_cmd("../.sdlc/bin/verigate.py", "antigravity", "Stop"), "timeout": 5}]
            },
        }
        _merge_antigravity_hooks(ag_dir / "hooks.json", ag_hooks)
        installed.extend(["GEMINI.md", ".agents/hooks.json", ".agents/skills/*"])

    # 5. Cursor IDE (.cursor/rules/verigate.mdc)
    if use_all or "cursor" in targets:
        cur_dir = target_dir / ".cursor" / "rules"
        cur_dir.mkdir(parents=True, exist_ok=True)
        _upsert_markdown_block(
            cur_dir / "verigate.mdc",
            UNIVERSAL_RULE_BODY,
            frontmatter="---\ndescription: Enterprise 6-Stage Deterministic AI-SDLC\nalwaysApply: true\n---",
        )
        installed.append(".cursor/rules/verigate.mdc")

    # 6. Windsurf (.windsurfrules)
    if use_all or "windsurf" in targets:
        _upsert_markdown_block(target_dir / ".windsurfrules", UNIVERSAL_RULE_BODY)
        installed.append(".windsurfrules")

    # 7. GitHub Copilot (.github/copilot-instructions.md)
    if use_all or "copilot" in targets:
        gh_dir = target_dir / ".github"
        gh_dir.mkdir(parents=True, exist_ok=True)
        _upsert_markdown_block(gh_dir / "copilot-instructions.md", UNIVERSAL_RULE_BODY)
        installed.append(".github/copilot-instructions.md")

    # 8. CI Gates (GitHub Actions + Azure Pipelines)
    if use_all or "ci" in targets:
        wf_dir = target_dir / ".github" / "workflows"
        wf_dir.mkdir(parents=True, exist_ok=True)
        ci_yml = """name: VeriGate AI-SDLC Deterministic Gate
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
"""
        (wf_dir / "verigate-gate.yml").write_text(ci_yml, encoding="utf-8")
        installed.append(".github/workflows/verigate-gate.yml")

    # 9. Universal Git Pre-Commit Hook (with python3 || python fallback)
    if use_all or "git" in targets:
        ghooks = target_dir / ".githooks"
        ghooks.mkdir(parents=True, exist_ok=True)
        pre_commit = ghooks / "pre-commit"
        pre_commit.write_text(
            "#!/usr/bin/env sh\nset -e\nPY=python3\ncommand -v python3 >/dev/null 2>&1 || PY=python\nexec \"$PY\" .sdlc/bin/verigate.py hook --adapter git-pre-commit\n",
            encoding="utf-8",
        )
        _make_executable(pre_commit)
        installed.append(".githooks/pre-commit")
        if activate_git_hooks and (target_dir / ".git").exists():
            subprocess.run(["git", "-C", str(target_dir), "config", "core.hooksPath", ".githooks"], check=False)

    return {"target": str(target_dir), "installed": installed}


def main() -> None:
    parser = argparse.ArgumentParser(description="Bootstrap VeriGate AI-SDLC into any project")
    parser.add_argument("--target", required=True, help="Target project directory")
    parser.add_argument(
        "--targets",
        default="all",
        help="Comma-separated surfaces: all,universal,codex,claude,antigravity,gemini,cursor,windsurf,copilot,ci,git",
    )
    parser.add_argument("--activate-git-hooks", action="store_true")
    parser.add_argument("--require-spec", action="store_true")
    args = parser.parse_args()

    chosen = {x.strip().lower() for x in args.targets.split(",") if x.strip()}
    result = install(Path(os.path.realpath(args.target)), chosen, args.activate_git_hooks, args.require_spec)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
