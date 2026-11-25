#!/usr/bin/env python3
"""VeriGate AI-SDLC (AI-SDLC) Deterministic Control Engine & Multi-LLM Hook Adapter.

Works identically across:
- Google Antigravity & Gemini CLI (`.agents/hooks.json`, `GEMINI.md`, `AGENTS.md`)
- Claude Code (`.claude/settings.json` hooks, `CLAUDE.md`, `.claude/agents/`)
- OpenAI Codex (`AGENTS.md`, `.codex/skills/`)
- Cursor (`.cursor/rules/verigate.mdc`, `AGENTS.md`)
- GitHub Copilot & Windsurf (`.github/copilot-instructions.md`, `.windsurfrules`)
- Universal Git & CI/CD (`.githooks/pre-commit`, GitHub Actions, Azure Pipelines)

Zero external dependencies (Python 3.9+ standard library only).
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
import time
from pathlib import Path

MAX_STOP_INTERCEPTS = 1

REVIEW_ONLY_RE = re.compile(
    r"\b(code review|review (the |this |my )?(code|pr|pull request|diff|changes)|"
    r"audit (the |this )?(code|repo|changes)|raise (a |an )?(github|azure devops|ado) issue)\b",
    re.IGNORECASE,
)
GREENFIELD_RE = re.compile(
    r"\b(build|create|develop|launch|scaffold|bootstrap|make|start)\b.*"
    r"\b(app|application|product|solution|saas|platform|mvp|system|project|service|website|portal|dashboard)\b"
    r"|\b(new project|new product|from scratch)\b",
    re.IGNORECASE | re.DOTALL,
)
FEATURE_RE = re.compile(
    r"\b(add|implement|architect|design|integrate|create)\b.*"
    r"\b(feature|endpoint|api|component|screen|module|schema|database|migration|workflow|auth|webhook)\b",
    re.IGNORECASE | re.DOTALL,
)
CHANGE_RE = re.compile(
    r"\b(fix|bug|refactor|update|change|modify|edit|patch|optimize|improve|rename|remove|delete)\b",
    re.IGNORECASE,
)

SECRET_BASENAME_RE = re.compile(
    r"^(\.env(\..+)?|id_rsa|id_ed25519|.*credentials.*\.json|.*secret.*\.json)$",
    re.IGNORECASE,
)
ALLOWED_ENV_EXAMPLES = {".env.example", ".env.sample", ".env.template"}
SECRET_EXTS = {".pem", ".key", ".p12", ".pfx"}

PROTECTED_LEDGER_RE = re.compile(
    r"(^|/)(\.sdlc/(?:changes/[^/]+/)?(approvals\.json|waivers\.jsonl|audit\.jsonl|bin/[^/]+)|.*shadow_ledger\.json)$",
    re.IGNORECASE,
)
GOVERNANCE_RE = re.compile(
    r"(^|/)(REVIEW\.md|verigate\.json|\.sdlc/(REVIEW\.md|config\.json|policy\.json|active-change)|\.claude/settings.*\.json|\.agents/hooks\.json|\.gemini/settings\.json|\.githooks/[^/]+|\.github/workflows/[^/]+\.ya?ml|azure-pipelines.*\.ya?ml)$",
    re.IGNORECASE,
)
SANCTIONED_GATE_CMD_RE = re.compile(
    r'^\s*(?:PATH="[^"]*"\s+)?(?:python3?|py)\s+(?:"[^"]*?verigate\.py"|\'[^\']*?verigate\.py\'|\S*?verigate\.py)\s+(status|validate|approve|waive|dispatch|merge-check|verify|ci-check)\b(.*)$'
)
SANCTIONED_BRIDGE_CMD_RE = re.compile(
    r'^\s*(?:PATH="[^"]*"\s+)?(?:python3?|py)\s+(?:"[^"]*?issue_bridge\.py"|\'[^\']*?issue_bridge\.py\'|\S*?issue_bridge\.py)\s+(detect|preview|create)\b(.*)$'
)
SHELL_CHAIN_OR_REDIRECT_RE = re.compile(r"[;&|`$><\n]")
ANY_VERIGATE_INVOCATION_RE = re.compile(r"(^|[\s/\"'\\])verigate\.py\b", re.IGNORECASE)
ANY_BRIDGE_INVOCATION_RE = re.compile(r"(^|[\s/\"'\\])issue_bridge\.py\b", re.IGNORECASE)
READONLY_SHELL_PROGS = {
    "ls",
    "dir",
    "cat",
    "type",
    "head",
    "tail",
    "wc",
    "stat",
    "get-childitem",
    "get-content",
    "test-path",
    "gci",
    "gc",
}
GIT_NO_VERIFY_RE = re.compile(r"\bgit\s+commit\b.*(?:\s--no-verify\b|\s-[a-zA-Z]*n\b)")
SHELL_SECRET_WRITE_RE = re.compile(
    r"(?:>|>>|\btee\b|\bcp\b|\bmv\b|\bsed\s+-i|\bperl\s+-[a-zA-Z]*i|"
    r"\b(?:Set-Content|Add-Content|Out-File|Remove-Item|Clear-Content|Copy-Item|Move-Item|Rename-Item|New-Item)\b)"
    r".*?(?:^|[\s/\\\"'=])(\.env(?:\.[a-zA-Z0-9_-]+)?|id_rsa|id_ed25519|[^\s/\\\"'`]+\.(?:pem|key|p12|pfx))(?=$|[\s\"'`;|&)])",
    re.IGNORECASE,
)
LEDGER_TAMPER_CMD_RE = re.compile(
    r"(\.sdlc[/\\](?:changes[/\\][^/\\\s]+[/\\])?(approvals|waivers|audit|bin|config\.json|active-change)|\.claude[/\\]settings|\.agents[/\\]hooks\.json|\.githooks|shadow_ledger\.json|verigate-shadow)",
    re.IGNORECASE,
)
EXTERNAL_MUTATION_CMD_RE = re.compile(
    r"\b(gh\s+(issue|pr)\s+(create|merge|close|edit)|"
    r"az\s+boards\s+work-item\s+(create|update|delete)|"
    r"az\s+repos\s+pr\s+(create|update|complete)|"
    r"git\s+push|"
    r"issue_bridge\.py\s+create)\b",
    re.IGNORECASE,
)
ERROR_SWALLOW_RE = re.compile(
    r"(?:\|\|\s*(?:true\b|exit\s+0\b|:(?=\s|$|[;&|\n]))|;\s*(?:true|exit\s+0|:)\s*$)",
    re.IGNORECASE,
)
UNQUOTED_REDIRECT_RE = re.compile(r"(?<!>)(?:[012&])?>>?\s*(?!&)")
SINGLE_TOKEN_TEST_RUNNERS = {
    "pytest",
    "vitest",
    "jest",
    "flake8",
    "mypy",
    "pyright",
    "tsc",
    "eslint",
    "tflint",
    "checkov",
    "tfsec",
}
PYTHON_PROGS_RE = re.compile(r"^(?:python(?:3(?:\.\d+)?)?|py)$")
PYTHON_TEST_MODULES = {"pytest", "unittest", "mypy", "flake8", "pyright", "checkov"}
PS_WRITE_CMDLET_RE = re.compile(
    r"\b(Set-Content|Add-Content|Out-File|Copy-Item|Move-Item)\b",
    re.IGNORECASE,
)
CHANGE_ID_RE = re.compile(r"^[a-zA-Z0-9._-]+$")
BRANCH_TICKET_RE = re.compile(r"(?<![A-Za-z0-9])([A-Z][A-Z0-9]{1,10}-\d+)(?![A-Za-z0-9])")

PROJECT_MARKERS = (".sdlc", ".git", "package.json", "pyproject.toml", "go.mod", "Cargo.toml", "pom.xml")
META_DIR_RE = re.compile(r"(^|/)(\.sdlc|\.claude|\.agents|\.cursor|\.githooks|\.codex)(/|$)")
REVIEW_ARTIFACT_RE = re.compile(r"(^|/)\.sdlc/(?:changes/[^/]+/)?review-(report\.md|findings\.json)$")


def utc_now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def global_state_dir() -> str:
    d = os.environ.get("VERIGATE_DATA_DIR") or os.environ.get("PLUGIN_DATA") or os.path.expanduser("~/.verigate-shadow")
    try:
        os.makedirs(d, mode=0o700, exist_ok=True)
        return d
    except OSError:
        uid = os.getuid() if hasattr(os, "getuid") else "user"
        fallback = os.path.join(tempfile.gettempdir(), f"verigate-shadow-{uid}")
        os.makedirs(fallback, mode=0o700, exist_ok=True)
        return fallback


def session_state_path(session_id: str) -> str:
    safe = re.sub(r"[^a-zA-Z0-9_-]", "_", session_id or "default")
    return os.path.join(global_state_dir(), f"session_{safe}.json")


def load_session(session_id: str) -> dict:
    p = session_state_path(session_id)
    if os.path.isfile(p):
        try:
            return json.loads(Path(p).read_text(encoding="utf-8"))
        except Exception:
            return {}
    return {}


def save_session(session_id: str, data: dict) -> None:
    p = session_state_path(session_id)
    tmp = f"{p}.tmp"
    Path(tmp).write_text(json.dumps(data, indent=2), encoding="utf-8")
    os.replace(tmp, p)


def shadow_ledger_path() -> str:
    return os.path.join(global_state_dir(), "shadow_ledger.json")


def load_shadow_ledger() -> dict:
    p = shadow_ledger_path()
    if os.path.isfile(p):
        try:
            return json.loads(Path(p).read_text(encoding="utf-8"))
        except Exception:
            return {}
    return {}


def save_shadow_ledger(ledger: dict) -> None:
    p = shadow_ledger_path()
    tmp = f"{p}.tmp"
    Path(tmp).write_text(json.dumps(ledger, indent=2), encoding="utf-8")
    os.replace(tmp, p)


def file_sha256(path_str: str) -> str | None:
    try:
        h = hashlib.sha256()
        with open(path_str, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def append_audit(project_root: str | None, event: str, details: dict) -> None:
    rec = {
        "timestamp": utc_now_iso(),
        "event": event,
        "project_root": os.path.realpath(project_root) if project_root else None,
        **details,
    }
    line = json.dumps(rec) + "\n"
    try:
        with open(os.path.join(global_state_dir(), "audit.jsonl"), "a", encoding="utf-8") as fh:
            fh.write(line)
    except OSError:
        pass
    if project_root and os.path.isdir(project_root):
        try:
            sdlc_dir = os.path.join(project_root, ".sdlc")
            os.makedirs(sdlc_dir, exist_ok=True)
            with open(os.path.join(sdlc_dir, "audit.jsonl"), "a", encoding="utf-8") as fh:
                fh.write(line)
        except OSError:
            pass


def normalize_target_path(target_path: str, cwd: str | None = None) -> str:
    if not target_path:
        return ""
    if os.path.isabs(target_path):
        return target_path
    return os.path.join(cwd or os.getcwd(), target_path)


def resolve_project_root(target_path: str, cwd: str | None = None) -> str:
    joined = normalize_target_path(target_path, cwd) if target_path else (cwd or ".")
    abs_target = os.path.realpath(joined)
    cur = abs_target if os.path.isdir(abs_target) else os.path.dirname(abs_target)
    home = os.path.realpath(os.path.expanduser("~"))
    while cur and cur not in ("/", "/Users", home, os.path.dirname(home)):
        if any(os.path.exists(os.path.join(cur, m)) for m in PROJECT_MARKERS):
            return cur
        parent = os.path.dirname(cur)
        if parent == cur:
            break
        cur = parent
    return os.path.realpath(cwd or ".")


def is_meta_or_doc_path(path_str: str) -> bool:
    norm = path_str.replace("\\", "/")
    if "/.gemini/" in norm and "/.gemini/antigravity/scratch/" not in norm:
        return True
    if META_DIR_RE.search(norm):
        return True
    base = os.path.basename(norm)
    return base in {
        "README.md",
        "AGENTS.md",
        "CLAUDE.md",
        "GEMINI.md",
        "REVIEW.md",
        ".gitignore",
        ".windsurfrules",
        ".env.example",
        ".env.sample",
        ".env.template",
    }


DEFAULT_BRANCH_PATTERN = r"([A-Z][A-Z0-9]{1,10}-\d+)"
TREE_SKIP_DIRS = {".git", ".sdlc", "node_modules", "__pycache__", ".venv", "venv", "dist", "build"}


def _read_git_ref_json(abs_root: str, git_ref: str, rel_path: str) -> dict | None:
    try:
        proc = subprocess.run(
            ["git", "-C", abs_root, "show", f"{git_ref}:{rel_path}"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if proc.returncode != 0:
            return None
        loaded = json.loads(proc.stdout)
        return loaded if isinstance(loaded, dict) else None
    except Exception:
        return None


def _normalize_verify_items(verify_cmds: object) -> list[str | list[str]]:
    if isinstance(verify_cmds, str):
        return [verify_cmds] if verify_cmds.strip() else []
    if not isinstance(verify_cmds, list):
        return []
    out: list[str | list[str]] = []
    for c in verify_cmds:
        if isinstance(c, list):
            toks = [str(t) for t in c if str(t)]
            if toks:
                out.append(toks)
        elif str(c).strip():
            out.append(str(c).strip())
    return out


def load_config(project_root: str, git_ref: str | None = None) -> dict:
    """Load declarative per-repo config from `.sdlc/config.json` with repo-root `verigate.json` override.

    When `git_ref` is provided (e.g. target branch `origin/main` in `ci-check`), config is loaded from
    `git_ref` first so an untrusted PR branch cannot weaken its own `gated_paths` or `verify` commands.
    Falls back to the working tree only when neither config file exists on `git_ref`.
    """
    abs_root = os.path.realpath(project_root)
    raw: dict = {}
    config_source = "working_tree"

    if git_ref:
        ref_raw: dict = {}
        for rel_cfg in (".sdlc/config.json", "verigate.json"):
            loaded = _read_git_ref_json(abs_root, git_ref, rel_cfg)
            if loaded:
                ref_raw.update(loaded)
        if ref_raw:
            raw = ref_raw
            config_source = f"base_ref:{git_ref}"
        else:
            config_source = "working_tree_fallback"

    if not raw:
        for cfg_path in (
            os.path.join(abs_root, ".sdlc", "config.json"),
            os.path.join(abs_root, "verigate.json"),
        ):
            if os.path.isfile(cfg_path):
                try:
                    loaded = json.loads(Path(cfg_path).read_text(encoding="utf-8"))
                    if isinstance(loaded, dict):
                        raw.update(loaded)
                except Exception:
                    pass

    gated_paths_raw = raw.get("gated_paths")
    gated_paths: list[dict] = []
    if isinstance(gated_paths_raw, list):
        for item in gated_paths_raw:
            if isinstance(item, dict) and item.get("pattern"):
                gated_paths.append(
                    {
                        "pattern": str(item["pattern"]),
                        "verify": _normalize_verify_items(item.get("verify")),
                        "cwd": str(item.get("cwd") or "."),
                    }
                )

    terraform_dirs_raw = raw.get("terraform_dirs")
    terraform_dirs = (
        [str(d) for d in terraform_dirs_raw if str(d).strip()]
        if isinstance(terraform_dirs_raw, list)
        else []
    )

    require_spec = bool(raw.get("require_spec_approval", False))
    if "require_change_folder_for_gated_paths" in raw:
        require_change_folder = bool(raw.get("require_change_folder_for_gated_paths"))
    else:
        require_change_folder = bool(gated_paths or require_spec)

    fail_on_missing_tool = bool(raw.get("fail_on_missing_tool", True))

    change_id_raw = raw.get("change_id") if isinstance(raw.get("change_id"), dict) else {}
    change_id_cfg = {
        "branch_pattern": str(change_id_raw.get("branch_pattern") or DEFAULT_BRANCH_PATTERN),
    }

    approvers_raw = raw.get("approvers") if isinstance(raw.get("approvers"), dict) else {}
    approvers_cfg = {
        "codeowners_paths": list(approvers_raw.get("codeowners_paths") or [".sdlc/changes/**"]),
        "required_reviewers": list(approvers_raw.get("required_reviewers") or []),
    }

    tracker_raw = raw.get("tracker") if isinstance(raw.get("tracker"), dict) else {}
    tracker_cfg = {
        "provider": str(tracker_raw.get("provider") or "auto"),
        "min_severity": str(tracker_raw.get("min_severity") or "High"),
    }

    return {
        "version": str(raw.get("version") or "3.1.0"),
        "config_source": config_source,
        "require_spec_approval": require_spec,
        "require_change_folder_for_gated_paths": require_change_folder,
        "fail_on_missing_tool": fail_on_missing_tool,
        "change_id": change_id_cfg,
        "gated_paths": gated_paths,
        "approvers": approvers_cfg,
        "tracker": tracker_cfg,
        "terraform_dirs": terraform_dirs,
    }


def _glob_to_regex(pattern: str) -> re.Pattern[str]:
    pat = pattern.replace("\\", "/").lstrip("/")
    while pat.startswith("./"):
        pat = pat[2:]
    i = 0
    n = len(pat)
    res: list[str] = ["^"]
    while i < n:
        ch = pat[i]
        if ch == "*":
            if i + 1 < n and pat[i + 1] == "*":
                while i + 1 < n and pat[i + 1] == "*":
                    i += 1
                if i + 1 < n and pat[i + 1] == "/":
                    res.append("(?:.+/)?")
                    i += 2
                    continue
                res.append(".*")
                i += 1
                continue
            res.append("[^/]*")
            i += 1
        elif ch == "?":
            res.append("[^/]")
            i += 1
        else:
            res.append(re.escape(ch))
            i += 1
    res.append("$")
    return re.compile("".join(res))


def _normalize_rel_path(path_str: str, project_root: str | None = None) -> str:
    p = path_str.replace("\\", "/")
    if project_root and os.path.isabs(path_str):
        try:
            abs_root = os.path.realpath(project_root)
            abs_p = os.path.realpath(path_str)
            rel = os.path.relpath(abs_p, abs_root).replace("\\", "/")
            if not rel.startswith("../") and rel != "..":
                p = rel
        except ValueError:
            pass
    while p.startswith("./"):
        p = p[2:]
    return p.lstrip("/")


def path_matches_glob(rel_path: str, pattern: str) -> bool:
    """Pure-Python glob matcher supporting `**`, `*`, `?` on forward-slash normalized paths."""
    if not rel_path or not pattern:
        return False
    norm_path = _normalize_rel_path(rel_path)
    return bool(_glob_to_regex(pattern).match(norm_path))


def get_effective_gated_rules(config: dict) -> list[dict]:
    rules = list(config.get("gated_paths") or [])
    if not rules:
        for tf_dir in config.get("terraform_dirs") or []:
            clean_dir = str(tf_dir).replace("\\", "/").strip("/")
            pat = f"{clean_dir}/**" if clean_dir and clean_dir != "." else "**/*.tf"
            rules.append(
                {
                    "pattern": pat,
                    "verify": ["terraform fmt -check -recursive", "terraform validate"],
                    "cwd": clean_dir or ".",
                }
            )
    return rules


def is_path_gated(rel_path: str, config: dict) -> bool:
    norm = _normalize_rel_path(rel_path)
    if not norm or is_meta_or_doc_path(norm) or norm == "verigate.json":
        return False
    rules = get_effective_gated_rules(config)
    if rules:
        return any(path_matches_glob(norm, r["pattern"]) for r in rules)
    return True


def matched_gated_rules(rel_paths: list[str] | None, config: dict) -> list[dict]:
    rules = get_effective_gated_rules(config)
    if rel_paths is None:
        return rules
    norm_paths = [_normalize_rel_path(p) for p in rel_paths if p]
    return [
        r
        for r in rules
        if any(
            not is_meta_or_doc_path(p) and path_matches_glob(p, r["pattern"])
            for p in norm_paths
        )
    ]


def collect_gated_files(project_root: str, config: dict) -> list[str]:
    abs_root = os.path.realpath(project_root)
    gated: list[str] = []
    for root, dirs, files in os.walk(abs_root):
        dirs[:] = sorted(d for d in dirs if d not in TREE_SKIP_DIRS)
        for fname in sorted(files):
            full = os.path.join(root, fname)
            rel = os.path.relpath(full, abs_root).replace("\\", "/")
            if is_path_gated(rel, config):
                gated.append(rel)
    gated.sort()
    return gated


def _git_head_commit(project_root: str) -> str:
    abs_root = os.path.realpath(project_root)
    try:
        proc = subprocess.run(
            ["git", "-C", abs_root, "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            return proc.stdout.strip()
    except Exception:
        pass
    return "UNCOMMITTED"


def compute_tree_digest(project_root: str, config: dict, target_files: list[str] | None = None) -> str:
    abs_root = os.path.realpath(project_root)
    if target_files is not None:
        rel_paths = sorted({_normalize_rel_path(f, abs_root) for f in target_files if f})
    else:
        rel_paths = collect_gated_files(abs_root, config)
    h = hashlib.sha256()
    for rel in rel_paths:
        full = os.path.join(abs_root, rel)
        d = file_sha256(full) or "MISSING"
        h.update(f"{rel}:{d}\n".encode("utf-8"))
    return h.hexdigest()


def _split_verify_command(cmd: str | list[str]) -> tuple[list[str], str]:
    """Parse a verify command (list form or string form) preserving Windows backslashes."""
    if isinstance(cmd, list):
        argv = [str(tok) for tok in cmd if str(tok)]
        return argv, " ".join(argv)
    cmd_str = str(cmd).strip()
    if not cmd_str:
        return [], ""
    use_posix = (os.name != "nt") and not re.search(r"[A-Za-z]:\\", cmd_str)
    tokens = shlex.split(cmd_str, posix=use_posix)
    if not use_posix:
        tokens = [_strip_quotes(t) for t in tokens]
    return tokens, cmd_str


def run_verify_rules(project_root: str, rules: list[dict], fail_on_missing_tool: bool) -> tuple[bool, list[dict]]:
    """Execute configured verify commands directly with shell=False and real OS exit codes."""
    abs_root = os.path.realpath(project_root)
    results: list[dict] = []
    for rule in rules:
        pattern = str(rule.get("pattern") or "**")
        cwd_rel = str(rule.get("cwd") or ".")
        rule_cwd = os.path.realpath(os.path.join(abs_root, cwd_rel))
        cmds = rule.get("verify") or []
        if isinstance(cmds, str):
            cmds = [cmds]
        for cmd in cmds:
            try:
                argv, cmd_str = _split_verify_command(cmd)
            except ValueError as exc:
                results.append(
                    {
                        "pattern": pattern,
                        "command": str(cmd),
                        "cwd": cwd_rel,
                        "exit_code": 2,
                        "missing_tool": False,
                        "skipped_missing_tool": False,
                        "passed": False,
                        "duration_ms": 0,
                        "stdout_tail": "",
                        "stderr_tail": f"Invalid command syntax: {exc}",
                    }
                )
                continue
            if not argv:
                continue
            t0 = time.monotonic()
            missing_tool = False
            skipped_missing_tool = False
            if not os.path.isdir(rule_cwd):
                exit_code = 1
                stdout_tail = ""
                stderr_tail = f"Working directory not found: {rule_cwd}"
                passed = False
            else:
                try:
                    proc = subprocess.run(
                        argv,
                        shell=False,
                        cwd=rule_cwd,
                        capture_output=True,
                        text=True,
                    )
                    exit_code = proc.returncode
                    stdout_tail = (proc.stdout or "")[-2000:]
                    stderr_tail = (proc.stderr or "")[-2000:]
                    if exit_code == 127:
                        missing_tool = True
                except FileNotFoundError:
                    exit_code = 127
                    missing_tool = True
                    stdout_tail = ""
                    stderr_tail = f"Command not found: {argv[0]}"
                if missing_tool:
                    if fail_on_missing_tool:
                        passed = False
                    else:
                        passed = True
                        skipped_missing_tool = True
                else:
                    passed = exit_code == 0
            duration_ms = int((time.monotonic() - t0) * 1000)
            results.append(
                {
                    "pattern": pattern,
                    "command": cmd_str,
                    "cwd": cwd_rel,
                    "exit_code": exit_code,
                    "missing_tool": missing_tool,
                    "skipped_missing_tool": skipped_missing_tool,
                    "passed": passed,
                    "duration_ms": duration_ms,
                    "stdout_tail": stdout_tail,
                    "stderr_tail": stderr_tail,
                }
            )
    all_passed = all(r["passed"] for r in results)
    return all_passed, results


def sanitize_change_id(raw: str | None, strict: bool = True) -> str | None:
    if not raw:
        return None
    val = raw.strip()
    if not val:
        return None
    if val in (".", "..") or ".." in val or not CHANGE_ID_RE.match(val):
        if strict:
            raise ValueError(f"Invalid change ID `{raw}`: must match [a-zA-Z0-9._-]+ without '..'.")
        return None
    return val


def _branch_ticket_id(project_root: str, config: dict | None = None) -> str | None:
    root = os.path.realpath(project_root)
    branch = ""
    for git_args in (
        ["git", "-C", root, "symbolic-ref", "--short", "HEAD"],
        ["git", "-C", root, "rev-parse", "--abbrev-ref", "HEAD"],
    ):
        try:
            proc = subprocess.run(git_args, capture_output=True, text=True, timeout=3)
            if proc.returncode == 0 and proc.stdout.strip():
                branch = proc.stdout.strip()
                break
        except Exception:
            continue
    if not branch or branch in ("main", "master", "HEAD"):
        return None
    cfg = config if config is not None else load_config(root)
    pat = ((cfg.get("change_id") or {}).get("branch_pattern") or "").strip()
    if pat and pat != DEFAULT_BRANCH_PATTERN:
        try:
            m = re.search(pat, branch)
            if m:
                raw_id = m.group(1) if m.lastindex else m.group(0)
                return sanitize_change_id(raw_id, strict=False)
            return None
        except re.error:
            pass
    m = BRANCH_TICKET_RE.search(branch)
    if m:
        return sanitize_change_id(m.group(1), strict=False)
    return None


def resolve_change_id(project_root: str, explicit_change: str | None = None, strict: bool = False) -> str | None:
    if explicit_change is not None and explicit_change.strip():
        return sanitize_change_id(explicit_change, strict=True)
    env_change = os.environ.get("VERIGATE_CHANGE")
    if env_change and env_change.strip():
        return sanitize_change_id(env_change, strict=strict)
    active_file = os.path.join(os.path.realpath(project_root), ".sdlc", "active-change")
    if os.path.isfile(active_file):
        try:
            for line in Path(active_file).read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    return sanitize_change_id(line, strict=False)
        except OSError:
            pass
    return _branch_ticket_id(project_root)


def resolve_artifact_dir(project_root: str, change_id: str | None = None, strict: bool = False) -> tuple[str, str, str | None]:
    abs_root = os.path.realpath(project_root)
    cid = resolve_change_id(abs_root, change_id, strict=strict)
    if cid:
        rel_dir = f".sdlc/changes/{cid}"
        abs_dir = os.path.join(abs_root, ".sdlc", "changes", cid)
        return abs_dir, rel_dir, cid
    return os.path.join(abs_root, ".sdlc"), ".sdlc", None


def check_required_change_folder(
    project_root: str,
    touched_rel_paths: list[str],
    config: dict,
    change_id: str | None = None,
) -> tuple[bool, str]:
    """Fail closed when gated paths are modified without an active `.sdlc/changes/<id>/{intent.md,spec.md}`."""
    abs_root = os.path.realpath(project_root)
    norm_paths = [_normalize_rel_path(p, abs_root) for p in touched_rel_paths if p]
    gated_touched = [p for p in norm_paths if is_path_gated(p, config)]
    if not gated_touched:
        return True, "No gated paths touched."
    if not config.get("require_change_folder_for_gated_paths", False):
        return True, "Change folder not required by config."

    cid = resolve_change_id(abs_root, change_id)
    has_explicit_gated_rules = bool(get_effective_gated_rules(config))
    if not cid and not has_explicit_gated_rules:
        # Backward compatibility for v2.x root `.sdlc/{intent.md,spec.md}` layout when `gated_paths` is not configured
        root_intent = os.path.join(abs_root, ".sdlc", "intent.md")
        root_spec = os.path.join(abs_root, ".sdlc", "spec.md")
        if os.path.isfile(root_intent) and os.path.isfile(root_spec):
            return True, "Legacy `.sdlc/{intent.md,spec.md}` present."

    sample = ", ".join(gated_touched[:3])
    if not cid:
        pat = ((config.get("change_id") or {}).get("branch_pattern") or DEFAULT_BRANCH_PATTERN)
        return (
            False,
            f"Gated path(s) modified ({sample}) without an active change ID. "
            f"Use a branch matching `{pat}`, set `.sdlc/active-change`, or pass `--change <ID>` "
            "and create `.sdlc/changes/<ID>/intent.md` + `spec.md`.",
        )

    change_dir = os.path.join(abs_root, ".sdlc", "changes", cid)
    intent_path = os.path.join(change_dir, "intent.md")
    spec_path = os.path.join(change_dir, "spec.md")
    if not os.path.isfile(intent_path):
        return (
            False,
            f"Missing required `.sdlc/changes/{cid}/intent.md` for gated path(s) ({sample}).",
        )
    if not os.path.isfile(spec_path):
        return (
            False,
            f"Missing required `.sdlc/changes/{cid}/spec.md` for gated path(s) ({sample}).",
        )
    return True, f"Change folder `.sdlc/changes/{cid}` verified for gated paths."


def _shadow_project_key(abs_root: str, change_id: str | None = None) -> str:
    return f"{abs_root}::change::{change_id}" if change_id else abs_root


def validate_intent(text: str) -> tuple[bool, str]:
    s = text.strip()
    if len(s) < 200:
        return (
            False,
            "Intent must be >=200 chars with Scope/Goal/Problem, Constraints/Edge-Cases/Non-Goals, and AC-1 & AC-2.",
        )
    if not re.search(r"\b(scope|goal|goals|problem|objective|overview)\b", s, re.I):
        return False, "Intent must include a Scope / Goal / Problem section."
    if not re.search(r"\b(constraints?|edge[- ]cases?|non[- ]goals?|out[- ]of[- ]scope)\b", s, re.I):
        return False, "Intent must include a Constraints / Edge-Cases / Non-Goals section."
    if not (re.search(r"\bAC[-_ ]?1\b", s, re.I) and re.search(r"\bAC[-_ ]?2\b", s, re.I)):
        return False, "Intent must define at least `AC-1` and `AC-2` Acceptance Criteria."
    return True, "valid"


def validate_spec(text: str) -> tuple[bool, str]:
    s = text.strip()
    if len(s) < 250:
        return (
            False,
            "Spec must be >=250 chars with Architecture/Module/Contract, Security/Guardrails, and Verification Matrix referencing AC-1.",
        )
    if not re.search(r"\b(architecture|module|component|contract|schema)\b", s, re.I):
        return False, "Spec must include an Architecture / Module / Contract section."
    if not re.search(
        r"\b(security|guardrails?|threat|auth(?:n|z|entication|orization)?|access[- ]control|hardening)\b",
        s,
        re.I,
    ):
        return False, "Spec must include a Security / Guardrails section."
    if not (re.search(r"\b(verif(?:ication)?|test\s+matrix|test\s+plan)\b", s, re.I) and re.search(r"\bAC[-_ ]?1\b", s, re.I)):
        return False, "Spec must include a Verification Matrix referencing `AC-1`."
    return True, "valid"


def _read_git_head_approval_hash(abs_root: str, stage_key: str, rel_approvals: str = ".sdlc/approvals.json") -> str | None:
    """Fallback for fresh git clones / worktrees / CI runners where local shadow ledger has no entry yet."""
    try:
        proc = subprocess.run(
            ["git", "-C", abs_root, "show", f"HEAD:{rel_approvals}"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if proc.returncode != 0:
            return None
        committed = json.loads(proc.stdout)
        return ((committed.get("approvals") or {}).get(stage_key) or {}).get("sha256")
    except Exception:
        return None


def verify_stage_approval(
    project_root: str,
    stage_key: str,
    rel_artifact: str | None = None,
    change_id: str | None = None,
    prefer_git_head: bool = False,
) -> tuple[bool, str]:
    abs_root = os.path.realpath(project_root)
    art_dir, rel_dir, cid = resolve_artifact_dir(abs_root, change_id)
    if not rel_artifact:
        rel_artifact = f"{rel_dir}/{'intent.md' if stage_key == 'S1_PLAN' else 'spec.md'}"
    rel_approvals = f"{rel_dir}/approvals.json"
    art_path = os.path.join(abs_root, rel_artifact)
    if not os.path.isfile(art_path):
        return False, f"Missing `{rel_artifact}` (`{art_path}`)."

    content = Path(art_path).read_text(encoding="utf-8")
    ok, msg = validate_intent(content) if stage_key == "S1_PLAN" else validate_spec(content)
    if not ok:
        return False, f"Incomplete `{rel_artifact}`: {msg}"

    live_hash = file_sha256(art_path)
    approvals_file = os.path.join(art_dir, "approvals.json")
    change_flag = f" --change {cid}" if cid else ""
    if not os.path.isfile(approvals_file):
        return (
            False,
            f"`{rel_artifact}` (sha256 `{live_hash[:12]}`) is unapproved. Review and run: `python3 .sdlc/bin/verigate.py approve --project .{change_flag} --stage S1_S2`.",
        )

    try:
        repo_app = json.loads(Path(approvals_file).read_text(encoding="utf-8"))
    except Exception:
        return False, f"Corrupted `{rel_approvals}`."

    repo_entry = (repo_app.get("approvals") or {}).get(stage_key) or {}
    if not repo_entry:
        return False, f"No approval entry for `{stage_key}` (`{rel_artifact}`). Run `verigate.py approve{change_flag}`."

    if prefer_git_head:
        trusted_hash = _read_git_head_approval_hash(abs_root, stage_key, rel_approvals)
    else:
        shadow_key = _shadow_project_key(abs_root, cid)
        shadow_entry = (
            (((load_shadow_ledger().get("projects") or {}).get(shadow_key) or {}).get("approvals") or {}).get(stage_key)
            or {}
        )
        trusted_hash = shadow_entry.get("sha256")
        if not trusted_hash:
            # On a fresh team clone, git worktree, or CI runner, trust HEAD-committed approvals.json
            trusted_hash = _read_git_head_approval_hash(abs_root, stage_key, rel_approvals)

    if not trusted_hash:
        return False, f"No verified human approval for `{stage_key}` (`{rel_artifact}`). Run `verigate.py approve{change_flag}`."
    if repo_entry.get("sha256") != trusted_hash:
        return False, f"Ledger mismatch for `{rel_artifact}`; re-run `verigate.py approve{change_flag}`."
    if live_hash != trusted_hash:
        return (
            False,
            f"STALE APPROVAL on `{rel_artifact}` (approved `{trusted_hash[:12]}`, current `{live_hash[:12]}`). Re-approve via `verigate.py approve{change_flag}`.",
        )
    return True, f"Approved ({live_hash[:12]})"


def classify_prompt(text: str) -> dict | None:
    if not text or len(text.strip()) < 4:
        return None
    if REVIEW_ONLY_RE.search(text):
        return {"profile": "Code Review & Triage", "code": "review", "enforce_spec": False}
    if GREENFIELD_RE.search(text):
        return {"profile": "Greenfield Solution", "code": "greenfield", "enforce_spec": True}
    if FEATURE_RE.search(text):
        return {"profile": "Feature / Architecture Delta", "code": "feature", "enforce_spec": True}
    if CHANGE_RE.search(text):
        return {"profile": "Incremental Change / Fix", "code": "change", "enforce_spec": False}
    return None


def render_dispatch_table(info: dict, rel_dir: str = ".sdlc") -> str:
    code = info["code"]
    s12 = "🟢 Required + SHA-256 Approval" if info["enforce_spec"] else "⚪ Bypassed"
    s34 = "🟡 On Fix" if code == "review" else ("🔒 Locked until S1+S2 Approved" if info["enforce_spec"] else "🟢 Active")
    return "\n".join(
        [
            "### ⚡ VeriGate AI-SDLC — Deterministic Stage & Role Dispatch",
            f"**Scope Profile:** `{info['profile']}` | **Spec SHA-256 Gate:** `{'ON' if info['enforce_spec'] else 'OFF'}`",
            "",
            "| Stage | Phase | Role / Agent | Verified Artifact | Gate Status |",
            "| :--- | :--- | :--- | :--- | :--- |",
            f"| **S1** | Plan | `verigate-requirements` | `{rel_dir}/intent.md` (`AC-1..AC-N`) | {s12} |",
            f"| **S2** | Design | `verigate-architect` | `{rel_dir}/spec.md` (Contracts & Matrix) | {s12} |",
            f"| **S3** | Build | `verigate-builder` | Modular Source Code | {s34} |",
            f"| **S4** | Verify | `verigate-verifier` | Executed Tests (or Logged Waiver) | 🟢 Enforced |",
            f"| **S5** | Review | `verigate-reviewer` + `verigate-sentinel` | `{rel_dir}/review-findings.json` + `report.md` | 🟢 Enforced |",
            "| **S6** | Triage | `issue_bridge.py` + Human | GitHub / Azure DevOps + Immediate Fix | 🟢 Dual-Action |",
        ]
    )


def is_spec_lock_active(proj_root: str, session: dict, change_id: str | None = None) -> bool:
    abs_root = os.path.realpath(proj_root)
    art_dir, _rel_dir, _cid = resolve_artifact_dir(abs_root, change_id)
    cfg = load_config(abs_root)
    cfg_enforce = bool(cfg.get("require_spec_approval", False))
    return (
        bool(session.get("enforceSpec", False))
        or cfg_enforce
        or os.path.isfile(os.path.join(art_dir, "intent.md"))
        or os.path.isfile(os.path.join(abs_root, ".sdlc", "intent.md"))
    )


def _strip_quoted_strings(cmd: str) -> str:
    """Replace single- and double-quoted string contents with empty quotes ('' / \"\")."""
    out: list[str] = []
    i = 0
    n = len(cmd)
    quote: str | None = None
    while i < n:
        ch = cmd[i]
        if quote is None:
            if ch == "\\" and i + 1 < n:
                out.append(ch)
                out.append(cmd[i + 1])
                i += 2
                continue
            if ch in ("'", '"'):
                quote = ch
                out.append(ch)
                i += 1
                continue
            out.append(ch)
            i += 1
        elif quote == "'":
            if ch == "'":
                out.append("'")
                quote = None
            i += 1
        else:
            if ch == "\\" and i + 1 < n:
                i += 2
                continue
            if ch == '"':
                out.append('"')
                quote = None
            i += 1
    if quote is not None:
        out.append(quote)
    return "".join(out)


def _split_shell_segments(cmd: str) -> list[str]:
    """Split shell/PowerShell command on unquoted &&, ||, ;, |, or newlines."""
    segments: list[str] = []
    buf: list[str] = []
    i = 0
    n = len(cmd)
    quote: str | None = None
    while i < n:
        ch = cmd[i]
        if quote is None:
            if ch == "\\" and i + 1 < n:
                buf.append(ch)
                buf.append(cmd[i + 1])
                i += 2
                continue
            if ch in ("'", '"'):
                quote = ch
                buf.append(ch)
                i += 1
                continue
            if ch in (";", "\n"):
                seg = "".join(buf).strip()
                if seg:
                    segments.append(seg)
                buf = []
                i += 1
                continue
            if ch == "&" and i + 1 < n and cmd[i + 1] == "&":
                seg = "".join(buf).strip()
                if seg:
                    segments.append(seg)
                buf = []
                i += 2
                continue
            if ch == "|":
                seg = "".join(buf).strip()
                if seg:
                    segments.append(seg)
                buf = []
                i += 2 if (i + 1 < n and cmd[i + 1] == "|") else 1
                continue
            buf.append(ch)
            i += 1
        elif quote == "'":
            buf.append(ch)
            if ch == "'":
                quote = None
            i += 1
        else:
            if ch == "\\" and i + 1 < n:
                buf.append(ch)
                buf.append(cmd[i + 1])
                i += 2
                continue
            buf.append(ch)
            if ch == '"':
                quote = None
            i += 1
    tail = "".join(buf).strip()
    if tail:
        segments.append(tail)
    return segments


def _normalize_prog_name(tok: str) -> str:
    name = os.path.basename(tok.replace("\\", "/")).lower()
    for ext in (".exe", ".cmd", ".bat", ".ps1"):
        if name.endswith(ext):
            name = name[: -len(ext)]
            break
    return name


def _segment_is_test_runner(seg: str) -> bool:
    toks = [_strip_quotes(t) for t in _safe_split(seg, posix=False)]
    while toks:
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", toks[0]):
            toks.pop(0)
            continue
        prog = _normalize_prog_name(toks[0])
        if prog == "env":
            toks.pop(0)
            while toks:
                if toks[0] in ("-u", "--unset", "-C", "--chdir") and len(toks) >= 2:
                    toks = toks[2:]
                elif toks[0].startswith("-") or re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", toks[0]):
                    toks.pop(0)
                else:
                    break
            continue
        if prog in ("uv", "poetry") and len(toks) >= 2 and toks[1].lower() == "run":
            toks = toks[2:]
            while toks and toks[0].startswith("-"):
                toks.pop(0)
            continue
        if prog in ("npx", "bunx"):
            toks.pop(0)
            while toks and toks[0].startswith("-"):
                toks.pop(0)
            continue
        if prog in ("pnpm", "yarn") and len(toks) >= 2 and toks[1].lower() == "exec":
            toks = toks[2:]
            while toks and toks[0].startswith("-"):
                toks.pop(0)
            continue
        break

    if not toks:
        return False

    prog = _normalize_prog_name(toks[0])
    args = [a.lower() for a in toks[1:]]
    raw_args = toks[1:]

    # Help, version, and dry-collection flags never execute real tests
    if any(a in ("-h", "--help", "--version", "--collect-only", "--co") for a in args) or "-V" in raw_args:
        return False

    if PYTHON_PROGS_RE.match(prog):
        i = 0
        while i < len(args):
            a = args[i]
            if a == "-m":
                if i + 1 < len(args):
                    mod = args[i + 1]
                    rest = args[i + 2 :]
                    if mod in PYTHON_TEST_MODULES:
                        return True
                    if mod == "ruff" and rest and rest[0] == "check":
                        return True
                return False
            if a in ("-c", "-"):
                return False
            if a.startswith("-"):
                if a in ("-w", "-x") and i + 1 < len(args):
                    i += 2
                else:
                    i += 1
                continue
            return False
        return False

    if prog in SINGLE_TOKEN_TEST_RUNNERS:
        return True

    if prog in ("npm", "pnpm", "yarn", "bun"):
        if not args:
            return False
        if args[0] == "test" or (args[0] == "run" and len(args) >= 2 and args[1] == "test"):
            return True
        if prog in ("pnpm", "yarn", "bun") and args[0] in SINGLE_TOKEN_TEST_RUNNERS:
            return True
        return False

    if prog in ("cargo", "go", "mvn", "mvnw", "gradle", "gradlew", "dotnet", "conftest"):
        return bool(args and args[0] == "test")

    if prog == "ruff":
        return bool(args and args[0] == "check")

    if prog == "terraform":
        if not args:
            return False
        if args[0] in ("validate", "test"):
            return True
        if args[0] == "fmt":
            return any(a in ("-check", "-check=true") for a in args[1:])
        return False

    if prog == "opa":
        return bool(args and args[0] in ("test", "eval"))

    return False


def _is_readonly_shell_command(cmd: str) -> bool:
    """Return True if every segment is a pure read-only file/dir inspector with no redirections or subshells."""
    if not cmd or not cmd.strip():
        return False
    unquoted = _strip_quoted_strings(cmd)
    if re.search(r"[|<>`\n]|(?<!&)&(?!&)|\$\(", unquoted):
        return False
    if re.search(r"(shadow_ledger\.json|verigate-shadow)", cmd, re.IGNORECASE):
        return False
    segs = _split_shell_segments(cmd)
    if not segs:
        return False
    for seg in segs:
        toks = [_strip_quotes(t) for t in _safe_split(seg, posix=False)]
        if not toks:
            return False
        prog = _normalize_prog_name(toks[0])
        if prog not in READONLY_SHELL_PROGS:
            return False
    return True


def is_real_test_runner_command(cmd: str) -> bool:
    """Return True only for an unchained test runner (or `cd ... && <test-runner>` where the test is final)."""
    if not cmd or not cmd.strip():
        return False
    unquoted = _strip_quoted_strings(cmd)
    if ERROR_SWALLOW_RE.search(unquoted):
        return False
    # Reject ;, ||, |, newline, or background & (excluding fd redirects like 2>&1 and &&)
    no_fd_redir = re.sub(r"[012&]>&[012]", "", unquoted)
    if re.search(r"[;|\n]|(?<!&)&(?!&)", no_fd_redir):
        return False
    segments = _split_shell_segments(cmd)
    if not segments:
        return False
    # The final command MUST be the test runner so no trailing command can mask a non-zero exit code
    return _segment_is_test_runner(segments[-1])


def _strip_quotes(token: str) -> str:
    if len(token) >= 2 and token[0] == token[-1] and token[0] in ("'", '"'):
        return token[1:-1]
    return token


def _safe_split(seg: str, posix: bool = True) -> list[str]:
    try:
        return shlex.split(seg, posix=posix)
    except ValueError:
        return seg.split()


def _extract_redirection_targets(seg: str) -> list[str]:
    """Extract target filenames following unquoted shell redirections (> / >>), excluding >& redirects."""
    targets: list[str] = []
    i = 0
    n = len(seg)
    quote: str | None = None
    while i < n:
        ch = seg[i]
        if quote is None:
            if ch == "\\" and i + 1 < n:
                i += 2
                continue
            if ch in ("'", '"'):
                quote = ch
                i += 1
                continue
            if ch == ">":
                prev = seg[i - 1] if i > 0 else ""
                if prev == ">":
                    i += 1
                    continue
                j = i + 1
                if j < n and seg[j] == ">":
                    j += 1
                while j < n and seg[j].isspace():
                    j += 1
                if j < n and seg[j] == "&":
                    i = j + 1
                    continue
                if j < n:
                    if seg[j] in ("'", '"'):
                        q = seg[j]
                        k = j + 1
                        buf: list[str] = []
                        while k < n:
                            if q == '"' and seg[k] == "\\" and k + 1 < n:
                                buf.append(seg[k + 1])
                                k += 2
                                continue
                            if seg[k] == q:
                                k += 1
                                break
                            buf.append(seg[k])
                            k += 1
                        t = "".join(buf).strip()
                        if t:
                            targets.append(t)
                        i = k
                        continue
                    k = j
                    while k < n and not seg[k].isspace() and seg[k] not in ";|&><'\"":
                        k += 1
                    t = seg[j:k].strip()
                    if t:
                        targets.append(t)
                    i = k
                    continue
                i = j
                continue
            i += 1
        elif quote == "'":
            if ch == "'":
                quote = None
            i += 1
        else:
            if ch == "\\" and i + 1 < n:
                i += 2
                continue
            if ch == '"':
                quote = None
            i += 1
    return targets


def extract_shell_write_targets(cmd: str) -> tuple[bool, list[str]]:
    """Detect shell/PowerShell file writes and extract target path(s)."""
    if not cmd or not cmd.strip():
        return False, []
    is_write = False
    targets: list[str] = []
    null_targets = {"/dev/null", "nul", "$null", "/dev/stdout", "/dev/stderr"}

    for seg in _split_shell_segments(cmd):
        if not seg:
            continue
        unquoted_seg = _strip_quoted_strings(seg)

        # 1. Unquoted shell redirections (> / >>), excluding >& redirects and null sinks
        if UNQUOTED_REDIRECT_RE.search(unquoted_seg):
            for target in _extract_redirection_targets(seg):
                if target and target.lower() not in null_targets:
                    is_write = True
                    targets.append(target)

        # 2. Inline Python open(..., 'w'/'a')
        if re.search(r"\b(?:python(?:3(?:\.\d+)?)?|py)\b.*\bopen\s*\([^)]*['\"][wa]", seg, re.IGNORECASE):
            is_write = True
            for m in re.finditer(
                r"\bopen\s*\(\s*r?[\"']([^\"']+)[\"']\s*,\s*(?:mode\s*=\s*)?[\"'][wa]",
                seg,
                re.IGNORECASE,
            ):
                targets.append(m.group(1))

        # 3. PowerShell write cmdlets (Set-Content, Add-Content, Out-File, Copy-Item, Move-Item)
        ps_m = PS_WRITE_CMDLET_RE.search(unquoted_seg)
        if ps_m:
            is_write = True
            cmdlet = ps_m.group(1).lower()
            param_m = re.search(
                r"-(?:Path|LiteralPath|FilePath|Destination)\s+(?:[\"']([^\"']+)[\"']|([^\s;|&'\"]+))",
                seg,
                re.IGNORECASE,
            )
            if param_m:
                targets.append((param_m.group(1) or param_m.group(2) or "").strip())
            else:
                ps_toks = _safe_split(seg, posix=False)
                idx = next((i for i, t in enumerate(ps_toks) if t.lower() == cmdlet), -1)
                if idx >= 0:
                    pos_args: list[str] = []
                    skip_next = False
                    for tok in ps_toks[idx + 1 :]:
                        if skip_next:
                            skip_next = False
                            continue
                        if tok.startswith("-"):
                            if tok.lower() in ("-value", "-encoding", "-inputobject", "-filter", "-include", "-exclude"):
                                skip_next = True
                            continue
                        pos_args.append(_strip_quotes(tok))
                    if pos_args:
                        targets.append(pos_args[-1] if cmdlet in ("copy-item", "move-item") else pos_args[0])

        # 4. POSIX write commands (tee, sed -i, perl -i, cp, mv)
        toks = _safe_split(seg, posix=True)
        while toks and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", toks[0]):
            toks.pop(0)
        if not toks:
            continue
        prog = os.path.basename(toks[0]).lower()
        args = toks[1:]

        if prog == "tee":
            is_write = True
            for a in args:
                if not a.startswith("-") and a.lower() not in null_targets:
                    targets.append(a)
        elif prog == "sed":
            if any(a == "-i" or a.startswith("-i") or a == "--in-place" or a.startswith("--in-place=") for a in args):
                is_write = True
                pos: list[str] = []
                has_expr_flag = False
                skip_next = False
                for a in args:
                    if skip_next:
                        skip_next = False
                        continue
                    if a in ("-e", "-f"):
                        has_expr_flag = True
                        skip_next = True
                        continue
                    if a.startswith("-"):
                        continue
                    if a:
                        pos.append(a)
                if has_expr_flag and pos:
                    targets.extend(pos)
                elif len(pos) >= 2:
                    targets.extend(pos[1:])
        elif prog == "perl":
            if any(re.match(r"^-[a-zA-Z]*i", a) for a in args):
                is_write = True
                pos = []
                skip_next = False
                for a in args:
                    if skip_next:
                        skip_next = False
                        continue
                    if a in ("-e", "-E", "-I", "-M", "-m"):
                        skip_next = True
                        continue
                    if a.startswith("-"):
                        continue
                    if a:
                        pos.append(a)
                targets.extend(pos)
        elif prog in ("cp", "mv"):
            is_write = True
            pos = []
            dest_t = None
            skip_next = False
            for a in args:
                if skip_next:
                    dest_t = a
                    skip_next = False
                    continue
                if a in ("-t", "--target-directory"):
                    skip_next = True
                    continue
                if a.startswith("-"):
                    continue
                pos.append(a)
            if dest_t:
                targets.append(dest_t)
            elif len(pos) >= 2:
                targets.append(pos[-1])

    # Deduplicate while preserving order
    seen: set[str] = set()
    deduped: list[str] = []
    for t in targets:
        if t and t not in seen:
            seen.add(t)
            deduped.append(t)
    return is_write, deduped


def evaluate_file_write(
    path_str: str,
    session: dict,
    cwd: str | None = None,
    change_id: str | None = None,
) -> tuple[str, str]:
    full_path = normalize_target_path(path_str, cwd)
    norm = full_path.replace("\\", "/")
    base = os.path.basename(norm)
    ext = os.path.splitext(base)[1].lower()

    if PROTECTED_LEDGER_RE.search(norm) or "verigate-shadow" in norm:
        return "deny", f"[VeriGate Integrity Gate] Direct edits to control-plane/ledger file `{base}` are blocked."

    if base.lower() not in ALLOWED_ENV_EXAMPLES and (SECRET_BASENAME_RE.match(base) or ext in SECRET_EXTS):
        return "deny", f"[VeriGate Secret Gate] Writing credential/key file `{base}` is blocked. Use `.env.example` or env vars."

    if GOVERNANCE_RE.search(norm):
        return "ask", f"[VeriGate Governance Gate] Modifying `{base}` requires explicit human approval."

    if is_meta_or_doc_path(full_path):
        return "allow", ""

    proj_root = resolve_project_root(full_path, cwd)
    config = load_config(proj_root)
    rel_path = _normalize_rel_path(full_path, proj_root)
    rules = get_effective_gated_rules(config)
    if rules:
        if not any(path_matches_glob(rel_path, r["pattern"]) for r in rules):
            return "allow", ""
        if config.get("require_change_folder_for_gated_paths", False):
            ok_cf, msg_cf = check_required_change_folder(proj_root, [rel_path], config, change_id=change_id)
            if not ok_cf:
                return "deny", f"[VeriGate Change Folder Gate] Blocked `{base}`: {msg_cf}"

    if is_spec_lock_active(proj_root, session, change_id):
        _art_dir, rel_dir, cid = resolve_artifact_dir(proj_root, change_id)
        ok1, m1 = verify_stage_approval(proj_root, "S1_PLAN", f"{rel_dir}/intent.md", change_id=cid)
        if not ok1:
            return "deny", f"[VeriGate S1 Gate] Blocked `{base}`: {m1}"
        ok2, m2 = verify_stage_approval(proj_root, "S2_DESIGN", f"{rel_dir}/spec.md", change_id=cid)
        if not ok2:
            return "deny", f"[VeriGate S2 Gate] Blocked `{base}`: {m2}"

    return "allow", ""


def evaluate_shell_command(
    cmd: str,
    session: dict | None = None,
    cwd: str | None = None,
    change_id: str | None = None,
) -> tuple[str, str]:
    if GIT_NO_VERIFY_RE.search(cmd):
        return "deny", "[VeriGate Integrity Gate] Bypassing git hooks with `--no-verify` / `-n` is blocked."

    m_secret = SHELL_SECRET_WRITE_RE.search(cmd)
    if m_secret and m_secret.group(1).lower() not in ALLOWED_ENV_EXAMPLES:
        return "deny", f"[VeriGate Secret Gate] Shell write to sensitive file `{m_secret.group(1)}` is blocked."

    if not SHELL_CHAIN_OR_REDIRECT_RE.search(cmd):
        m = SANCTIONED_GATE_CMD_RE.match(cmd)
        if m:
            subcmd = m.group(1)
            if subcmd in ("status", "validate", "dispatch", "merge-check", "verify", "ci-check"):
                return "allow", ""
            if subcmd == "approve":
                return "force_ask", "[VeriGate Approval Gate] Confirm human review of intent & spec SHA-256 digests."
            if subcmd == "waive":
                return "force_ask", "[VeriGate Waiver Gate] Confirm recording a logged Stage Waiver in `waivers.jsonl`."
        mb = SANCTIONED_BRIDGE_CMD_RE.match(cmd)
        if mb:
            subcmd = mb.group(1)
            if subcmd in ("detect", "preview"):
                return "allow", ""
            if subcmd == "create":
                return "force_ask", "[VeriGate External Gate] Confirm creating GitHub Issues / Azure DevOps Work Items via `issue_bridge.py`."

    if ANY_VERIGATE_INVOCATION_RE.search(cmd):
        return (
            "deny",
            "[VeriGate Integrity Gate] Invoking `verigate.py` with shell chaining, redirection, or wrappers is blocked. Run standalone: `python3 .sdlc/bin/verigate.py <status|validate|approve|waive|dispatch|verify|ci-check>`.",
        )

    if ANY_BRIDGE_INVOCATION_RE.search(cmd):
        return (
            "deny",
            "[VeriGate Integrity Gate] Invoking `issue_bridge.py` with shell chaining, redirection, or wrappers is blocked. Run standalone: `python3 .sdlc/bin/issue_bridge.py <detect|preview|create>`.",
        )

    if _is_readonly_shell_command(cmd):
        return "allow", ""

    if LEDGER_TAMPER_CMD_RE.search(cmd):
        return "deny", "[VeriGate Integrity Gate] Direct shell access to `.sdlc` ledgers or hook configs is forbidden."

    if EXTERNAL_MUTATION_CMD_RE.search(cmd):
        return "force_ask", "[VeriGate External Gate] Creating GitHub/Azure DevOps tickets, PRs, or pushing requires human confirmation."

    is_write, targets = extract_shell_write_targets(cmd)
    if is_write:
        non_meta = [t for t in targets if not is_meta_or_doc_path(normalize_target_path(t, cwd))]
        if non_meta or not targets:
            anchor = non_meta[0] if non_meta else ""
            proj_root = resolve_project_root(anchor, cwd)
            if is_spec_lock_active(proj_root, session or {}, change_id):
                _art_dir, rel_dir, cid = resolve_artifact_dir(proj_root, change_id)
                label = os.path.basename(non_meta[0].replace("\\", "/")) if non_meta else "source file"
                ok1, m1 = verify_stage_approval(proj_root, "S1_PLAN", f"{rel_dir}/intent.md", change_id=cid)
                if not ok1:
                    return "deny", f"[VeriGate S1 Shell Write Gate] Blocked shell write to `{label}`: {m1}"
                ok2, m2 = verify_stage_approval(proj_root, "S2_DESIGN", f"{rel_dir}/spec.md", change_id=cid)
                if not ok2:
                    return "deny", f"[VeriGate S2 Shell Write Gate] Blocked shell write to `{label}`: {m2}"

    return "allow", ""


# --- CLI Actions ---


def cmd_init(project_root: str, require_spec: bool, change_id: str | None = None) -> int:
    sdlc = Path(project_root) / ".sdlc"
    sdlc.mkdir(parents=True, exist_ok=True)
    cfg = sdlc / "config.json"
    if not cfg.exists():
        cfg.write_text(
            json.dumps(
                {
                    "version": "3.0.0",
                    "require_spec_approval": require_spec,
                    "require_change_folder_for_gated_paths": require_spec,
                    "fail_on_missing_tool": True,
                    "change_id": {"branch_pattern": DEFAULT_BRANCH_PATTERN},
                    "gated_paths": [],
                    "approvers": {"codeowners_paths": [".sdlc/changes/**"], "required_reviewers": []},
                    "tracker": {"provider": "auto", "min_severity": "High"},
                    "terraform_dirs": [],
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
    policy = sdlc / "policy.json"
    if not policy.exists():
        policy.write_text(
            json.dumps(
                {
                    "require_zero_findings": True,
                    "require_review_in_ci": True,
                    "max_open_critical": 0,
                    "max_open_high": 0,
                    "min_quality_score": 85,
                    "max_review_fix_cycles": 3,
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
    rev = sdlc / "REVIEW.md"
    if not rev.exists():
        rev.write_text(
            "# Governed Code Review Policy (`REVIEW.md`)\n\n"
            "- **Critical**: Auth bypass, secret exposure, injection, data loss, crash on primary flow.\n"
            "- **High**: Violated `AC-*` in `intent.md`, contract drift from `spec.md`, missing tests.\n"
            "- **Medium**: Performance bottleneck, incomplete boundary validation.\n"
            "- **Low**: Readability, naming, minor tech debt.\n",
            encoding="utf-8",
        )

    art_dir, rel_dir, cid = resolve_artifact_dir(project_root, change_id, strict=True)
    Path(art_dir).mkdir(parents=True, exist_ok=True)
    if change_id:
        (sdlc / "active-change").write_text(f"{cid}\n", encoding="utf-8")

    out: dict = {"status": "initialized", "sdlc_dir": str(sdlc), "artifact_dir": rel_dir}
    if cid:
        out["change_id"] = cid
    print(json.dumps(out, indent=2))
    return 0


def load_policy(project_root: str, git_ref: str | None = None) -> dict:
    """Load `.sdlc/policy.json`, preferring `git_ref` when provided so PRs cannot weaken merge policy."""
    abs_root = os.path.realpath(project_root)
    policy = {
        "require_zero_findings": True,
        "require_review_in_ci": True,
        "max_open_critical": 0,
        "max_open_high": 0,
        "min_quality_score": 85,
        "max_review_fix_cycles": 3,
    }
    if git_ref:
        ref_pol = _read_git_ref_json(abs_root, git_ref, ".sdlc/policy.json")
        if ref_pol:
            policy.update(ref_pol)
            return policy
    policy_file = Path(abs_root) / ".sdlc" / "policy.json"
    if policy_file.is_file():
        try:
            loaded = json.loads(policy_file.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                policy.update(loaded)
        except Exception:
            pass
    return policy


def _evaluate_merge_policy(
    project_root: str,
    change_id: str | None = None,
    prefer_git_head: bool = False,
    git_ref: str | None = None,
) -> tuple[bool, dict]:
    """Evaluate review policy and spec SHA-256 digest consistency without side-effect printing."""
    art_dir_str, rel_dir, cid = resolve_artifact_dir(project_root, change_id, strict=bool(change_id))
    art_dir = Path(art_dir_str)
    policy = load_policy(project_root, git_ref=git_ref)

    reasons: list[str] = []

    if (art_dir / "intent.md").is_file():
        ok1, m1 = verify_stage_approval(
            project_root, "S1_PLAN", f"{rel_dir}/intent.md", change_id=cid, prefer_git_head=prefer_git_head
        )
        if not ok1:
            reasons.append(f"S1_PLAN: {m1}")
        ok2, m2 = verify_stage_approval(
            project_root, "S2_DESIGN", f"{rel_dir}/spec.md", change_id=cid, prefer_git_head=prefer_git_head
        )
        if not ok2:
            reasons.append(f"S2_DESIGN: {m2}")

    findings_file = art_dir / "review-findings.json"
    open_count = -1
    score = 0
    verdict = "MISSING"
    if not findings_file.is_file():
        reasons.append(f"Missing `{rel_dir}/review-findings.json` from Stage 5 Code Review.")
    else:
        try:
            report = json.loads(findings_file.read_text(encoding="utf-8"))
            verdict = str(report.get("verdict") or "UNKNOWN").upper()
            score = int(report.get("quality_score") or 0)
            findings = report.get("findings") or []
            open_findings = [
                f
                for f in findings
                if str(f.get("status") or "open").lower() not in ("fixed", "resolved", "closed", "fixed_verified")
            ]
            open_count = len(open_findings)
            crit_count = sum(1 for f in open_findings if str(f.get("severity") or "").lower() == "critical")
            high_count = sum(1 for f in open_findings if str(f.get("severity") or "").lower() == "high")

            if verdict != "APPROVE":
                reasons.append(f"Review verdict is `{verdict}` (must be `APPROVE`).")
            if policy.get("require_zero_findings", True) and open_count > 0:
                reasons.append(
                    f"{open_count} open review finding(s) remain (team policy requires 0 open findings — run Review <-> Fix cycle)."
                )
            if crit_count > int(policy.get("max_open_critical", 0)):
                reasons.append(f"{crit_count} open Critical finding(s) exceed policy limit.")
            if high_count > int(policy.get("max_open_high", 0)):
                reasons.append(f"{high_count} open High finding(s) exceed policy limit.")
            if score < int(policy.get("min_quality_score", 85)):
                reasons.append(
                    f"Quality score {score} is below team policy minimum ({policy.get('min_quality_score', 85)})."
                )
        except Exception as exc:
            reasons.append(f"Invalid `{rel_dir}/review-findings.json`: {exc}")

    ready = len(reasons) == 0
    status = "READY_TO_MERGE" if ready else "BLOCKED_BY_POLICY"
    out: dict = {
        "status": status,
        "ready_to_merge": ready,
        "artifact_dir": rel_dir,
        "verdict": verdict,
        "quality_score": score,
        "open_findings": open_count,
        "policy": policy,
        "blocking_reasons": reasons,
        "note": "Consistency and policy check (verifies artifact SHA-256 digest consistency and review policy; not cryptographic proof of human identity).",
    }
    if cid:
        out["change_id"] = cid
    return ready, out


def cmd_merge_check(project_root: str, change_id: str | None = None) -> int:
    """Deterministic Consistency & Policy Check: Review (0 open findings) + Spec SHA-256 digest consistency -> Ready to Merge."""
    ready, out = _evaluate_merge_policy(project_root, change_id=change_id, prefer_git_head=False)
    append_audit(
        project_root,
        "MERGE_POLICY_APPROVED" if ready else "MERGE_POLICY_BLOCKED",
        {
            "status": out["status"],
            "change_id": out.get("change_id"),
            "verdict": out["verdict"],
            "quality_score": out["quality_score"],
            "open_findings": out["open_findings"],
            "reasons": out["blocking_reasons"],
        },
    )
    print(json.dumps(out, indent=2))
    return 0 if ready else 1


def cmd_verify(project_root: str, change_id: str | None = None, files_arg: str | None = None) -> int:
    """Execute configured gated_paths verify commands directly (shell=False) and write commit-bound verify-result.json."""
    abs_root = os.path.realpath(project_root)
    config = load_config(abs_root)
    art_dir_str, rel_dir, cid = resolve_artifact_dir(abs_root, change_id, strict=True)
    art_dir = Path(art_dir_str)
    art_dir.mkdir(parents=True, exist_ok=True)

    target_files: list[str] | None = None
    if files_arg is not None and files_arg.strip():
        target_files = [_normalize_rel_path(f.strip(), abs_root) for f in files_arg.split(",") if f.strip()]

    rules = matched_gated_rules(target_files, config)
    fail_on_missing = bool(config.get("fail_on_missing_tool", True))
    passed, results = run_verify_rules(abs_root, rules, fail_on_missing)
    head_commit = _git_head_commit(abs_root)
    tree_digest = compute_tree_digest(abs_root, config, target_files=target_files)

    payload: dict = {
        "timestamp": utc_now_iso(),
        "head_commit": head_commit,
        "tree_digest": tree_digest,
        "change_id": cid,
        "artifact_dir": rel_dir,
        "passed": passed,
        "fail_on_missing_tool": fail_on_missing,
        "results": results,
    }

    res_file = art_dir / "verify-result.json"
    tmp = f"{res_file}.tmp"
    Path(tmp).write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, res_file)

    append_audit(
        abs_root,
        "VERIFY_PASSED" if passed else "VERIFY_FAILED",
        {
            "change_id": cid,
            "head_commit": head_commit,
            "tree_digest": tree_digest,
            "passed": passed,
            "check_count": len(results),
        },
    )
    print(json.dumps(payload, indent=2))
    return 0 if passed else 1


def _git_diff_pr_files(abs_root: str, base_ref: str) -> list[str]:
    candidates = [
        ["git", "-C", abs_root, "diff", "--name-only", f"{base_ref}...HEAD"],
        ["git", "-C", abs_root, "diff", "--name-only", f"{base_ref}..HEAD"],
        ["git", "-C", abs_root, "diff", "--name-only", "HEAD~1..HEAD"],
        ["git", "-C", abs_root, "diff-tree", "--no-commit-id", "--name-only", "-r", "HEAD"],
    ]
    for args in candidates:
        try:
            proc = subprocess.run(args, capture_output=True, text=True, timeout=10)
            if proc.returncode == 0:
                return [_normalize_rel_path(line.strip()) for line in proc.stdout.splitlines() if line.strip()]
        except Exception:
            continue
    return []


def _infer_change_id_from_paths(rel_paths: list[str]) -> str | None:
    found: set[str] = set()
    for p in rel_paths:
        m = re.match(r"^\.sdlc/changes/([^/]+)/", p.replace("\\", "/"))
        if m:
            cid = sanitize_change_id(m.group(1), strict=False)
            if cid:
                found.add(cid)
    return next(iter(found)) if len(found) == 1 else None


def cmd_ci_check(project_root: str, base_ref: str = "origin/main", change_id: str | None = None) -> int:
    """PR pipeline recompute gate: loads config/policy from base_ref and recomputes all checks from scratch."""
    abs_root = os.path.realpath(project_root)
    config = load_config(abs_root, git_ref=base_ref)
    policy = load_policy(abs_root, git_ref=base_ref)
    touched_files = _git_diff_pr_files(abs_root, base_ref)
    gated_touched = [p for p in touched_files if is_path_gated(p, config)]
    head_commit = _git_head_commit(abs_root)

    resolved_cid = resolve_change_id(abs_root, change_id, strict=bool(change_id))
    if not resolved_cid:
        resolved_cid = _infer_change_id_from_paths(touched_files)
    art_dir_str, rel_dir, cid = resolve_artifact_dir(abs_root, resolved_cid, strict=False)
    art_dir = Path(art_dir_str)

    if not gated_touched:
        out = {
            "status": "PASSED",
            "passed": True,
            "base_ref": base_ref,
            "config_source": config.get("config_source"),
            "head_commit": head_commit,
            "artifact_dir": rel_dir,
            "change_id": cid,
            "touched_files": touched_files,
            "gated_paths_touched": [],
            "trusted_laptop_verify_result": False,
            "checks": {},
            "blocking_reasons": [],
            "message": "No gated paths touched; CI gate passed.",
        }
        append_audit(abs_root, "CI_CHECK_PASSED", {"change_id": cid, "head_commit": head_commit, "gated_count": 0})
        print(json.dumps(out, indent=2))
        return 0

    reasons: list[str] = []
    checks: dict = {}

    # 1. Required change folder for gated paths
    ok_cf, msg_cf = check_required_change_folder(abs_root, touched_files, config, change_id=cid)
    checks["change_folder"] = {"passed": ok_cf, "detail": msg_cf}
    if not ok_cf:
        reasons.append(f"CHANGE_FOLDER: {msg_cf}")

    # 2. Validate intent.md + spec.md content & HEAD-committed SHA-256 approvals
    if ok_cf or (art_dir / "intent.md").is_file() or (art_dir / "spec.md").is_file():
        ok1, m1 = verify_stage_approval(abs_root, "S1_PLAN", f"{rel_dir}/intent.md", change_id=cid, prefer_git_head=True)
        checks["S1_PLAN"] = {"passed": ok1, "detail": m1}
        if not ok1:
            reasons.append(f"S1_PLAN: {m1}")
        ok2, m2 = verify_stage_approval(abs_root, "S2_DESIGN", f"{rel_dir}/spec.md", change_id=cid, prefer_git_head=True)
        checks["S2_DESIGN"] = {"passed": ok2, "detail": m2}
        if not ok2:
            reasons.append(f"S2_DESIGN: {m2}")

    # 3. Recompute all matching verify commands from scratch (NEVER trust laptop verify-result.json)
    rules = matched_gated_rules(gated_touched, config)
    fail_on_missing = bool(config.get("fail_on_missing_tool", True))
    v_passed, v_results = run_verify_rules(abs_root, rules, fail_on_missing)
    checks["verify"] = {
        "passed": v_passed,
        "recomputed": True,
        "fail_on_missing_tool": fail_on_missing,
        "results": v_results,
    }
    if not v_passed:
        for r in v_results:
            if not r["passed"]:
                if r.get("missing_tool"):
                    reasons.append(
                        f"VERIFY_MISSING_TOOL ({r['pattern']}): `{r['command']}` not found (fail_on_missing_tool=true)."
                    )
                else:
                    reasons.append(
                        f"VERIFY_FAILED ({r['pattern']}): `{r['command']}` exited with code {r['exit_code']}."
                    )

    # 4. Stage 5 review policy consistency check (required by default in CI unless require_review_in_ci is False)
    require_review = bool(policy.get("require_review_in_ci", True))
    if require_review or (art_dir / "review-findings.json").is_file():
        m_ready, m_out = _evaluate_merge_policy(abs_root, change_id=cid, prefer_git_head=True, git_ref=base_ref)
        checks["merge_policy"] = {
            "passed": m_ready,
            "required": require_review,
            "status": m_out["status"],
            "verdict": m_out["verdict"],
            "quality_score": m_out["quality_score"],
            "open_findings": m_out["open_findings"],
            "blocking_reasons": m_out["blocking_reasons"],
        }
        if not m_ready:
            for r in m_out["blocking_reasons"]:
                reasons.append(f"MERGE_POLICY: {r}")

    passed = len(reasons) == 0
    out = {
        "status": "PASSED" if passed else "FAILED",
        "passed": passed,
        "base_ref": base_ref,
        "config_source": config.get("config_source"),
        "head_commit": head_commit,
        "artifact_dir": rel_dir,
        "change_id": cid,
        "touched_files": touched_files,
        "gated_paths_touched": gated_touched,
        "trusted_laptop_verify_result": False,
        "checks": checks,
        "blocking_reasons": reasons,
    }
    append_audit(
        abs_root,
        "CI_CHECK_PASSED" if passed else "CI_CHECK_FAILED",
        {
            "change_id": cid,
            "head_commit": head_commit,
            "gated_count": len(gated_touched),
            "reasons": reasons,
        },
    )
    print(json.dumps(out, indent=2))
    return 0 if passed else 1


def cmd_approve(project_root: str, stage: str, approver: str, note: str, change_id: str | None = None) -> int:
    art_dir_str, rel_dir, cid = resolve_artifact_dir(project_root, change_id, strict=True)
    art_dir = Path(art_dir_str)
    stage_map = {
        "S1_PLAN": [("S1_PLAN", f"{rel_dir}/intent.md")],
        "S2_DESIGN": [("S2_DESIGN", f"{rel_dir}/spec.md")],
        "S1_S2": [("S1_PLAN", f"{rel_dir}/intent.md"), ("S2_DESIGN", f"{rel_dir}/spec.md")],
    }
    art_dir.mkdir(parents=True, exist_ok=True)
    app_file = art_dir / "approvals.json"
    repo_data = json.loads(app_file.read_text(encoding="utf-8")) if app_file.is_file() else {"version": "2.4.0", "approvals": {}}
    repo_data.pop("project_root", None)
    repo_data.setdefault("approvals", {})
    if cid:
        repo_data["change_id"] = cid

    shadow = load_shadow_ledger()
    shadow_key = _shadow_project_key(os.path.realpath(project_root), cid)
    proj_sh = shadow.setdefault("projects", {}).setdefault(shadow_key, {"approvals": {}, "waivers": []})
    now = utc_now_iso()
    approved = []

    for st_key, rel in stage_map[stage]:
        ap = Path(project_root) / rel
        if not ap.is_file():
            print(json.dumps({"status": "error", "error": f"Missing `{rel}`"}))
            return 1
        ok, msg = validate_intent(ap.read_text(encoding="utf-8")) if st_key == "S1_PLAN" else validate_spec(ap.read_text(encoding="utf-8"))
        if not ok:
            print(json.dumps({"status": "error", "stage": st_key, "error": msg}))
            return 1
        digest = file_sha256(str(ap))
        entry = {"artifact": rel, "sha256": digest, "approved_at": now, "approved_by": approver, "note": note}
        repo_data["approvals"][st_key] = entry
        proj_sh["approvals"][st_key] = entry
        approved.append({"stage": st_key, **entry})
        append_audit(project_root, "STAGE_CONTENT_APPROVED", {"stage": st_key, "change_id": cid, "artifact": rel, "sha256": digest, "approved_by": approver})

    tmp = f"{app_file}.tmp"
    Path(tmp).write_text(json.dumps(repo_data, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, app_file)
    save_shadow_ledger(shadow)
    out: dict = {"status": "approved", "artifact_dir": rel_dir, "approved": approved}
    if cid:
        out["change_id"] = cid
    print(json.dumps(out, indent=2))
    return 0


def cmd_waive(project_root: str, stage: str, reason: str, change_id: str | None = None) -> int:
    if len(reason.strip()) < 8:
        print(json.dumps({"status": "error", "error": "Waiver `--reason` must be >=8 chars."}))
        return 1
    art_dir_str, rel_dir, cid = resolve_artifact_dir(project_root, change_id, strict=True)
    art_dir = Path(art_dir_str)
    art_dir.mkdir(parents=True, exist_ok=True)
    digests = {}
    for root, dirs, files in os.walk(project_root):
        dirs[:] = [d for d in dirs if d not in {".git", ".sdlc", "node_modules", "__pycache__", ".venv", "venv", "dist", "build"}]
        for f in files:
            fp = os.path.realpath(os.path.join(root, f))
            if not is_meta_or_doc_path(fp):
                d = file_sha256(fp)
                if d:
                    digests[fp] = d

    rec = {"waived_at": utc_now_iso(), "stage": stage, "reason": reason.strip(), "files": digests}
    if cid:
        rec["change_id"] = cid
    with open(art_dir / "waivers.jsonl", "a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec) + "\n")

    shadow = load_shadow_ledger()
    shadow_key = _shadow_project_key(os.path.realpath(project_root), cid)
    shadow.setdefault("projects", {}).setdefault(shadow_key, {"approvals": {}, "waivers": []}).setdefault("waivers", []).append(rec)
    save_shadow_ledger(shadow)
    append_audit(project_root, "STAGE_WAIVER_APPROVED", {"stage": stage, "change_id": cid, "reason": reason.strip(), "file_count": len(digests)})
    out: dict = {"status": "waived", "stage": stage, "artifact_dir": rel_dir, "waived_file_count": len(digests)}
    if cid:
        out["change_id"] = cid
    print(json.dumps(out, indent=2))
    return 0


# --- Multi-Harness Hook Protocol Adapter ---


TEST_FAILURE_OUTPUT_RE = re.compile(
    r"(?:FAILED\s*\((?:failures|errors)=|={3,}\s*FAILURES\s*={3,}|test result:\s*FAILED|\bFAIL\t|\b[1-9]\d*\s+failed\b)",
    re.IGNORECASE,
)


def _response_indicates_failure(tresp: object) -> bool:
    """Detect non-zero exit codes, interruptions, or test failure banners in dict or string tool_response payloads."""
    if isinstance(tresp, dict):
        for key in ("exit_code", "exitCode", "code", "returncode"):
            val = tresp.get(key)
            if val is not None:
                try:
                    if int(val) != 0:
                        return True
                except (TypeError, ValueError):
                    return True
        if tresp.get("interrupted") or tresp.get("is_error") or tresp.get("isError"):
            return True
        combined = f"{tresp.get('stdout') or ''}\n{tresp.get('stderr') or ''}"
        if combined.strip() and TEST_FAILURE_OUTPUT_RE.search(combined):
            return True
        return False
    if isinstance(tresp, str):
        if re.search(r"\b(?:Exit code|Command exited with code)\s+[1-9]\d*\b", tresp, re.IGNORECASE):
            return True
        if TEST_FAILURE_OUTPUT_RE.search(tresp):
            return True
    return False


def _log_hook_debug(adapter: str, event: str, payload: dict) -> None:
    if os.environ.get("VERIGATE_DEBUG_HOOK") != "1":
        return
    try:
        tname = payload.get("tool_name") or (payload.get("toolCall") or {}).get("name") or ""
        if "tool_response" in payload:
            tresp = payload.get("tool_response")
        elif "toolResponse" in payload:
            tresp = payload.get("toolResponse")
        else:
            tresp = payload.get("result")
        if isinstance(tresp, dict):
            resp_keys = sorted(str(k) for k in tresp.keys())
            resp_type = "dict"
        elif tresp is None:
            resp_keys = []
            resp_type = "none"
        else:
            resp_keys = []
            resp_type = type(tresp).__name__
        rec = {
            "timestamp": utc_now_iso(),
            "adapter": adapter,
            "event": event,
            "tool_name": str(tname),
            "tool_response_type": resp_type,
            "tool_response_keys": resp_keys,
        }
        with open(os.path.join(global_state_dir(), "hook_debug.jsonl"), "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec) + "\n")
    except OSError:
        pass


def _has_valid_waiver(
    project_root: str,
    change_id: str | None,
    stage_names: tuple[str, ...],
    rel_file_paths: list[str],
) -> bool:
    abs_root = os.path.realpath(project_root)
    art_dir_str, _rel_dir, cid = resolve_artifact_dir(abs_root, change_id)
    live_digests: dict[str, str] = {}
    for rel in rel_file_paths:
        rp = os.path.realpath(os.path.join(abs_root, rel))
        d = file_sha256(rp)
        if not d:
            return False
        live_digests[rp] = d
    if not live_digests:
        return False

    waivers: list[dict] = []
    projects_sh = load_shadow_ledger().get("projects") or {}
    waivers.extend(((projects_sh.get(_shadow_project_key(abs_root, cid)) or {}).get("waivers")) or [])
    if cid:
        waivers.extend(((projects_sh.get(abs_root) or {}).get("waivers")) or [])

    waivers_file = os.path.join(art_dir_str, "waivers.jsonl")
    if os.path.isfile(waivers_file):
        try:
            for line in Path(waivers_file).read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line:
                    waivers.append(json.loads(line))
        except Exception:
            pass

    return any(
        w.get("stage") in stage_names
        and all((w.get("files") or {}).get(fp) == d for fp, d in live_digests.items())
        for w in waivers
    )


def _git_pre_push_files(proj: str) -> list[str]:
    # 1. Tracked upstream branch diff (when upstream exists)
    try:
        proc = subprocess.run(["git", "-C", proj, "diff", "--name-only", "@{u}..HEAD"], capture_output=True, text=True, timeout=10)
        if proc.returncode == 0:
            return [_normalize_rel_path(line.strip()) for line in proc.stdout.splitlines() if line.strip()]
    except Exception:
        pass

    # 2. New branch with no upstream yet: diff from merge-base against default branch so ALL branch commits are checked
    for base_candidate in ("origin/main", "origin/master", "main", "master"):
        try:
            mb = subprocess.run(
                ["git", "-C", proj, "merge-base", "HEAD", base_candidate],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if mb.returncode == 0 and mb.stdout.strip():
                base_sha = mb.stdout.strip()
                head_sha = _git_head_commit(proj)
                if base_sha != head_sha:
                    proc = subprocess.run(
                        ["git", "-C", proj, "diff", "--name-only", f"{base_sha}..HEAD"],
                        capture_output=True,
                        text=True,
                        timeout=10,
                    )
                    if proc.returncode == 0:
                        return [_normalize_rel_path(line.strip()) for line in proc.stdout.splitlines() if line.strip()]
        except Exception:
            continue

    # 3. Root-commit / single-branch fallback
    try:
        proc = subprocess.run(["git", "-C", proj, "diff-tree", "--no-commit-id", "--name-only", "-r", "HEAD"], capture_output=True, text=True, timeout=10)
        if proc.returncode == 0:
            return [_normalize_rel_path(line.strip()) for line in proc.stdout.splitlines() if line.strip()]
    except Exception:
        pass
    return []


def handle_hook(adapter: str, event_override: str | None, change_id: str | None = None) -> int:
    if adapter == "git-pre-commit":
        proj = resolve_project_root(".", os.getcwd())
        config = load_config(proj)
        proc = subprocess.run(
            ["git", "-C", proj, "diff", "--cached", "--name-only", "--diff-filter=ACMR"],
            capture_output=True,
            text=True,
        )
        staged_rel = [_normalize_rel_path(line.strip()) for line in proc.stdout.splitlines() if line.strip()]
        ok_cf, msg_cf = check_required_change_folder(proj, staged_rel, config, change_id=change_id)
        if not ok_cf:
            sys.stderr.write(f"\n❌ [VeriGate Change Folder Gate] {msg_cf}\n")
            return 1
        for rel in staged_rel:
            sp = os.path.join(proj, rel)
            if PROTECTED_LEDGER_RE.search(sp.replace("\\", "/")):
                continue
            decision, reason = evaluate_file_write(sp, {}, proj, change_id=change_id)
            if decision == "deny":
                sys.stderr.write(f"\n❌ {reason}\n")
                return 1
        return 0

    if adapter == "git-pre-push":
        proj = resolve_project_root(".", os.getcwd())
        config = load_config(proj)
        pushed_rel = _git_pre_push_files(proj)
        gated_pushed = [p for p in pushed_rel if is_path_gated(p, config)]
        if not gated_pushed:
            return 0

        ok_cf, msg_cf = check_required_change_folder(proj, pushed_rel, config, change_id=change_id)
        if not ok_cf:
            sys.stderr.write(f"\n❌ [VeriGate Pre-Push Gate] {msg_cf}\n")
            return 1

        art_dir_str, rel_dir, cid = resolve_artifact_dir(proj, change_id)
        change_flag = f" --change {cid}" if cid else ""

        if is_spec_lock_active(proj, {}, change_id=cid) or os.path.isfile(os.path.join(art_dir_str, "intent.md")):
            ok1, m1 = verify_stage_approval(proj, "S1_PLAN", f"{rel_dir}/intent.md", change_id=cid)
            if not ok1:
                sys.stderr.write(f"\n❌ [VeriGate Pre-Push S1 Gate] {m1}\n")
                return 1
            ok2, m2 = verify_stage_approval(proj, "S2_DESIGN", f"{rel_dir}/spec.md", change_id=cid)
            if not ok2:
                sys.stderr.write(f"\n❌ [VeriGate Pre-Push S2 Gate] {m2}\n")
                return 1

        if _has_valid_waiver(proj, cid, ("ALL", "S4_TEST"), gated_pushed):
            return 0

        verify_file = os.path.join(art_dir_str, "verify-result.json")
        if not os.path.isfile(verify_file):
            sys.stderr.write(
                f"\n❌ [VeriGate Pre-Push Verify Gate] Missing `{rel_dir}/verify-result.json`. "
                f"Run: `python3 .sdlc/bin/verigate.py verify --project .{change_flag}`.\n"
            )
            return 1
        try:
            vres = json.loads(Path(verify_file).read_text(encoding="utf-8"))
        except Exception:
            sys.stderr.write(
                f"\n❌ [VeriGate Pre-Push Verify Gate] Corrupted `{rel_dir}/verify-result.json`. "
                f"Re-run: `python3 .sdlc/bin/verigate.py verify --project .{change_flag}`.\n"
            )
            return 1

        if not vres.get("passed"):
            sys.stderr.write(
                f"\n❌ [VeriGate Pre-Push Verify Gate] Latest verification in `{rel_dir}/verify-result.json` did not pass. "
                f"Fix failures and run: `python3 .sdlc/bin/verigate.py verify --project .{change_flag}`.\n"
            )
            return 1

        current_head = _git_head_commit(proj)
        if vres.get("head_commit") != current_head:
            sys.stderr.write(
                f"\n❌ [VeriGate Pre-Push Verify Gate] Stale `{rel_dir}/verify-result.json` "
                f"(verified `{str(vres.get('head_commit'))[:12]}`, current HEAD `{current_head[:12]}`). "
                f"Re-run: `python3 .sdlc/bin/verigate.py verify --project .{change_flag}`.\n"
            )
            return 1

        current_digest = compute_tree_digest(proj, config)
        if vres.get("tree_digest") != current_digest:
            sys.stderr.write(
                f"\n❌ [VeriGate Pre-Push Verify Gate] Gated files changed since `{rel_dir}/verify-result.json` was generated "
                f"(digest mismatch). Re-run: `python3 .sdlc/bin/verigate.py verify --project .{change_flag}`.\n"
            )
            return 1

        return 0

    raw = sys.stdin.read()
    try:
        payload = json.loads(raw) if raw.strip() else {}
    except ValueError:
        print("{}")
        return 0

    if adapter == "auto":
        adapter = "claude" if ("hook_event_name" in payload or "tool_input" in payload or "session_id" in payload) else "antigravity"

    session_id = str(payload.get("conversationId") or payload.get("session_id") or "default")
    cwd = payload.get("cwd") or os.getcwd()
    event = event_override or payload.get("hookEventName") or payload.get("hook_event_name") or ""
    _log_hook_debug(adapter, event, payload)
    session = load_session(session_id)

    if event in ("PreInvocation", "UserPromptSubmit"):
        prompt_text = (payload.get("lastUserInput") or payload.get("prompt") or "").strip()
        if not prompt_text:
            print("{}")
            return 0
        phash = hashlib.sha256(prompt_text.encode("utf-8")).hexdigest()[:16]
        if session.get("lastPromptHash") == phash:
            print("{}")
            return 0
        session["lastPromptHash"] = phash
        session["stopIntercepts"] = 0
        info = classify_prompt(prompt_text)
        if not info:
            save_session(session_id, session)
            print("{}")
            return 0
        session["enforceSpec"] = info["enforce_spec"]
        save_session(session_id, session)
        proj = resolve_project_root("", cwd)
        _art_dir, rel_dir, _cid = resolve_artifact_dir(proj, change_id)
        table_md = render_dispatch_table(info, rel_dir=rel_dir)
        if adapter == "claude":
            print(json.dumps({"hookSpecificOutput": {"hookEventName": "UserPromptSubmit", "additionalContext": table_md}}))
        else:
            print(
                json.dumps(
                    {
                        "injectSteps": [
                            {
                                "systemMessage": {
                                    "systemMessage": f"[VeriGate AI-SDLC] Profile: {info['profile']}. Enforce S1-S6 gates.",
                                    "metadata": {"user_markdown": table_md},
                                }
                            }
                        ]
                    }
                )
            )
        return 0

    if event == "PreToolUse":
        if adapter == "claude":
            tname = payload.get("tool_name") or ""
            tinput = payload.get("tool_input") or {}
            if tname in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
                target_file = str(tinput.get("file_path") or tinput.get("notebook_path") or "")
                decision, reason = evaluate_file_write(target_file, session, cwd, change_id=change_id)
            elif tname in ("Bash", "PowerShell"):
                decision, reason = evaluate_shell_command(str(tinput.get("command") or ""), session, cwd, change_id=change_id)
            else:
                decision, reason = "allow", ""
            claude_dec = "ask" if decision in ("ask", "force_ask") else decision
            out: dict = {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": claude_dec}}
            if reason:
                out["hookSpecificOutput"]["permissionDecisionReason"] = reason
            print(json.dumps(out))
            return 0

        tc = payload.get("toolCall") or {}
        tname = tc.get("name") or ""
        targs = tc.get("args") or {}
        if isinstance(targs, str):
            try:
                targs = json.loads(targs) if targs.strip() else {}
            except ValueError:
                targs = {}
        if tname in ("write_file", "edit_file"):
            decision, reason = evaluate_file_write(str(targs.get("Path") or ""), session, cwd, change_id=change_id)
        elif tname == "run_command":
            decision, reason = evaluate_shell_command(str(targs.get("CommandLine") or ""), session, cwd, change_id=change_id)
        else:
            decision, reason = "allow", ""
        out = {"decision": decision}
        if reason:
            out["reason"] = reason
        print(json.dumps(out))
        return 0

    if event == "PostToolUse":
        cmd_str = ""
        cmd_failed = bool(payload.get("error"))
        if adapter == "claude":
            tname = payload.get("tool_name") or ""
            tinput = payload.get("tool_input") or {}
            tresp = payload.get("tool_response")
            if _response_indicates_failure(tresp):
                cmd_failed = True
            path = (
                str(tinput.get("file_path") or tinput.get("notebook_path") or "")
                if tname in ("Write", "Edit", "MultiEdit", "NotebookEdit")
                else ""
            )
            if tname in ("Bash", "PowerShell"):
                cmd_str = str(tinput.get("command") or "")
            sub_agent = (
                str(tinput.get("subagent_type") or tinput.get("agent") or tinput.get("name") or "")
                if tname in ("Task", "Agent")
                else ""
            )
        else:
            tresp = payload.get("toolResponse") if "toolResponse" in payload else payload.get("result")
            if _response_indicates_failure(tresp):
                cmd_failed = True
            if cmd_failed:
                print("{}")
                return 0
            tc = payload.get("toolCall") or {}
            tname = tc.get("name") or ""
            targs = tc.get("args") or {}
            if isinstance(targs, str):
                try:
                    targs = json.loads(targs) if targs.strip() else {}
                except ValueError:
                    targs = {}
            path = str(targs.get("Path") or "") if tname in ("write_file", "edit_file") else ""
            if tname == "run_command":
                cmd_str = str(targs.get("CommandLine") or "")
            sub_agent = str(targs.get("TypeName") or "") if tname == "invoke_subagent" else ""

        dirty = list(session.get("dirtyFiles") or [])
        if path and not cmd_failed:
            full_p = os.path.realpath(normalize_target_path(path, cwd))
            norm = full_p.replace("\\", "/")
            if REVIEW_ARTIFACT_RE.search(norm):
                session["reviewed"] = True
            elif not is_meta_or_doc_path(full_p):
                if full_p not in dirty:
                    dirty.append(full_p)
                session["dirtyFiles"] = dirty[-25:]
                session["verified"] = False
                session["reviewed"] = False
        elif cmd_str and not cmd_failed:
            is_write, targets = extract_shell_write_targets(cmd_str)
            wrote_source = False
            if is_write:
                non_meta_paths: list[str] = []
                for t in targets:
                    full_p = os.path.realpath(normalize_target_path(t, cwd))
                    norm = full_p.replace("\\", "/")
                    if REVIEW_ARTIFACT_RE.search(norm):
                        session["reviewed"] = True
                    elif not is_meta_or_doc_path(full_p):
                        non_meta_paths.append(full_p)
                if non_meta_paths:
                    wrote_source = True
                    for fp in non_meta_paths:
                        if fp not in dirty:
                            dirty.append(fp)
                    session["dirtyFiles"] = dirty[-25:]
                    session["verified"] = False
                    session["reviewed"] = False
                elif not targets:
                    wrote_source = True
                    marker = os.path.realpath(cwd)
                    if marker not in dirty:
                        dirty.append(marker)
                    session["dirtyFiles"] = dirty[-25:]
                    session["verified"] = False
                    session["reviewed"] = False
            is_verigate_verify = (
                not SHELL_CHAIN_OR_REDIRECT_RE.search(cmd_str)
                and (m_vg := SANCTIONED_GATE_CMD_RE.match(cmd_str)) is not None
                and m_vg.group(1) == "verify"
            )
            if not wrote_source and (is_verigate_verify or (dirty and is_real_test_runner_command(cmd_str))):
                session["verified"] = True
        elif not cmd_failed and "reviewer" in sub_agent.lower():
            session["reviewed"] = True

        save_session(session_id, session)
        print("{}")
        return 0

    if event == "Stop":
        dirty = session.get("dirtyFiles") or []
        if not dirty:
            print(json.dumps({"decision": "allow"} if adapter == "antigravity" else {}))
            return 0
        proj = resolve_project_root(dirty[0], cwd)
        _art_dir, rel_dir, cid = resolve_artifact_dir(proj, change_id)
        verified = bool(session.get("verified", True))
        reviewed = bool(session.get("reviewed", True))

        projects_sh = load_shadow_ledger().get("projects") or {}
        shadow_waivers = list(((projects_sh.get(_shadow_project_key(proj, cid)) or {}).get("waivers")) or [])
        if cid:
            shadow_waivers.extend(((projects_sh.get(proj) or {}).get("waivers")) or [])

        live_digests = {}
        all_exist = True
        for p in dirty:
            rp = os.path.realpath(normalize_target_path(p, cwd))
            d = file_sha256(rp)
            if d:
                live_digests[rp] = d
            else:
                all_exist = False

        waived_s4 = bool(live_digests) and all_exist and any(
            w.get("stage") in ("ALL", "S4_TEST") and all((w.get("files") or {}).get(fp) == d for fp, d in live_digests.items())
            for w in shadow_waivers
        )
        waived_s5 = bool(live_digests) and all_exist and any(
            w.get("stage") in ("ALL", "S5_REVIEW") and all((w.get("files") or {}).get(fp) == d for fp, d in live_digests.items())
            for w in shadow_waivers
        )

        if (verified or waived_s4) and (reviewed or waived_s5):
            session["dirtyFiles"] = []
            session["stopIntercepts"] = 0
            save_session(session_id, session)
            print(json.dumps({"decision": "allow"} if adapter == "antigravity" else {}))
            return 0

        intercepts = int(session.get("stopIntercepts") or 0)
        stop_hook_active = bool(payload.get("continuationActive") or payload.get("stop_hook_active"))
        if intercepts < MAX_STOP_INTERCEPTS and not stop_hook_active:
            session["stopIntercepts"] = intercepts + 1
            save_session(session_id, session)
            change_flag = f" --change {cid}" if cid else ""
            msg = (
                "[VeriGate Guide Rail — Not a crash] Action needed before finishing: modified source files still need "
                f"S4 Verification (standalone test run) AND S5 Code Review (`{rel_dir}/review-findings.json` + `{rel_dir}/review-report.md`). "
                "If blocked by a missing tool/runtime, request a logged waiver: "
                f'`python3 .sdlc/bin/verigate.py waive --project "{proj}"{change_flag} --stage ALL --reason "<blocker>"`.'
            )
            append_audit(proj, "STOP_GATE_INTERCEPT", {"session_id": session_id, "change_id": cid})
            if adapter == "claude":
                print(json.dumps({"decision": "block", "reason": msg}))
            else:
                print(json.dumps({"decision": "continue", "reason": msg}))
            return 0

        append_audit(proj, "STOP_GATE_CIRCUIT_BREAKER_TRIPPED", {"session_id": session_id, "change_id": cid, "files": live_digests})
        session["dirtyFiles"] = []
        session["stopIntercepts"] = 0
        save_session(session_id, session)
        print(json.dumps({"decision": "allow"} if adapter == "antigravity" else {}))
        return 0

    print("{}")
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description="VeriGate AI-SDLC Deterministic Control Engine")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_init = sub.add_parser("init")
    p_init.add_argument("--project", default=".")
    p_init.add_argument("--require-spec", action="store_true")
    p_init.add_argument("--change", default=None)

    p_disp = sub.add_parser("dispatch")
    p_disp.add_argument("prompt")

    p_val = sub.add_parser("validate")
    p_val.add_argument("--project", default=".")
    p_val.add_argument("--change", default=None)

    p_app = sub.add_parser("approve")
    p_app.add_argument("--project", default=".")
    p_app.add_argument("--stage", choices=["S1_PLAN", "S2_DESIGN", "S1_S2"], default="S1_S2")
    p_app.add_argument("--approver", default="human_validator")
    p_app.add_argument("--note", default="")
    p_app.add_argument("--change", default=None)

    p_waive = sub.add_parser("waive")
    p_waive.add_argument("--project", default=".")
    p_waive.add_argument("--stage", choices=["S4_TEST", "S5_REVIEW", "ALL"], default="ALL")
    p_waive.add_argument("--reason", required=True)
    p_waive.add_argument("--change", default=None)

    p_stat = sub.add_parser("status")
    p_stat.add_argument("--project", default=".")
    p_stat.add_argument("--change", default=None)

    p_merge = sub.add_parser("merge-check")
    p_merge.add_argument("--project", default=".")
    p_merge.add_argument("--change", default=None)

    p_verify = sub.add_parser("verify")
    p_verify.add_argument("--project", default=".")
    p_verify.add_argument("--change", default=None)
    p_verify.add_argument("--files", default=None)

    p_ci = sub.add_parser("ci-check")
    p_ci.add_argument("--project", default=".")
    p_ci.add_argument("--base", default="origin/main")
    p_ci.add_argument("--change", default=None)

    p_hook = sub.add_parser("hook")
    p_hook.add_argument("--adapter", choices=["auto", "antigravity", "claude", "git-pre-commit", "git-pre-push"], default="auto")
    p_hook.add_argument("--event", default=None)
    p_hook.add_argument("--change", default=None)

    args = parser.parse_args()

    try:
        if args.cmd == "init":
            sys.exit(cmd_init(os.path.realpath(args.project), args.require_spec, change_id=args.change))
        if args.cmd == "dispatch":
            info = classify_prompt(args.prompt) or {"profile": "General Engineering", "code": "change", "enforce_spec": False}
            print(render_dispatch_table(info))
            sys.exit(0)
        if args.cmd == "validate":
            proj = os.path.realpath(args.project)
            _art_dir, rel_dir, cid = resolve_artifact_dir(proj, args.change, strict=True)
            ok1, m1 = verify_stage_approval(proj, "S1_PLAN", f"{rel_dir}/intent.md", change_id=cid)
            ok2, m2 = verify_stage_approval(proj, "S2_DESIGN", f"{rel_dir}/spec.md", change_id=cid)
            out: dict = {"artifact_dir": rel_dir, "S1_PLAN": m1, "S2_DESIGN": m2, "ready_for_build": bool(ok1 and ok2)}
            if cid:
                out["change_id"] = cid
            print(json.dumps(out, indent=2))
            sys.exit(0 if (ok1 and ok2) else 1)
        if args.cmd == "approve":
            sys.exit(cmd_approve(os.path.realpath(args.project), args.stage, args.approver, args.note, change_id=args.change))
        if args.cmd == "waive":
            sys.exit(cmd_waive(os.path.realpath(args.project), args.stage, args.reason, change_id=args.change))
        if args.cmd == "status":
            proj = os.path.realpath(args.project)
            _art_dir, rel_dir, cid = resolve_artifact_dir(proj, args.change, strict=True)
            ok1, m1 = verify_stage_approval(proj, "S1_PLAN", f"{rel_dir}/intent.md", change_id=cid)
            ok2, m2 = verify_stage_approval(proj, "S2_DESIGN", f"{rel_dir}/spec.md", change_id=cid)
            out = {
                "project_root": proj,
                "artifact_dir": rel_dir,
                "S1_PLAN": {"approved": ok1, "detail": m1},
                "S2_DESIGN": {"approved": ok2, "detail": m2},
            }
            if cid:
                out["change_id"] = cid
            print(json.dumps(out, indent=2))
            sys.exit(0)
        if args.cmd == "merge-check":
            sys.exit(cmd_merge_check(os.path.realpath(args.project), change_id=args.change))
        if args.cmd == "verify":
            sys.exit(cmd_verify(os.path.realpath(args.project), change_id=args.change, files_arg=args.files))
        if args.cmd == "ci-check":
            sys.exit(cmd_ci_check(os.path.realpath(args.project), base_ref=args.base, change_id=args.change))
        if args.cmd == "hook":
            sys.exit(handle_hook(args.adapter, args.event, change_id=args.change))
    except ValueError as exc:
        print(json.dumps({"status": "error", "error": str(exc)}))
        sys.exit(1)


if __name__ == "__main__":
    main()
