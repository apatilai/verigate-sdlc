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
import subprocess
import sys
import tempfile
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
    r"(^|/)(\.sdlc/(approvals\.json|waivers\.jsonl|audit\.jsonl|bin/[^/]+)|.*shadow_ledger\.json)$",
    re.IGNORECASE,
)
GOVERNANCE_RE = re.compile(
    r"(^|/)(REVIEW\.md|\.sdlc/(REVIEW\.md|config\.json|policy\.json)|\.claude/settings.*\.json|\.agents/hooks\.json|\.gemini/settings\.json|\.githooks/[^/]+|\.github/workflows/[^/]+\.ya?ml|azure-pipelines.*\.ya?ml)$",
    re.IGNORECASE,
)
SANCTIONED_GATE_CMD_RE = re.compile(
    r'^\s*(?:PATH="[^"]*"\s+)?(?:python3?|py)\s+(?:"[^"]*?verigate\.py"|\'[^\']*?verigate\.py\'|\S*?verigate\.py)\s+(status|validate|approve|waive|dispatch|merge-check)\b(.*)$'
)
SHELL_CHAIN_OR_REDIRECT_RE = re.compile(r"[;&|`$><\n]")
ANY_VERIGATE_INVOCATION_RE = re.compile(r"(^|[\s/\"'\\])verigate\.py\b", re.IGNORECASE)
GIT_NO_VERIFY_RE = re.compile(r"\bgit\s+commit\b.*(?:\s--no-verify\b|\s-[a-zA-Z]*n\b)")
SHELL_SECRET_WRITE_RE = re.compile(
    r"(?:>|>>|\btee\b|\bcp\b|\bmv\b).*?(?:^|[\s/\"'])(\.env(?:\.[a-zA-Z0-9_-]+)?|id_rsa|id_ed25519|\S+\.(?:pem|key|p12|pfx))\b",
    re.IGNORECASE,
)
LEDGER_TAMPER_CMD_RE = re.compile(
    r"(\.sdlc/(approvals|waivers|audit|bin|config\.json)|\.claude/settings|\.agents/hooks\.json|\.githooks|shadow_ledger\.json|verigate-shadow)",
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
TEST_RUNNER_CMD_RE = re.compile(
    r"\b(pytest|unittest|npm\s+test|pnpm\s+test|yarn\s+test|bun\s+test|vitest|jest|"
    r"cargo\s+test|go\s+test|mvn\s+test|gradle\s+test|dotnet\s+test|"
    r"ruff\s+check|flake8|mypy|pyright|tsc|eslint)\b",
    re.IGNORECASE,
)

PROJECT_MARKERS = (".sdlc", ".git", "package.json", "pyproject.toml", "go.mod", "Cargo.toml", "pom.xml")
META_DIR_RE = re.compile(r"(^|/)(\.sdlc|\.claude|\.agents|\.cursor|\.githooks|\.codex)(/|$)")
REVIEW_ARTIFACT_RE = re.compile(r"(^|/)\.sdlc/review-(report\.md|findings\.json)$")


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


def validate_intent(text: str) -> tuple[bool, str]:
    s = text.strip()
    if len(s) < 80:
        return False, "`.sdlc/intent.md` must be >=80 chars with scope, constraints, and Acceptance Criteria."
    if not re.search(r"\bAC[-_ ]?1\b", s, re.I):
        return False, "`.sdlc/intent.md` must define numbered Acceptance Criteria (`AC-1..AC-N`)."
    return True, "valid"


def validate_spec(text: str) -> tuple[bool, str]:
    s = text.strip()
    if len(s) < 100:
        return False, "`.sdlc/spec.md` must be >=100 chars with architecture contracts and Verification Matrix."
    if not re.search(r"\b(contract|schema|module|component|architecture)\b", s, re.I):
        return False, "`.sdlc/spec.md` must specify module/component boundaries or contracts."
    if not re.search(r"\b(verif|test|AC[-_ ]?1)\b", s, re.I):
        return False, "`.sdlc/spec.md` must include a Verification Matrix mapping `AC-*` to tests."
    return True, "valid"


def _read_git_head_approval_hash(abs_root: str, stage_key: str) -> str | None:
    """Fallback for fresh git clones / worktrees / CI runners where local shadow ledger has no entry yet."""
    try:
        proc = subprocess.run(
            ["git", "-C", abs_root, "show", "HEAD:.sdlc/approvals.json"],
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


def verify_stage_approval(project_root: str, stage_key: str, rel_artifact: str) -> tuple[bool, str]:
    abs_root = os.path.realpath(project_root)
    art_path = os.path.join(abs_root, rel_artifact)
    if not os.path.isfile(art_path):
        return False, f"Missing `{rel_artifact}` (`{art_path}`)."

    content = Path(art_path).read_text(encoding="utf-8")
    ok, msg = validate_intent(content) if stage_key == "S1_PLAN" else validate_spec(content)
    if not ok:
        return False, f"Incomplete `{rel_artifact}`: {msg}"

    live_hash = file_sha256(art_path)
    approvals_file = os.path.join(abs_root, ".sdlc", "approvals.json")
    if not os.path.isfile(approvals_file):
        return (
            False,
            f"`{rel_artifact}` (sha256 `{live_hash[:12]}`) is unapproved. Review and run: `python3 .sdlc/bin/verigate.py approve --project . --stage S1_S2`.",
        )

    try:
        repo_app = json.loads(Path(approvals_file).read_text(encoding="utf-8"))
    except Exception:
        return False, "Corrupted `.sdlc/approvals.json`."

    repo_entry = (repo_app.get("approvals") or {}).get(stage_key) or {}
    if not repo_entry:
        return False, f"No approval entry for `{stage_key}` (`{rel_artifact}`). Run `verigate.py approve`."

    shadow_entry = (
        (((load_shadow_ledger().get("projects") or {}).get(abs_root) or {}).get("approvals") or {}).get(stage_key)
        or {}
    )
    trusted_hash = shadow_entry.get("sha256")
    if not trusted_hash:
        # On a fresh team clone, git worktree, or CI runner, trust HEAD-committed `.sdlc/approvals.json`
        trusted_hash = _read_git_head_approval_hash(abs_root, stage_key)

    if not trusted_hash:
        return False, f"No verified human approval for `{stage_key}` (`{rel_artifact}`). Run `verigate.py approve`."
    if repo_entry.get("sha256") != trusted_hash:
        return False, f"Ledger mismatch for `{rel_artifact}`; re-run `verigate.py approve`."
    if live_hash != trusted_hash:
        return (
            False,
            f"STALE APPROVAL on `{rel_artifact}` (approved `{trusted_hash[:12]}`, current `{live_hash[:12]}`). Re-approve via `verigate.py approve`.",
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


def render_dispatch_table(info: dict) -> str:
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
            f"| **S1** | Plan | `verigate-requirements` | `.sdlc/intent.md` (`AC-1..AC-N`) | {s12} |",
            f"| **S2** | Design | `verigate-architect` | `.sdlc/spec.md` (Contracts & Matrix) | {s12} |",
            f"| **S3** | Build | `verigate-builder` | Modular Source Code | {s34} |",
            f"| **S4** | Verify | `verigate-verifier` | Executed Tests (or Logged Waiver) | 🟢 Enforced |",
            "| **S5** | Review | `verigate-reviewer` + `verigate-sentinel` | `.sdlc/review-findings.json` + `report.md` | 🟢 Enforced |",
            "| **S6** | Triage | `issue_bridge.py` + Human | GitHub / Azure DevOps + Immediate Fix | 🟢 Dual-Action |",
        ]
    )


def evaluate_file_write(path_str: str, session: dict, cwd: str | None = None) -> tuple[str, str]:
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
    cfg_file = os.path.join(proj_root, ".sdlc", "config.json")
    cfg_enforce = False
    if os.path.isfile(cfg_file):
        try:
            cfg_enforce = bool(json.loads(Path(cfg_file).read_text(encoding="utf-8")).get("require_spec_approval", False))
        except Exception:
            pass

    enforce = bool(session.get("enforceSpec", False)) or cfg_enforce or os.path.isfile(os.path.join(proj_root, ".sdlc", "intent.md"))
    if enforce:
        ok1, m1 = verify_stage_approval(proj_root, "S1_PLAN", ".sdlc/intent.md")
        if not ok1:
            return "deny", f"[VeriGate S1 Gate] Blocked `{base}`: {m1}"
        ok2, m2 = verify_stage_approval(proj_root, "S2_DESIGN", ".sdlc/spec.md")
        if not ok2:
            return "deny", f"[VeriGate S2 Gate] Blocked `{base}`: {m2}"

    return "allow", ""


def evaluate_shell_command(cmd: str) -> tuple[str, str]:
    if GIT_NO_VERIFY_RE.search(cmd):
        return "deny", "[VeriGate Integrity Gate] Bypassing git hooks with `--no-verify` / `-n` is blocked."

    m_secret = SHELL_SECRET_WRITE_RE.search(cmd)
    if m_secret and m_secret.group(1).lower() not in ALLOWED_ENV_EXAMPLES:
        return "deny", f"[VeriGate Secret Gate] Shell write to sensitive file `{m_secret.group(1)}` is blocked."

    if not SHELL_CHAIN_OR_REDIRECT_RE.search(cmd):
        m = SANCTIONED_GATE_CMD_RE.match(cmd)
        if m:
            subcmd = m.group(1)
            if subcmd in ("status", "validate", "dispatch", "merge-check"):
                return "allow", ""
            if subcmd == "approve":
                return "force_ask", "[VeriGate Approval Gate] Confirm human review of `.sdlc/intent.md` & `.sdlc/spec.md` SHA-256 digests."
            if subcmd == "waive":
                return "force_ask", "[VeriGate Waiver Gate] Confirm recording a logged Stage Waiver in `.sdlc/waivers.jsonl`."

    if ANY_VERIGATE_INVOCATION_RE.search(cmd):
        return (
            "deny",
            "[VeriGate Integrity Gate] Invoking `verigate.py` with shell chaining, redirection, or wrappers is blocked. Run standalone: `python3 .sdlc/bin/verigate.py <status|validate|approve|waive|dispatch>`.",
        )

    if LEDGER_TAMPER_CMD_RE.search(cmd):
        return "deny", "[VeriGate Integrity Gate] Direct shell access to `.sdlc` ledgers or hook configs is forbidden."

    if EXTERNAL_MUTATION_CMD_RE.search(cmd):
        return "force_ask", "[VeriGate External Gate] Creating GitHub/Azure DevOps tickets, PRs, or pushing requires human confirmation."

    return "allow", ""


# --- CLI Actions ---


def cmd_init(project_root: str, require_spec: bool) -> int:
    sdlc = Path(project_root) / ".sdlc"
    sdlc.mkdir(parents=True, exist_ok=True)
    cfg = sdlc / "config.json"
    if not cfg.exists():
        cfg.write_text(json.dumps({"require_spec_approval": require_spec, "version": "2.3.0"}, indent=2) + "\n", encoding="utf-8")
    policy = sdlc / "policy.json"
    if not policy.exists():
        policy.write_text(
            json.dumps(
                {
                    "require_zero_findings": True,
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
            "- **High**: Violated `AC-*` in `.sdlc/intent.md`, contract drift from `.sdlc/spec.md`, missing tests.\n"
            "- **Medium**: Performance bottleneck, incomplete boundary validation.\n"
            "- **Low**: Readability, naming, minor tech debt.\n",
            encoding="utf-8",
        )
    print(json.dumps({"status": "initialized", "sdlc_dir": str(sdlc)}, indent=2))
    return 0


def cmd_merge_check(project_root: str) -> int:
    """Deterministic Team Policy Approval Gate: Review (0 open findings) + Spec SHA-256 -> Ready to Merge."""
    sdlc = Path(project_root) / ".sdlc"
    policy_file = sdlc / "policy.json"
    policy = {
        "require_zero_findings": True,
        "max_open_critical": 0,
        "max_open_high": 0,
        "min_quality_score": 85,
        "max_review_fix_cycles": 3,
    }
    if policy_file.is_file():
        try:
            policy.update(json.loads(policy_file.read_text(encoding="utf-8")))
        except Exception:
            pass

    reasons: list[str] = []

    if (sdlc / "intent.md").is_file():
        ok1, m1 = verify_stage_approval(project_root, "S1_PLAN", ".sdlc/intent.md")
        if not ok1:
            reasons.append(f"S1_PLAN: {m1}")
        ok2, m2 = verify_stage_approval(project_root, "S2_DESIGN", ".sdlc/spec.md")
        if not ok2:
            reasons.append(f"S2_DESIGN: {m2}")

    findings_file = sdlc / "review-findings.json"
    open_count = -1
    score = 0
    verdict = "MISSING"
    if not findings_file.is_file():
        reasons.append("Missing `.sdlc/review-findings.json` from Stage 5 Code Review.")
    else:
        try:
            report = json.loads(findings_file.read_text(encoding="utf-8"))
            verdict = str(report.get("verdict") or "UNKNOWN").upper()
            score = int(report.get("quality_score") or 0)
            findings = report.get("findings") or []
            open_findings = [f for f in findings if str(f.get("status") or "open").lower() not in ("fixed", "resolved", "closed", "fixed_verified")]
            open_count = len(open_findings)
            crit_count = sum(1 for f in open_findings if str(f.get("severity") or "").lower() == "critical")
            high_count = sum(1 for f in open_findings if str(f.get("severity") or "").lower() == "high")

            if verdict != "APPROVE":
                reasons.append(f"Review verdict is `{verdict}` (must be `APPROVE`).")
            if policy.get("require_zero_findings", True) and open_count > 0:
                reasons.append(f"{open_count} open review finding(s) remain (team policy requires 0 open findings — run Review <-> Fix cycle).")
            if crit_count > int(policy.get("max_open_critical", 0)):
                reasons.append(f"{crit_count} open Critical finding(s) exceed policy limit.")
            if high_count > int(policy.get("max_open_high", 0)):
                reasons.append(f"{high_count} open High finding(s) exceed policy limit.")
            if score < int(policy.get("min_quality_score", 85)):
                reasons.append(f"Quality score {score} is below team policy minimum ({policy.get('min_quality_score', 85)}).")
        except Exception as exc:
            reasons.append(f"Invalid `.sdlc/review-findings.json`: {exc}")

    ready = len(reasons) == 0
    status = "READY_TO_MERGE" if ready else "BLOCKED_BY_POLICY"
    append_audit(
        project_root,
        "MERGE_POLICY_APPROVED" if ready else "MERGE_POLICY_BLOCKED",
        {"status": status, "verdict": verdict, "quality_score": score, "open_findings": open_count, "reasons": reasons},
    )
    print(
        json.dumps(
            {
                "status": status,
                "ready_to_merge": ready,
                "verdict": verdict,
                "quality_score": score,
                "open_findings": open_count,
                "policy": policy,
                "blocking_reasons": reasons,
            },
            indent=2,
        )
    )
    return 0 if ready else 1


def cmd_approve(project_root: str, stage: str, approver: str, note: str) -> int:
    stage_map = {
        "S1_PLAN": [("S1_PLAN", ".sdlc/intent.md")],
        "S2_DESIGN": [("S2_DESIGN", ".sdlc/spec.md")],
        "S1_S2": [("S1_PLAN", ".sdlc/intent.md"), ("S2_DESIGN", ".sdlc/spec.md")],
    }
    sdlc = Path(project_root) / ".sdlc"
    sdlc.mkdir(parents=True, exist_ok=True)
    app_file = sdlc / "approvals.json"
    repo_data = json.loads(app_file.read_text(encoding="utf-8")) if app_file.is_file() else {"version": "2.2.0", "approvals": {}}
    repo_data.pop("project_root", None)
    repo_data.setdefault("approvals", {})

    shadow = load_shadow_ledger()
    proj_sh = shadow.setdefault("projects", {}).setdefault(project_root, {"approvals": {}, "waivers": []})
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
        append_audit(project_root, "STAGE_CONTENT_APPROVED", {"stage": st_key, "artifact": rel, "sha256": digest, "approved_by": approver})

    tmp = f"{app_file}.tmp"
    Path(tmp).write_text(json.dumps(repo_data, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, app_file)
    save_shadow_ledger(shadow)
    print(json.dumps({"status": "approved", "approved": approved}, indent=2))
    return 0


def cmd_waive(project_root: str, stage: str, reason: str) -> int:
    if len(reason.strip()) < 8:
        print(json.dumps({"status": "error", "error": "Waiver `--reason` must be >=8 chars."}))
        return 1
    sdlc = Path(project_root) / ".sdlc"
    sdlc.mkdir(parents=True, exist_ok=True)
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
    with open(sdlc / "waivers.jsonl", "a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec) + "\n")

    shadow = load_shadow_ledger()
    shadow.setdefault("projects", {}).setdefault(project_root, {"approvals": {}, "waivers": []}).setdefault("waivers", []).append(rec)
    save_shadow_ledger(shadow)
    append_audit(project_root, "STAGE_WAIVER_APPROVED", {"stage": stage, "reason": reason.strip(), "file_count": len(digests)})
    print(json.dumps({"status": "waived", "stage": stage, "waived_file_count": len(digests)}, indent=2))
    return 0


# --- Multi-Harness Hook Protocol Adapter ---


def handle_hook(adapter: str, event_override: str | None) -> int:
    if adapter == "git-pre-commit":
        proj = resolve_project_root(".", os.getcwd())
        proc = subprocess.run(
            ["git", "-C", proj, "diff", "--cached", "--name-only", "--diff-filter=ACMR"],
            capture_output=True,
            text=True,
        )
        staged = [os.path.join(proj, line.strip()) for line in proc.stdout.splitlines() if line.strip()]
        for sp in staged:
            if PROTECTED_LEDGER_RE.search(sp.replace("\\", "/")):
                continue
            decision, reason = evaluate_file_write(sp, {}, proj)
            if decision == "deny":
                sys.stderr.write(f"\n❌ {reason}\n")
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
        table_md = render_dispatch_table(info)
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
            if tname in ("Write", "Edit", "MultiEdit"):
                decision, reason = evaluate_file_write(str(tinput.get("file_path") or ""), session, cwd)
            elif tname == "Bash":
                decision, reason = evaluate_shell_command(str(tinput.get("command") or ""))
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
            decision, reason = evaluate_file_write(str(targs.get("Path") or ""), session, cwd)
        elif tname == "run_command":
            decision, reason = evaluate_shell_command(str(targs.get("CommandLine") or ""))
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
            tresp = payload.get("tool_response") or {}
            if isinstance(tresp, dict) and tresp.get("exit_code") not in (None, 0):
                cmd_failed = True
            path = str(tinput.get("file_path") or "") if tname in ("Write", "Edit", "MultiEdit") else ""
            if tname == "Bash":
                cmd_str = str(tinput.get("command") or "")
            sub_agent = str(tinput.get("subagent_type") or "") if tname == "Task" else ""
        else:
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
        elif cmd_str and not cmd_failed and dirty and TEST_RUNNER_CMD_RE.search(cmd_str):
            session["verified"] = True
        elif not cmd_failed and "verifier" in sub_agent:
            session["verified"] = True
        elif not cmd_failed and "reviewer" in sub_agent:
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
        verified = bool(session.get("verified", True))
        reviewed = bool(session.get("reviewed", True))

        shadow_waivers = (((load_shadow_ledger().get("projects") or {}).get(proj) or {}).get("waivers")) or []
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
            msg = (
                "[VeriGate AI-SDLC Stop Gate] Modified source files require S4 Verification (tests) AND S5 Code Review "
                "(`.sdlc/review-findings.json` + `.sdlc/review-report.md`). If blocked by a missing tool/runtime, request a logged waiver: "
                f'`python3 .sdlc/bin/verigate.py waive --project "{proj}" --stage ALL --reason "<blocker>"`.'
            )
            append_audit(proj, "STOP_GATE_INTERCEPT", {"session_id": session_id})
            if adapter == "claude":
                print(json.dumps({"decision": "block", "reason": msg}))
            else:
                print(json.dumps({"decision": "continue", "reason": msg}))
            return 0

        append_audit(proj, "STOP_GATE_CIRCUIT_BREAKER_TRIPPED", {"session_id": session_id, "files": live_digests})
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

    p_disp = sub.add_parser("dispatch")
    p_disp.add_argument("prompt")

    p_val = sub.add_parser("validate")
    p_val.add_argument("--project", default=".")

    p_app = sub.add_parser("approve")
    p_app.add_argument("--project", default=".")
    p_app.add_argument("--stage", choices=["S1_PLAN", "S2_DESIGN", "S1_S2"], default="S1_S2")
    p_app.add_argument("--approver", default="human_validator")
    p_app.add_argument("--note", default="")

    p_waive = sub.add_parser("waive")
    p_waive.add_argument("--project", default=".")
    p_waive.add_argument("--stage", choices=["S4_TEST", "S5_REVIEW", "ALL"], default="ALL")
    p_waive.add_argument("--reason", required=True)

    p_stat = sub.add_parser("status")
    p_stat.add_argument("--project", default=".")

    p_merge = sub.add_parser("merge-check")
    p_merge.add_argument("--project", default=".")

    p_hook = sub.add_parser("hook")
    p_hook.add_argument("--adapter", choices=["auto", "antigravity", "claude", "git-pre-commit"], default="auto")
    p_hook.add_argument("--event", default=None)

    args = parser.parse_args()

    if args.cmd == "init":
        sys.exit(cmd_init(os.path.realpath(args.project), args.require_spec))
    if args.cmd == "dispatch":
        info = classify_prompt(args.prompt) or {"profile": "General Engineering", "code": "change", "enforce_spec": False}
        print(render_dispatch_table(info))
        sys.exit(0)
    if args.cmd == "validate":
        proj = os.path.realpath(args.project)
        ok1, m1 = verify_stage_approval(proj, "S1_PLAN", ".sdlc/intent.md")
        ok2, m2 = verify_stage_approval(proj, "S2_DESIGN", ".sdlc/spec.md")
        print(json.dumps({"S1_PLAN": m1, "S2_DESIGN": m2, "ready_for_build": bool(ok1 and ok2)}, indent=2))
        sys.exit(0 if (ok1 and ok2) else 1)
    if args.cmd == "approve":
        sys.exit(cmd_approve(os.path.realpath(args.project), args.stage, args.approver, args.note))
    if args.cmd == "waive":
        sys.exit(cmd_waive(os.path.realpath(args.project), args.stage, args.reason))
    if args.cmd == "status":
        proj = os.path.realpath(args.project)
        ok1, m1 = verify_stage_approval(proj, "S1_PLAN", ".sdlc/intent.md")
        ok2, m2 = verify_stage_approval(proj, "S2_DESIGN", ".sdlc/spec.md")
        print(json.dumps({"project_root": proj, "S1_PLAN": {"approved": ok1, "detail": m1}, "S2_DESIGN": {"approved": ok2, "detail": m2}}, indent=2))
        sys.exit(0)
    if args.cmd == "merge-check":
        sys.exit(cmd_merge_check(os.path.realpath(args.project)))
    if args.cmd == "hook":
        sys.exit(handle_hook(args.adapter, args.event))


if __name__ == "__main__":
    main()
