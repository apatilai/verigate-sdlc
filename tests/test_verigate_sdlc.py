#!/usr/bin/env python3
"""Bundled zero-dependency unittest suite for VeriGate AI-SDLC (v3.0).

Run with:
    python3 -m unittest discover -s tests -v
"""

from __future__ import annotations

import importlib.util
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

KIT_ROOT = pathlib.Path(__file__).resolve().parent.parent

VALID_INTENT_MD = (
    "# Billing Service Intent\n\n"
    "## Scope\n"
    "Implement multi-tenant invoice generation with strict tenant isolation, idempotency keys, "
    "and deterministic audit logging for every API request.\n\n"
    "## Constraints & Non-Goals\n"
    "- No cross-tenant reads or shared mutable state.\n"
    "- Out of scope: payment processor settlement retries.\n\n"
    "## Acceptance Criteria\n"
    "- AC-1: Return HTTP 200 with a tenant-scoped invoice JSON payload.\n"
    "- AC-2: Reject cross-tenant invoice access with HTTP 403 and zero data leakage.\n"
)

VALID_SPEC_MD = (
    "# Billing Architecture Spec\n\n"
    "## Architecture & Module Contracts\n"
    "Module `src/app.py` defines the invoice handler schema, idempotency store interface, "
    "and tenant authorization contract enforced at the service boundary.\n\n"
    "## Security & Guardrails\n"
    "All requests validate signed tenant JWT claims before querying storage. Secrets are "
    "injected via environment variables and never persisted in repository files.\n\n"
    "## Verification Matrix\n"
    "- AC-1 -> unit test `test_tenant_invoice_200`\n"
    "- AC-2 -> security test `test_cross_tenant_403`\n"
)


def _load_module(name: str, path: pathlib.Path):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod


class VeriGateSDLCTestSuite(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp_dir = pathlib.Path(os.path.realpath(tempfile.mkdtemp(prefix="aisdlc-ut-")))
        self.repo = self.tmp_dir / "app-repo"
        self.repo.mkdir()
        self.env = os.environ.copy()
        self.env["VERIGATE_DATA_DIR"] = str(self.tmp_dir / "shadow")
        self.env.pop("VERIGATE_CHANGE", None)

        subprocess.run(["git", "init", str(self.repo)], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(self.repo), "config", "user.email", "ci@example.com"], check=True)
        subprocess.run(["git", "-C", str(self.repo), "config", "user.name", "CI"], check=True)

        subprocess.run(
            [sys.executable, str(KIT_ROOT / "install_verigate.py"), "--target", str(self.repo), "--targets", "all", "--activate-git-hooks", "--require-spec"],
            check=True,
            capture_output=True,
            env=self.env,
        )
        self.aisdlc_bin = self.repo / ".sdlc" / "bin" / "verigate.py"
        self.bridge_bin = self.repo / ".sdlc" / "bin" / "issue_bridge.py"

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def _hook(self, payload: dict, raw_override: str | None = None, env_override: dict | None = None) -> dict:
        p = subprocess.run(
            [sys.executable, str(self.aisdlc_bin), "hook", "--adapter", "auto"],
            input=raw_override if raw_override is not None else json.dumps(payload),
            text=True,
            capture_output=True,
            cwd=str(self.repo),
            env=env_override if env_override is not None else self.env,
        )
        self.assertEqual(p.returncode, 0, p.stderr)
        return json.loads(p.stdout)

    def test_rev001_and_rev002_security_gates(self) -> None:
        # Chained approve command -> DENY
        r_chain = self._hook(
            {"session_id": "s1", "hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "true && python3 .sdlc/bin/verigate.py approve --stage S1_S2"}, "cwd": str(self.repo)}
        )
        self.assertEqual(r_chain["hookSpecificOutput"]["permissionDecision"], "deny")

        # Standalone approve command -> ASK (force_ask in Antigravity)
        r_ok = self._hook(
            {"conversationId": "a1", "hookEventName": "PreToolUse", "toolCall": {"name": "run_command", "args": {"CommandLine": "python3 .sdlc/bin/verigate.py approve --project . --stage S1_S2"}}, "cwd": str(self.repo)}
        )
        self.assertEqual(r_ok["decision"], "force_ask")

        # git commit --no-verify & shell secret write -> DENY
        r_nv = self._hook({"conversationId": "a1", "hookEventName": "PreToolUse", "toolCall": {"name": "run_command", "args": {"CommandLine": "git commit -m bypass --no-verify"}}, "cwd": str(self.repo)})
        self.assertEqual(r_nv["decision"], "deny")
        r_env_sh = self._hook({"conversationId": "a1", "hookEventName": "PreToolUse", "toolCall": {"name": "run_command", "args": {"CommandLine": "echo SECRET=1 > .env"}}, "cwd": str(self.repo)})
        self.assertEqual(r_env_sh["decision"], "deny")

        # Control-plane self-edit -> DENY; hook config edit -> ASK
        r_self = self._hook({"session_id": "s1", "hook_event_name": "PreToolUse", "tool_name": "Write", "tool_input": {"file_path": ".sdlc/bin/verigate.py"}, "cwd": str(self.repo)})
        self.assertEqual(r_self["hookSpecificOutput"]["permissionDecision"], "deny")
        r_cfg = self._hook({"session_id": "s1", "hook_event_name": "PreToolUse", "tool_name": "Write", "tool_input": {"file_path": ".claude/settings.json"}, "cwd": str(self.repo)})
        self.assertEqual(r_cfg["hookSpecificOutput"]["permissionDecision"], "ask")

    def test_rev003_and_rev004_approval_clone_and_idempotent_install(self) -> None:
        # Relative .sdlc/intent.md allowed even before approval
        r_intent = self._hook({"session_id": "s2", "hook_event_name": "PreToolUse", "tool_name": "Write", "tool_input": {"file_path": ".sdlc/intent.md"}, "cwd": str(self.repo)})
        self.assertEqual(r_intent["hookSpecificOutput"]["permissionDecision"], "allow")

        # Preserve custom brownfield content across re-install
        (self.repo / "CLAUDE.md").write_text("# Team Custom Instructions\nKeep this header.\n\n" + (self.repo / "CLAUDE.md").read_text(encoding="utf-8"), encoding="utf-8")
        claude_cfg = json.loads((self.repo / ".claude/settings.json").read_text(encoding="utf-8"))
        claude_cfg["permissions"] = {"allow": ["Read"]}
        (self.repo / ".claude/settings.json").write_text(json.dumps(claude_cfg), encoding="utf-8")

        subprocess.run([sys.executable, str(KIT_ROOT / "install_verigate.py"), "--target", str(self.repo), "--targets", "claude"], check=True, capture_output=True, env=self.env)
        merged_md = (self.repo / "CLAUDE.md").read_text(encoding="utf-8")
        self.assertIn("# Team Custom Instructions", merged_md)
        self.assertEqual(merged_md.count("<!-- VERIGATE:START -->"), 1)
        merged_cfg = json.loads((self.repo / ".claude/settings.json").read_text(encoding="utf-8"))
        self.assertEqual(merged_cfg["permissions"], {"allow": ["Read"]})
        self.assertEqual(len(merged_cfg["hooks"]["PreToolUse"]), 1)

        # Author & approve S1+S2, commit to git, then simulate a teammate's fresh clone (empty shadow ledger!)
        (self.repo / ".sdlc/intent.md").write_text(VALID_INTENT_MD, encoding="utf-8")
        (self.repo / ".sdlc/spec.md").write_text(VALID_SPEC_MD, encoding="utf-8")
        subprocess.run([sys.executable, str(self.aisdlc_bin), "approve", "--project", str(self.repo), "--stage", "S1_S2"], check=True, capture_output=True, env=self.env)
        (self.repo / "src").mkdir()
        (self.repo / "src/app.py").write_text("x = 1\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.repo), "add", "."], check=True)
        subprocess.run(["git", "-C", str(self.repo), "commit", "-m", "initial approved commit"], check=True, capture_output=True, env=self.env)

        clone_dir = self.tmp_dir / "teammate-clone"
        subprocess.run(["git", "clone", str(self.repo), str(clone_dir)], check=True, capture_output=True)
        fresh_env = self.env.copy()
        fresh_env["VERIGATE_DATA_DIR"] = str(self.tmp_dir / "empty-teammate-shadow")
        p_stat = subprocess.run([sys.executable, str(clone_dir / ".sdlc/bin/verigate.py"), "status", "--project", str(clone_dir)], check=True, capture_output=True, text=True, env=fresh_env)
        stat_data = json.loads(p_stat.stdout)
        self.assertTrue(stat_data["S1_PLAN"]["approved"])
        self.assertTrue(stat_data["S2_DESIGN"]["approved"])

    def test_rev005_and_rev006_post_tool_stop_and_issue_bridge(self) -> None:
        # Malformed JSON on hook stdin exits 0 cleanly
        self.assertEqual(self._hook({}, raw_override="{malformed"), {})

        # Non-test shell command (`git status`) must NOT mark dirty edits verified
        (self.repo / "src").mkdir(exist_ok=True)
        f = self.repo / "src/mod.py"
        f.write_text("y = 2\n", encoding="utf-8")
        self._hook({"session_id": "s6", "hook_event_name": "PostToolUse", "tool_name": "Write", "tool_input": {"file_path": "src/mod.py"}, "cwd": str(self.repo)})
        self._hook({"session_id": "s6", "hook_event_name": "PostToolUse", "tool_name": "Bash", "tool_input": {"command": "git status"}, "cwd": str(self.repo)})
        self._hook({"session_id": "s6", "hook_event_name": "PostToolUse", "tool_name": "Write", "tool_input": {"file_path": ".sdlc/review-findings.json"}, "cwd": str(self.repo)})
        # Still unverified -> Stop blocks!
        s_block = self._hook({"session_id": "s6", "hook_event_name": "Stop", "stop_hook_active": False, "cwd": str(self.repo)})
        self.assertEqual(s_block["decision"], "block")

        # Real test runner (`python3 -m unittest`) marks verified=True -> Stop allows!
        self._hook({"session_id": "s6", "hook_event_name": "PostToolUse", "tool_name": "Bash", "tool_input": {"command": "python3 -m unittest"}, "tool_response": {"exit_code": 0}, "cwd": str(self.repo)})
        s_ok = self._hook({"session_id": "s6", "hook_event_name": "Stop", "stop_hook_active": True, "cwd": str(self.repo)})
        self.assertEqual(s_ok, {})

        # Issue bridge: idempotent skip on existing tracker_id + missing-CLI error resilience
        bridge = _load_module("issue_bridge", self.bridge_bin)
        findings_path = self.repo / ".sdlc/review-findings.json"
        findings_path.write_text(
            json.dumps(
                {
                    "detected_provider": "azdo",
                    "findings": [
                        {"id": "REV-001", "severity": "High", "title": "Already filed", "tracker_id": "AB#99", "tracker_url": "https://dev.azure.com/org/proj/_workitems/edit/99"},
                    ],
                }
            ),
            encoding="utf-8",
        )
        p_create = subprocess.run([sys.executable, str(self.bridge_bin), "create", "--findings", str(findings_path), "--provider", "azdo"], check=True, capture_output=True, text=True)
        res = json.loads(p_create.stdout)["results"]
        self.assertEqual(res[0]["status"], "skipped_existing")
        self.assertEqual(res[0]["tracker_id"], "AB#99")

        # Verify missing binary returns structured error dict instead of raising FileNotFoundError
        orig_run = bridge.subprocess.run
        try:
            def _raise_fnf(*_a, **_kw):
                raise FileNotFoundError("az not installed")
            bridge.subprocess.run = _raise_fnf
            err_res = bridge._create_azdo_work_item({"id": "REV-002", "severity": "High", "title": "Bug"}, "https://dev.azure.com/o", "p", "Bug")
            self.assertEqual(err_res["status"], "error")
            self.assertIn("az not installed", err_res["error"])
        finally:
            bridge.subprocess.run = orig_run

    def test_review_fix_policy_merge_loop(self) -> None:
        # Step 1: 2 findings -> BLOCKED_BY_POLICY
        findings_path = self.repo / ".sdlc/review-findings.json"
        findings_path.write_text(
            json.dumps(
                {
                    "verdict": "CHANGES_REQUESTED",
                    "quality_score": 72,
                    "findings": [
                        {"id": "REV-001", "severity": "High", "status": "open", "title": "Finding 1"},
                        {"id": "REV-002", "severity": "Medium", "status": "open", "title": "Finding 2"},
                    ],
                }
            ),
            encoding="utf-8",
        )
        p1 = subprocess.run([sys.executable, str(self.aisdlc_bin), "merge-check", "--project", str(self.repo)], capture_output=True, text=True, env=self.env)
        self.assertNotEqual(p1.returncode, 0)
        d1 = json.loads(p1.stdout)
        self.assertEqual(d1["status"], "BLOCKED_BY_POLICY")
        self.assertEqual(d1["open_findings"], 2)

        # Step 2: Fix 1 pushed -> 1 finding remaining -> still BLOCKED_BY_POLICY
        findings_path.write_text(
            json.dumps(
                {
                    "verdict": "CHANGES_REQUESTED",
                    "quality_score": 84,
                    "findings": [
                        {"id": "REV-001", "severity": "High", "status": "fixed_verified", "title": "Finding 1"},
                        {"id": "REV-002", "severity": "Medium", "status": "open", "title": "Finding 2"},
                    ],
                }
            ),
            encoding="utf-8",
        )
        p2 = subprocess.run([sys.executable, str(self.aisdlc_bin), "merge-check", "--project", str(self.repo)], capture_output=True, text=True, env=self.env)
        self.assertNotEqual(p2.returncode, 0)
        self.assertEqual(json.loads(p2.stdout)["open_findings"], 1)

        # Step 3: Fix 2 pushed -> 0 open findings + APPROVE -> READY_TO_MERGE!
        findings_path.write_text(
            json.dumps({"verdict": "APPROVE", "quality_score": 96, "findings": []}),
            encoding="utf-8",
        )
        p3 = subprocess.run([sys.executable, str(self.aisdlc_bin), "merge-check", "--project", str(self.repo)], capture_output=True, text=True, env=self.env)
        self.assertEqual(p3.returncode, 0, p3.stdout)
        d3 = json.loads(p3.stdout)
        self.assertEqual(d3["status"], "READY_TO_MERGE")
        self.assertTrue(d3["ready_to_merge"])
        self.assertEqual(d3["open_findings"], 0)

    def test_gap1_shell_writes_blocked_and_tracked(self) -> None:
        # Spec lock is ON (--require-spec in setUp) and S1/S2 not approved yet.
        # Shell writes must be denied in PreToolUse.
        shell_cmds = [
            "sed -i 's/a/b/g' src/app.py",
            "cat > src/app.py",
            "python3 -c \"open('src/app.py','w').write('x=1')\"",
        ]
        for cmd in shell_cmds:
            res = self._hook(
                {"session_id": "gap1", "hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": cmd}, "cwd": str(self.repo)}
            )
            self.assertEqual(res["hookSpecificOutput"]["permissionDecision"], "deny", f"Expected deny for: {cmd}")

        # In PostToolUse, a shell write to a source file must mark dirtyFiles and reset verified/reviewed
        (self.repo / "src").mkdir(exist_ok=True)
        (self.repo / "src/app.py").write_text("x = 1\n", encoding="utf-8")
        self._hook(
            {
                "session_id": "gap1-post",
                "hook_event_name": "PostToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "cat > src/app.py"},
                "tool_response": {"exit_code": 0},
                "cwd": str(self.repo),
            }
        )
        s_block = self._hook({"session_id": "gap1-post", "hook_event_name": "Stop", "stop_hook_active": False, "cwd": str(self.repo)})
        self.assertEqual(s_block["decision"], "block")

        # Also verify python3 -c open(...,'w') resets verified after a previous test pass
        self._hook(
            {
                "session_id": "gap1-post2",
                "hook_event_name": "PostToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "python3 -c \"open('src/app.py','w').write('x=2')\""},
                "tool_response": {"exit_code": 0},
                "cwd": str(self.repo),
            }
        )
        self._hook({"session_id": "gap1-post2", "hook_event_name": "PostToolUse", "tool_name": "Write", "tool_input": {"file_path": ".sdlc/review-findings.json"}, "cwd": str(self.repo)})
        s_block2 = self._hook({"session_id": "gap1-post2", "hook_event_name": "Stop", "stop_hook_active": False, "cwd": str(self.repo)})
        self.assertEqual(s_block2["decision"], "block")

    def test_gap2_powershell_and_notebook_edit_gates(self) -> None:
        # Check .claude/settings.json matchers include PowerShell and NotebookEdit
        claude_cfg = json.loads((self.repo / ".claude/settings.json").read_text(encoding="utf-8"))
        pre_matcher = claude_cfg["hooks"]["PreToolUse"][0]["matcher"]
        post_matcher = claude_cfg["hooks"]["PostToolUse"][0]["matcher"]
        for tool in ("PowerShell", "NotebookEdit"):
            self.assertIn(tool, pre_matcher)
            self.assertIn(tool, post_matcher)

        # PowerShell source writes denied under spec lock
        for ps_cmd in (
            "Set-Content -Path src/app.py -Value 'x=1'",
            "'x=1' | Out-File -FilePath src/app.py",
        ):
            r_ps = self._hook(
                {"session_id": "gap2", "hook_event_name": "PreToolUse", "tool_name": "PowerShell", "tool_input": {"command": ps_cmd}, "cwd": str(self.repo)}
            )
            self.assertEqual(r_ps["hookSpecificOutput"]["permissionDecision"], "deny", f"Expected deny for: {ps_cmd}")

        # NotebookEdit denied under spec lock
        r_nb = self._hook(
            {"session_id": "gap2", "hook_event_name": "PreToolUse", "tool_name": "NotebookEdit", "tool_input": {"notebook_path": "notebooks/analysis.ipynb"}, "cwd": str(self.repo)}
        )
        self.assertEqual(r_nb["hookSpecificOutput"]["permissionDecision"], "deny")

        # PowerShell ledger edits and secret edits always denied
        for tamper_cmd in (
            "Set-Content -Path .sdlc\\approvals.json -Value '{}'",
            "'{}' | Out-File .sdlc/approvals.json",
            "Remove-Item .sdlc\\approvals.json",
            "Set-Content -Path .env -Value 'SECRET=1'",
        ):
            r_tamper = self._hook(
                {"session_id": "gap2", "hook_event_name": "PreToolUse", "tool_name": "PowerShell", "tool_input": {"command": tamper_cmd}, "cwd": str(self.repo)}
            )
            self.assertEqual(r_tamper["hookSpecificOutput"]["permissionDecision"], "deny", f"Expected deny for: {tamper_cmd}")

        # NotebookEdit tracked in PostToolUse
        (self.repo / "notebooks").mkdir(exist_ok=True)
        (self.repo / "notebooks/analysis.ipynb").write_text("{}", encoding="utf-8")
        self._hook(
            {"session_id": "gap2-nb", "hook_event_name": "PostToolUse", "tool_name": "NotebookEdit", "tool_input": {"notebook_path": "notebooks/analysis.ipynb"}, "cwd": str(self.repo)}
        )
        self._hook({"session_id": "gap2-nb", "hook_event_name": "PostToolUse", "tool_name": "Write", "tool_input": {"file_path": ".sdlc/review-findings.json"}, "cwd": str(self.repo)})
        s_nb = self._hook({"session_id": "gap2-nb", "hook_event_name": "Stop", "stop_hook_active": False, "cwd": str(self.repo)})
        self.assertEqual(s_nb["decision"], "block")

    def test_gap3_and_gap8_real_test_exit_codes_and_agent_tool(self) -> None:
        # Gap #8: Agent tool in Claude PostToolUse matcher
        claude_cfg = json.loads((self.repo / ".claude/settings.json").read_text(encoding="utf-8"))
        post_matcher = claude_cfg["hooks"]["PostToolUse"][0]["matcher"]
        self.assertIn("Agent", post_matcher)
        self.assertIn("Task", post_matcher)

        (self.repo / "src").mkdir(exist_ok=True)
        (self.repo / "src/svc.py").write_text("v = 1\n", encoding="utf-8")

        # Mark dirty via Write, mark reviewed via Claude `Agent` tool (Gap #8)
        self._hook({"session_id": "gap3", "hook_event_name": "PostToolUse", "tool_name": "Write", "tool_input": {"file_path": "src/svc.py"}, "cwd": str(self.repo)})
        self._hook({"session_id": "gap3", "hook_event_name": "PostToolUse", "tool_name": "Agent", "tool_input": {"subagent_type": "verigate-reviewer"}, "cwd": str(self.repo)})

        # `echo pytest` must NOT mark verified
        self._hook({"session_id": "gap3", "hook_event_name": "PostToolUse", "tool_name": "Bash", "tool_input": {"command": "echo pytest"}, "tool_response": {"exit_code": 0}, "cwd": str(self.repo)})
        # Calling verifier subagent via Agent or Task must NOT mark verified
        self._hook({"session_id": "gap3", "hook_event_name": "PostToolUse", "tool_name": "Agent", "tool_input": {"subagent_type": "verigate-verifier"}, "cwd": str(self.repo)})
        self._hook({"session_id": "gap3", "hook_event_name": "PostToolUse", "tool_name": "Task", "tool_input": {"subagent_type": "verigate-verifier"}, "cwd": str(self.repo)})
        # Real test command with non-zero exit_code must NOT mark verified
        self._hook({"session_id": "gap3", "hook_event_name": "PostToolUse", "tool_name": "Bash", "tool_input": {"command": "pytest -q"}, "tool_response": {"exit_code": 1}, "cwd": str(self.repo)})

        # Stop must still block (not verified!)
        s_block = self._hook({"session_id": "gap3", "hook_event_name": "Stop", "stop_hook_active": False, "cwd": str(self.repo)})
        self.assertEqual(s_block["decision"], "block")

        # Real test command with exit_code == 0 DOES mark verified -> Stop allows (since Agent reviewer already set reviewed=True!)
        self._hook({"session_id": "gap3", "hook_event_name": "PostToolUse", "tool_name": "Bash", "tool_input": {"command": "pytest -q"}, "tool_response": {"exit_code": 0}, "cwd": str(self.repo)})
        s_allow = self._hook({"session_id": "gap3", "hook_event_name": "Stop", "stop_hook_active": False, "cwd": str(self.repo)})
        self.assertEqual(s_allow, {})

    def test_gap6_stronger_intent_and_spec_content_validation(self) -> None:
        # Thin 80-char intent.md with only AC-1 must be REJECTED
        thin_intent = "# Intent\nScope: Build billing endpoint.\n- AC-1: Return HTTP 200 on valid call.\n"
        self.assertLess(len(thin_intent.strip()), 100)
        (self.repo / ".sdlc/intent.md").write_text(thin_intent, encoding="utf-8")
        (self.repo / ".sdlc/spec.md").write_text(VALID_SPEC_MD, encoding="utf-8")

        p_rej = subprocess.run(
            [sys.executable, str(self.aisdlc_bin), "approve", "--project", str(self.repo), "--stage", "S1_S2"],
            capture_output=True,
            text=True,
            env=self.env,
        )
        self.assertNotEqual(p_rej.returncode, 0)
        self.assertIn("200", p_rej.stdout)

        # Full >=200-char intent.md with Scope, Constraints, AC-1, AC-2 passes
        (self.repo / ".sdlc/intent.md").write_text(VALID_INTENT_MD, encoding="utf-8")
        p_ok = subprocess.run(
            [sys.executable, str(self.aisdlc_bin), "approve", "--project", str(self.repo), "--stage", "S1_S2"],
            capture_output=True,
            text=True,
            env=self.env,
        )
        self.assertEqual(p_ok.returncode, 0, p_ok.stdout + p_ok.stderr)
        self.assertEqual(json.loads(p_ok.stdout)["status"], "approved")

    def test_gap7_per_change_isolation(self) -> None:
        # Initialize two independent changes: PROJ-123 and PROJ-456
        subprocess.run([sys.executable, str(self.aisdlc_bin), "init", "--project", str(self.repo), "--change", "PROJ-123"], check=True, capture_output=True, env=self.env)
        c123 = self.repo / ".sdlc/changes/PROJ-123"
        c456 = self.repo / ".sdlc/changes/PROJ-456"
        c456.mkdir(parents=True, exist_ok=True)

        (c123 / "intent.md").write_text(VALID_INTENT_MD, encoding="utf-8")
        (c123 / "spec.md").write_text(VALID_SPEC_MD, encoding="utf-8")
        (c123 / "review-findings.json").write_text(json.dumps({"verdict": "APPROVE", "quality_score": 95, "findings": []}), encoding="utf-8")

        # PROJ-456 has unapproved intent/spec and blocking findings
        (c456 / "intent.md").write_text(VALID_INTENT_MD + "\nExtra note for PROJ-456.\n", encoding="utf-8")
        (c456 / "spec.md").write_text(VALID_SPEC_MD + "\nExtra note for PROJ-456.\n", encoding="utf-8")
        (c456 / "review-findings.json").write_text(
            json.dumps({"verdict": "CHANGES_REQUESTED", "quality_score": 60, "findings": [{"id": "REV-1", "severity": "High", "status": "open"}]}),
            encoding="utf-8",
        )

        # Approve only PROJ-123
        p_app = subprocess.run([sys.executable, str(self.aisdlc_bin), "approve", "--project", str(self.repo), "--change", "PROJ-123", "--stage", "S1_S2"], check=True, capture_output=True, text=True, env=self.env)
        self.assertEqual(json.loads(p_app.stdout)["change_id"], "PROJ-123")
        self.assertTrue((c123 / "approvals.json").is_file())
        self.assertFalse((c456 / "approvals.json").exists())

        # PROJ-123 passes validate & merge-check; PROJ-456 fails both without colliding
        p_val123 = subprocess.run([sys.executable, str(self.aisdlc_bin), "validate", "--project", str(self.repo), "--change", "PROJ-123"], capture_output=True, text=True, env=self.env)
        self.assertEqual(p_val123.returncode, 0, p_val123.stdout)
        p_mc123 = subprocess.run([sys.executable, str(self.aisdlc_bin), "merge-check", "--project", str(self.repo), "--change", "PROJ-123"], capture_output=True, text=True, env=self.env)
        self.assertEqual(p_mc123.returncode, 0, p_mc123.stdout)
        self.assertEqual(json.loads(p_mc123.stdout)["status"], "READY_TO_MERGE")

        p_val456 = subprocess.run([sys.executable, str(self.aisdlc_bin), "validate", "--project", str(self.repo), "--change", "PROJ-456"], capture_output=True, text=True, env=self.env)
        self.assertNotEqual(p_val456.returncode, 0)
        p_mc456 = subprocess.run([sys.executable, str(self.aisdlc_bin), "merge-check", "--project", str(self.repo), "--change", "PROJ-456"], capture_output=True, text=True, env=self.env)
        self.assertNotEqual(p_mc456.returncode, 0)
        self.assertEqual(json.loads(p_mc456.stdout)["status"], "BLOCKED_BY_POLICY")

    def test_gap9_dry_run_backups_and_fail_closed_json(self) -> None:
        # 1. --dry-run writes zero files
        dry_repo = self.tmp_dir / "dry-repo"
        dry_repo.mkdir()
        p_dry = subprocess.run(
            [sys.executable, str(KIT_ROOT / "install_verigate.py"), "--target", str(dry_repo), "--targets", "all", "--dry-run"],
            check=True,
            capture_output=True,
            text=True,
            env=self.env,
        )
        dry_out = json.loads(p_dry.stdout)
        self.assertTrue(dry_out["dry_run"])
        self.assertGreater(len(dry_out["created"]), 0)
        self.assertEqual(list(dry_repo.iterdir()), [], "--dry-run must write zero files")

        # 2. Re-install creates .sdlc/backups/
        p_re = subprocess.run(
            [sys.executable, str(KIT_ROOT / "install_verigate.py"), "--target", str(self.repo), "--targets", "claude"],
            check=True,
            capture_output=True,
            text=True,
            env=self.env,
        )
        re_out = json.loads(p_re.stdout)
        self.assertGreater(len(re_out["backed_up"]), 0)
        backups_root = self.repo / ".sdlc/backups"
        self.assertTrue(backups_root.is_dir())
        self.assertGreater(len(list(backups_root.iterdir())), 0)

        # 3. Malformed .claude/settings.json fails non-zero without overwriting
        bad_json = "{not valid json"
        settings_path = self.repo / ".claude/settings.json"
        settings_path.write_text(bad_json, encoding="utf-8")
        p_bad = subprocess.run(
            [sys.executable, str(KIT_ROOT / "install_verigate.py"), "--target", str(self.repo), "--targets", "claude"],
            capture_output=True,
            text=True,
            env=self.env,
        )
        self.assertNotEqual(p_bad.returncode, 0)
        self.assertEqual(settings_path.read_text(encoding="utf-8"), bad_json)

    def test_gap10_terraform_iac_runners_mark_verified(self) -> None:
        (self.repo / "infra").mkdir(exist_ok=True)
        (self.repo / "infra/main.tf").write_text('resource "null_resource" "a" {}\n', encoding="utf-8")

        for idx, tf_cmd in enumerate(("terraform validate", "terraform fmt -check", "tflint")):
            sid = f"gap10-{idx}"
            self._hook({"session_id": sid, "hook_event_name": "PostToolUse", "tool_name": "Write", "tool_input": {"file_path": "infra/main.tf"}, "cwd": str(self.repo)})
            self._hook({"session_id": sid, "hook_event_name": "PostToolUse", "tool_name": "Write", "tool_input": {"file_path": ".sdlc/review-findings.json"}, "cwd": str(self.repo)})

            # Non-zero exit code must NOT verify
            self._hook({"session_id": sid, "hook_event_name": "PostToolUse", "tool_name": "Bash", "tool_input": {"command": tf_cmd}, "tool_response": {"exit_code": 1}, "cwd": str(self.repo)})
            s_blk = self._hook({"session_id": sid, "hook_event_name": "Stop", "stop_hook_active": False, "cwd": str(self.repo)})
            self.assertEqual(s_blk["decision"], "block", f"Expected Stop block when {tf_cmd} exited 1")

            # Zero exit code MUST verify
            self._hook({"session_id": sid, "hook_event_name": "PostToolUse", "tool_name": "Bash", "tool_input": {"command": tf_cmd}, "tool_response": {"exit_code": 0}, "cwd": str(self.repo)})
            s_ok = self._hook({"session_id": sid, "hook_event_name": "Stop", "stop_hook_active": False, "cwd": str(self.repo)})
            self.assertEqual(s_ok, {}, f"Expected Stop allow when {tf_cmd} exited 0")

    def test_gap11_and_gap12_azure_pipelines_and_no_sh_c_hooks(self) -> None:
        # Gap #11: azure-pipelines.yml generated by --targets ci
        ci_repo = self.tmp_dir / "ci-repo"
        ci_repo.mkdir()
        subprocess.run(
            [sys.executable, str(KIT_ROOT / "install_verigate.py"), "--target", str(ci_repo), "--targets", "ci"],
            check=True,
            capture_output=True,
            env=self.env,
        )
        self.assertTrue((ci_repo / "azure-pipelines.yml").is_file())
        self.assertTrue((ci_repo / ".github/workflows/verigate-gate.yml").is_file())
        azdo_text = (ci_repo / "azure-pipelines.yml").read_text(encoding="utf-8")
        self.assertIn("VERIGATE_REF", azdo_text)
        self.assertIn("ci-check --project .", azdo_text)
        self.assertNotIn(".sdlc/bin/verigate.py", azdo_text)

        # Gap #12 & Finding #8: Generated .claude/settings.json and .agents/hooks.json do NOT wrap commands in `sh -c`
        # and Claude hooks use `$CLAUDE_PROJECT_DIR/.sdlc/bin/verigate.py`.
        claude_raw = (self.repo / ".claude/settings.json").read_text(encoding="utf-8")
        ag_raw = (self.repo / ".agents/hooks.json").read_text(encoding="utf-8")
        self.assertNotIn("sh -c", claude_raw)
        self.assertNotIn("sh -c", ag_raw)
        self.assertIn("$CLAUDE_PROJECT_DIR/.sdlc/bin/verigate.py", claude_raw)
        self.assertIn("verigate.py hook", ag_raw)

    def test_gaps4_and_5_readme_honest_control_framing(self) -> None:
        readme = (KIT_ROOT / "README.md").read_text(encoding="utf-8")
        lower = readme.lower()
        self.assertIn("three-layer control architecture", lower)
        self.assertIn("optional early-feedback adapters", lower)
        self.assertIn("branch protection", lower)
        self.assertIn("human approval", lower)
        self.assertIn("azure-pipelines.yml", readme)
        self.assertIn("verigate-gate.yml", readme)

    def test_v25_finding1_exact_test_runner_and_error_swallowing(self) -> None:
        (self.repo / "src").mkdir(exist_ok=True)
        (self.repo / "src/svc.py").write_text("v = 1\n", encoding="utf-8")

        non_verifying_cmds = [
            "pip install pytest",
            'git commit -m "add pytest config"',
            "grep -r jest package.json",
            "pytest || true",
            "pytest; true",
        ]
        for idx, cmd in enumerate(non_verifying_cmds):
            sid = f"f1-neg-{idx}"
            self._hook({"session_id": sid, "hook_event_name": "PostToolUse", "tool_name": "Write", "tool_input": {"file_path": "src/svc.py"}, "cwd": str(self.repo)})
            self._hook({"session_id": sid, "hook_event_name": "PostToolUse", "tool_name": "Write", "tool_input": {"file_path": ".sdlc/review-findings.json"}, "cwd": str(self.repo)})
            self._hook(
                {
                    "session_id": sid,
                    "hook_event_name": "PostToolUse",
                    "tool_name": "Bash",
                    "tool_input": {"command": cmd},
                    "tool_response": {"exit_code": 0},
                    "cwd": str(self.repo),
                }
            )
            s_blk = self._hook({"session_id": sid, "hook_event_name": "Stop", "stop_hook_active": False, "cwd": str(self.repo)})
            self.assertEqual(s_blk.get("decision"), "block", f"Expected verified=False (Stop block) for: {cmd}")

        for idx, cmd in enumerate(("pytest -q", "python3 -m unittest")):
            sid = f"f1-pos-{idx}"
            self._hook({"session_id": sid, "hook_event_name": "PostToolUse", "tool_name": "Write", "tool_input": {"file_path": "src/svc.py"}, "cwd": str(self.repo)})
            self._hook({"session_id": sid, "hook_event_name": "PostToolUse", "tool_name": "Write", "tool_input": {"file_path": ".sdlc/review-findings.json"}, "cwd": str(self.repo)})
            self._hook(
                {
                    "session_id": sid,
                    "hook_event_name": "PostToolUse",
                    "tool_name": "Bash",
                    "tool_input": {"command": cmd},
                    "tool_response": {"exit_code": 0},
                    "cwd": str(self.repo),
                }
            )
            s_ok = self._hook({"session_id": sid, "hook_event_name": "Stop", "stop_hook_active": False, "cwd": str(self.repo)})
            self.assertEqual(s_ok, {}, f"Expected verified=True (Stop allow) for: {cmd}")

    def test_v25_finding2_quote_aware_write_detection_no_phantom_dirty(self) -> None:
        # Spec lock is ON (--require-spec in setUp) and S1/S2 not approved.
        safe_cmds = [
            'git log --format="%h -> %s"',
            'python -c "print(1>0)"',
        ]
        sid = "f2-quote"
        for cmd in safe_cmds:
            r_pre = self._hook(
                {
                    "session_id": sid,
                    "hook_event_name": "PreToolUse",
                    "tool_name": "Bash",
                    "tool_input": {"command": cmd},
                    "cwd": str(self.repo),
                }
            )
            self.assertEqual(r_pre["hookSpecificOutput"]["permissionDecision"], "allow", f"Expected allow for: {cmd}")
            self._hook(
                {
                    "session_id": sid,
                    "hook_event_name": "PostToolUse",
                    "tool_name": "Bash",
                    "tool_input": {"command": cmd},
                    "tool_response": {"exit_code": 0},
                    "cwd": str(self.repo),
                }
            )

        session_file = pathlib.Path(self.env["VERIGATE_DATA_DIR"]) / f"session_{sid}.json"
        if session_file.is_file():
            sess = json.loads(session_file.read_text(encoding="utf-8"))
            self.assertEqual(sess.get("dirtyFiles", []), [], f"Unexpected dirtyFiles: {sess.get('dirtyFiles')}")
        s_ok = self._hook({"session_id": sid, "hook_event_name": "Stop", "stop_hook_active": False, "cwd": str(self.repo)})
        self.assertEqual(s_ok, {})

    def test_v25_finding4_active_change_protection_and_branch_ticket(self) -> None:
        # Writing .sdlc/active-change via Write -> ask
        r_write = self._hook(
            {
                "session_id": "f4",
                "hook_event_name": "PreToolUse",
                "tool_name": "Write",
                "tool_input": {"file_path": ".sdlc/active-change"},
                "cwd": str(self.repo),
            }
        )
        self.assertEqual(r_write["hookSpecificOutput"]["permissionDecision"], "ask")

        # Writing .sdlc/active-change via shell -> deny
        r_sh = self._hook(
            {
                "session_id": "f4",
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "echo PROJ-999 > .sdlc/active-change"},
                "cwd": str(self.repo),
            }
        )
        self.assertEqual(r_sh["hookSpecificOutput"]["permissionDecision"], "deny")

        # Creating/checking out branch feature/PROJ-789-billing auto-derives change ID PROJ-789
        subprocess.run(["git", "-C", str(self.repo), "checkout", "-b", "feature/PROJ-789-billing"], check=True, capture_output=True)
        p_stat = subprocess.run(
            [sys.executable, str(self.aisdlc_bin), "status", "--project", str(self.repo)],
            check=True,
            capture_output=True,
            text=True,
            env=self.env,
        )
        stat = json.loads(p_stat.stdout)
        self.assertEqual(stat["change_id"], "PROJ-789")
        self.assertEqual(stat["artifact_dir"], ".sdlc/changes/PROJ-789")

    def test_v25_findings6_and_7_pr_scoped_ci_and_terraform_dirs(self) -> None:
        gh_yml = (self.repo / ".github/workflows/verigate-gate.yml").read_text(encoding="utf-8")
        az_yml = (self.repo / "azure-pipelines.yml").read_text(encoding="utf-8")

        for name, yml in (("github", gh_yml), ("azure", az_yml)):
            self.assertIn("VERIGATE_REF", yml, f"{name} CI must pin VERIGATE_REF")
            self.assertIn("VERIGATE_REPO", yml, f"{name} CI must define VERIGATE_REPO")
            self.assertIn("ci-check --project . --base", yml, f"{name} CI must invoke pinned ci-check")
            self.assertNotIn(".sdlc/bin/verigate.py", yml, f"{name} CI must never run untrusted PR-branch verigate.py")
            self.assertNotIn("terraform fmt -check -recursive", yml, f"{name} CI must not blindly run repo-wide terraform fmt")

        self.assertIn("fetch-depth: 0", gh_yml)
        self.assertIn("fetchDepth: 0", az_yml)

        # Default config.json from `init` includes v3.0 keys + backward-compatible terraform_dirs
        cfg = json.loads((self.repo / ".sdlc/config.json").read_text(encoding="utf-8"))
        self.assertIn("terraform_dirs", cfg)
        self.assertIsInstance(cfg["terraform_dirs"], list)
        self.assertEqual(cfg.get("version"), "3.0.0")
        self.assertIn("gated_paths", cfg)
        self.assertIn("fail_on_missing_tool", cfg)

    def test_v25_finding8_claude_project_dir_hook_path(self) -> None:
        claude_cfg = json.loads((self.repo / ".claude/settings.json").read_text(encoding="utf-8"))
        for event in ("UserPromptSubmit", "PreToolUse", "PostToolUse", "Stop"):
            entries = claude_cfg["hooks"][event]
            self.assertTrue(entries, f"Missing Claude hook entries for {event}")
            cmds = [h["command"] for e in entries for h in e.get("hooks", [])]
            self.assertTrue(
                any("$CLAUDE_PROJECT_DIR/.sdlc/bin/verigate.py" in c for c in cmds),
                f"Expected $CLAUDE_PROJECT_DIR/.sdlc/bin/verigate.py in {event} hooks: {cmds}",
            )

    def test_v25_finding9_string_and_dict_exit_code_detection(self) -> None:
        (self.repo / "src").mkdir(exist_ok=True)
        (self.repo / "src/app.py").write_text("x = 1\n", encoding="utf-8")

        # 1. String tool_response containing "Exit code 1" -> failed (verified stays False)
        sid_str = "f9-str"
        self._hook({"session_id": sid_str, "hook_event_name": "PostToolUse", "tool_name": "Write", "tool_input": {"file_path": "src/app.py"}, "cwd": str(self.repo)})
        self._hook({"session_id": sid_str, "hook_event_name": "PostToolUse", "tool_name": "Write", "tool_input": {"file_path": ".sdlc/review-findings.json"}, "cwd": str(self.repo)})
        self._hook(
            {
                "session_id": sid_str,
                "hook_event_name": "PostToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "pytest -q"},
                "tool_response": "FAILED tests/test_app.py\nExit code 1",
                "cwd": str(self.repo),
            }
        )
        s_blk_str = self._hook({"session_id": sid_str, "hook_event_name": "Stop", "stop_hook_active": False, "cwd": str(self.repo)})
        self.assertEqual(s_blk_str.get("decision"), "block")

        # 2. Dict tool_response with exit_code: 1 -> failed (verified stays False)
        sid_dict = "f9-dict"
        self._hook({"session_id": sid_dict, "hook_event_name": "PostToolUse", "tool_name": "Write", "tool_input": {"file_path": "src/app.py"}, "cwd": str(self.repo)})
        self._hook({"session_id": sid_dict, "hook_event_name": "PostToolUse", "tool_name": "Write", "tool_input": {"file_path": ".sdlc/review-findings.json"}, "cwd": str(self.repo)})
        self._hook(
            {
                "session_id": sid_dict,
                "hook_event_name": "PostToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "pytest -q"},
                "tool_response": {"exit_code": 1},
                "cwd": str(self.repo),
            }
        )
        s_blk_dict = self._hook({"session_id": sid_dict, "hook_event_name": "Stop", "stop_hook_active": False, "cwd": str(self.repo)})
        self.assertEqual(s_blk_dict.get("decision"), "block")

        # 3. Clean string tool_response (no non-zero exit code) -> verified=True -> Stop allows
        debug_env = self.env.copy()
        debug_env["VERIGATE_DEBUG_HOOK"] = "1"
        self._hook(
            {
                "session_id": sid_str,
                "hook_event_name": "PostToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "pytest -q"},
                "tool_response": "3 passed in 0.12s",
                "cwd": str(self.repo),
            },
            env_override=debug_env,
        )
        s_ok = self._hook({"session_id": sid_str, "hook_event_name": "Stop", "stop_hook_active": False, "cwd": str(self.repo)})
        self.assertEqual(s_ok, {})
        debug_log = pathlib.Path(self.env["VERIGATE_DATA_DIR"]) / "hook_debug.jsonl"
        self.assertTrue(debug_log.is_file(), "Expected hook_debug.jsonl when VERIGATE_DEBUG_HOOK=1")

    def test_v25_findings3_and_5_docs_limits_codeowners_consistency(self) -> None:
        readme = (KIT_ROOT / "README.md").read_text(encoding="utf-8")
        for limit_token in ("Path.write_text", "git apply", "New-Item", "curl -o"):
            self.assertIn(limit_token, readme, f"README.md missing known limit: {limit_token}")
        self.assertIn("CODEOWNERS", readme)
        self.assertIn(".sdlc/changes/**", readme)
        self.assertIn("consistency", readme.lower())

        # Also verify merge-check JSON note frames it as a consistency check
        (self.repo / ".sdlc/review-findings.json").write_text(
            json.dumps({"verdict": "APPROVE", "quality_score": 95, "findings": []}),
            encoding="utf-8",
        )
        p_mc = subprocess.run(
            [sys.executable, str(self.aisdlc_bin), "merge-check", "--project", str(self.repo)],
            check=True,
            capture_output=True,
            text=True,
            env=self.env,
        )
        mc_data = json.loads(p_mc.stdout)
        self.assertIn("consistency", mc_data.get("note", "").lower())

    def test_v26_live_trial_fixes(self) -> None:
        # 1. Chained trailing commands after test runner must NEVER mark verified (live Claude Code payload has no exit_code)
        (self.repo / "src").mkdir(exist_ok=True)
        (self.repo / "src/calc.py").write_text("def add(a, b): return a + b\n", encoding="utf-8")
        self._hook({"session_id": "live1", "hook_event_name": "PostToolUse", "tool_name": "Write", "tool_input": {"file_path": "src/calc.py"}, "cwd": str(self.repo)})
        self._hook({"session_id": "live1", "hook_event_name": "PostToolUse", "tool_name": "Write", "tool_input": {"file_path": ".sdlc/review-findings.json"}, "cwd": str(self.repo)})

        real_claude_resp = {"stdout": "Ran 3 tests\nFAILED (failures=2)\ndone\n", "stderr": "", "interrupted": False, "isImage": False, "noOutputExpected": False}
        for bad_cmd in (
            "python -m unittest discover -s tests; echo done",
            'pytest; echo "exit=$?"',
            "pytest && echo done",
            "pytest | tail -n 5",
        ):
            self._hook(
                {"session_id": "live1", "hook_event_name": "PostToolUse", "tool_name": "Bash", "tool_input": {"command": bad_cmd}, "tool_response": real_claude_resp, "cwd": str(self.repo)}
            )
            sess_file = pathlib.Path(self.env["VERIGATE_DATA_DIR"]) / "session_live1.json"
            self.assertFalse(json.loads(sess_file.read_text(encoding="utf-8")).get("verified"), f"Should NOT verify on: {bad_cmd}")

        # Even a standalone test command with FAILED output in stdout/stderr must NOT mark verified
        self._hook(
            {"session_id": "live1", "hook_event_name": "PostToolUse", "tool_name": "Bash", "tool_input": {"command": "python -m unittest discover -s tests"}, "tool_response": real_claude_resp, "cwd": str(self.repo)}
        )
        sess_file = pathlib.Path(self.env["VERIGATE_DATA_DIR"]) / "session_live1.json"
        self.assertFalse(json.loads(sess_file.read_text(encoding="utf-8")).get("verified"))

        # Stop block message clearly says Not a crash
        s_blk = self._hook({"session_id": "live1", "hook_event_name": "Stop", "stop_hook_active": False, "cwd": str(self.repo)})
        self.assertEqual(s_blk["decision"], "block")
        self.assertIn("Not a crash", s_blk["reason"])

        # Clean standalone test run with clean stdout marks verified
        clean_resp = {"stdout": "Ran 3 tests\nOK\n", "stderr": "", "interrupted": False, "isImage": False, "noOutputExpected": False}
        self._hook(
            {"session_id": "live1", "hook_event_name": "PostToolUse", "tool_name": "Bash", "tool_input": {"command": "cd . && python -m unittest discover -s tests"}, "tool_response": clean_resp, "cwd": str(self.repo)}
        )
        self.assertTrue(json.loads(sess_file.read_text(encoding="utf-8")).get("verified"))

        # 2. issue_bridge.py detect/preview -> allow; create -> ask/force_ask; chained -> deny
        r_det = self._hook({"session_id": "live2", "hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "python .sdlc/bin/issue_bridge.py detect --repo ."}, "cwd": str(self.repo)})
        self.assertEqual(r_det["hookSpecificOutput"]["permissionDecision"], "allow")
        r_cr = self._hook({"session_id": "live2", "hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "python .sdlc/bin/issue_bridge.py create --findings .sdlc/review-findings.json"}, "cwd": str(self.repo)})
        self.assertEqual(r_cr["hookSpecificOutput"]["permissionDecision"], "ask")
        r_cr_chain = self._hook({"session_id": "live2", "hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "python .sdlc/bin/issue_bridge.py create --findings .sdlc/review-findings.json; true"}, "cwd": str(self.repo)})
        self.assertEqual(r_cr_chain["hookSpecificOutput"]["permissionDecision"], "deny")

        # 3. Read-only inspection on .sdlc/bin allowed; destructive commands & shadow_ledger remain denied
        r_ls = self._hook({"session_id": "live2", "hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "ls .sdlc/bin"}, "cwd": str(self.repo)})
        self.assertEqual(r_ls["hookSpecificOutput"]["permissionDecision"], "allow")
        r_cat = self._hook({"session_id": "live2", "hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "cat .sdlc/intent.md .sdlc/spec.md"}, "cwd": str(self.repo)})
        self.assertEqual(r_cat["hookSpecificOutput"]["permissionDecision"], "allow")
        r_rm = self._hook({"session_id": "live2", "hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "rm .sdlc/bin/verigate.py"}, "cwd": str(self.repo)})
        self.assertEqual(r_rm["hookSpecificOutput"]["permissionDecision"], "deny")

    def _init_v3_repo(self, name: str, config: dict) -> tuple[pathlib.Path, pathlib.Path]:
        repo = self.tmp_dir / name
        repo.mkdir()
        subprocess.run(["git", "init", "-b", "main", str(repo)], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(repo), "config", "user.email", "ci@example.com"], check=True)
        subprocess.run(["git", "-C", str(repo), "config", "user.name", "CI"], check=True)
        subprocess.run(
            [
                sys.executable,
                str(KIT_ROOT / "install_verigate.py"),
                "--target",
                str(repo),
                "--targets",
                "git,ci",
                "--activate-git-hooks",
            ],
            check=True,
            capture_output=True,
            env=self.env,
        )
        (repo / "verigate.json").write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
        (repo / "README.md").write_text("# Sample Repo\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
        subprocess.run(
            ["git", "-C", str(repo), "commit", "--no-verify", "-m", "chore: bootstrap repo"],
            check=True,
            capture_output=True,
            env=self.env,
        )
        return repo, repo / ".sdlc" / "bin" / "verigate.py"

    def test_v30_declarative_config_gated_paths(self) -> None:
        cfg = {
            "version": "3.0.0",
            "require_spec_approval": True,
            "require_change_folder_for_gated_paths": True,
            "fail_on_missing_tool": True,
            "gated_paths": [
                {
                    "pattern": "services/**",
                    "verify": [f"{sys.executable} -c 'print(\"ok\")'"],
                    "cwd": ".",
                }
            ],
        }
        repo, vbin = self._init_v3_repo("v3-gated", cfg)

        # Non-gated path (docs/notes.md) is allowed without a change folder in git-pre-commit
        (repo / "docs").mkdir()
        (repo / "docs/notes.md").write_text("# Notes\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(repo), "add", "docs/notes.md"], check=True)
        p_doc = subprocess.run(
            [sys.executable, str(vbin), "hook", "--adapter", "git-pre-commit"],
            cwd=str(repo),
            capture_output=True,
            text=True,
            env=self.env,
        )
        self.assertEqual(p_doc.returncode, 0, p_doc.stderr)

        # Also allowed in PreToolUse AI hook without a change folder
        r_doc_hook = subprocess.run(
            [sys.executable, str(vbin), "hook", "--adapter", "auto"],
            input=json.dumps(
                {
                    "session_id": "v3-gp",
                    "hook_event_name": "PreToolUse",
                    "tool_name": "Write",
                    "tool_input": {"file_path": "docs/notes.md"},
                    "cwd": str(repo),
                }
            ),
            text=True,
            capture_output=True,
            cwd=str(repo),
            env=self.env,
        )
        self.assertEqual(r_doc_hook.returncode, 0)
        self.assertEqual(json.loads(r_doc_hook.stdout)["hookSpecificOutput"]["permissionDecision"], "allow")

        # Gated path (services/api.py) without change folder is DENIED in git-pre-commit and PreToolUse
        (repo / "services").mkdir()
        (repo / "services/api.py").write_text("def handle(): return 200\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(repo), "add", "services/api.py"], check=True)
        p_svc = subprocess.run(
            [sys.executable, str(vbin), "hook", "--adapter", "git-pre-commit"],
            cwd=str(repo),
            capture_output=True,
            text=True,
            env=self.env,
        )
        self.assertNotEqual(p_svc.returncode, 0)
        self.assertIn("Change Folder Gate", p_svc.stderr)

        r_svc_hook = subprocess.run(
            [sys.executable, str(vbin), "hook", "--adapter", "auto"],
            input=json.dumps(
                {
                    "session_id": "v3-gp",
                    "hook_event_name": "PreToolUse",
                    "tool_name": "Write",
                    "tool_input": {"file_path": "services/api.py"},
                    "cwd": str(repo),
                }
            ),
            text=True,
            capture_output=True,
            cwd=str(repo),
            env=self.env,
        )
        self.assertEqual(r_svc_hook.returncode, 0)
        self.assertEqual(json.loads(r_svc_hook.stdout)["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_v30_real_verify_commit_bound_and_missing_tool_fail_closed(self) -> None:
        # 1. Passing verify command writes commit-bound verify-result.json
        cfg_pass = {
            "version": "3.0.0",
            "fail_on_missing_tool": True,
            "gated_paths": [
                {
                    "pattern": "services/**",
                    "verify": [f"{sys.executable} -c 'import sys; sys.exit(0)'"],
                    "cwd": ".",
                }
            ],
        }
        repo, vbin = self._init_v3_repo("v3-verify", cfg_pass)
        (repo / "services").mkdir()
        (repo / "services/api.py").write_text("VALUE = 1\n", encoding="utf-8")

        head_sha = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()

        p_ok = subprocess.run(
            [sys.executable, str(vbin), "verify", "--project", str(repo), "--change", "PROJ-101"],
            capture_output=True,
            text=True,
            env=self.env,
        )
        self.assertEqual(p_ok.returncode, 0, p_ok.stdout + p_ok.stderr)
        vres_path = repo / ".sdlc/changes/PROJ-101/verify-result.json"
        self.assertTrue(vres_path.is_file())
        vres = json.loads(vres_path.read_text(encoding="utf-8"))
        self.assertTrue(vres["passed"])
        self.assertEqual(vres["head_commit"], head_sha)
        self.assertTrue(vres["tree_digest"])
        self.assertEqual(len(vres["tree_digest"]), 64)
        self.assertEqual(vres["results"][0]["exit_code"], 0)

        # 2. Failing verify command writes passed: false and exits non-zero
        cfg_fail = dict(cfg_pass)
        cfg_fail["gated_paths"] = [
            {
                "pattern": "services/**",
                "verify": [f"{sys.executable} -c 'import sys; sys.exit(2)'"],
                "cwd": ".",
            }
        ]
        (repo / "verigate.json").write_text(json.dumps(cfg_fail, indent=2) + "\n", encoding="utf-8")
        p_fail = subprocess.run(
            [sys.executable, str(vbin), "verify", "--project", str(repo), "--change", "PROJ-101"],
            capture_output=True,
            text=True,
            env=self.env,
        )
        self.assertNotEqual(p_fail.returncode, 0)
        vres_fail = json.loads(vres_path.read_text(encoding="utf-8"))
        self.assertFalse(vres_fail["passed"])
        self.assertEqual(vres_fail["results"][0]["exit_code"], 2)

        # 3. Missing binary FAILS when fail_on_missing_tool: true
        cfg_miss_fail = {
            "version": "3.0.0",
            "fail_on_missing_tool": True,
            "gated_paths": [
                {
                    "pattern": "services/**",
                    "verify": ["nonexistent_tool_xyz --check"],
                    "cwd": ".",
                }
            ],
        }
        (repo / "verigate.json").write_text(json.dumps(cfg_miss_fail, indent=2) + "\n", encoding="utf-8")
        p_mf = subprocess.run(
            [sys.executable, str(vbin), "verify", "--project", str(repo), "--change", "PROJ-101"],
            capture_output=True,
            text=True,
            env=self.env,
        )
        self.assertNotEqual(p_mf.returncode, 0)
        vres_mf = json.loads(vres_path.read_text(encoding="utf-8"))
        self.assertFalse(vres_mf["passed"])
        self.assertTrue(vres_mf["results"][0]["missing_tool"])

        # 4. Missing binary PASSES / SKIPS when fail_on_missing_tool: false
        cfg_miss_skip = dict(cfg_miss_fail, fail_on_missing_tool=False)
        (repo / "verigate.json").write_text(json.dumps(cfg_miss_skip, indent=2) + "\n", encoding="utf-8")
        p_ms = subprocess.run(
            [sys.executable, str(vbin), "verify", "--project", str(repo), "--change", "PROJ-101"],
            capture_output=True,
            text=True,
            env=self.env,
        )
        self.assertEqual(p_ms.returncode, 0, p_ms.stdout + p_ms.stderr)
        vres_ms = json.loads(vres_path.read_text(encoding="utf-8"))
        self.assertTrue(vres_ms["passed"])
        self.assertTrue(vres_ms["results"][0]["missing_tool"])
        self.assertTrue(vres_ms["results"][0]["skipped_missing_tool"])

    def test_v30_required_change_folder_and_git_pre_commit_pre_push(self) -> None:
        cfg = {
            "version": "3.0.0",
            "require_spec_approval": True,
            "require_change_folder_for_gated_paths": True,
            "fail_on_missing_tool": True,
            "gated_paths": [
                {
                    "pattern": "services/**",
                    "verify": [f"{sys.executable} -c 'import sys; sys.exit(0)'"],
                    "cwd": ".",
                }
            ],
        }
        repo, vbin = self._init_v3_repo("v3-hooks", cfg)
        subprocess.run(["git", "-C", str(repo), "checkout", "-b", "feature/PROJ-202-api"], check=True, capture_output=True)

        # Touching services/api.py without .sdlc/changes/PROJ-202/ fails git-pre-commit
        (repo / "services").mkdir()
        (repo / "services/api.py").write_text("def v1(): return 1\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(repo), "add", "services/api.py"], check=True)
        p_pc_fail = subprocess.run(
            [sys.executable, str(vbin), "hook", "--adapter", "git-pre-commit"],
            cwd=str(repo),
            capture_output=True,
            text=True,
            env=self.env,
        )
        self.assertNotEqual(p_pc_fail.returncode, 0)

        # Create approved change folder .sdlc/changes/PROJ-202/ -> git-pre-commit PASSES
        cdir = repo / ".sdlc/changes/PROJ-202"
        cdir.mkdir(parents=True, exist_ok=True)
        (cdir / "intent.md").write_text(VALID_INTENT_MD, encoding="utf-8")
        (cdir / "spec.md").write_text(VALID_SPEC_MD, encoding="utf-8")
        subprocess.run(
            [sys.executable, str(vbin), "approve", "--project", str(repo), "--change", "PROJ-202", "--stage", "S1_S2"],
            check=True,
            capture_output=True,
            env=self.env,
        )
        subprocess.run(["git", "-C", str(repo), "add", ".sdlc/changes/PROJ-202", "services/api.py"], check=True)
        p_pc_ok = subprocess.run(
            [sys.executable, str(vbin), "hook", "--adapter", "git-pre-commit"],
            cwd=str(repo),
            capture_output=True,
            text=True,
            env=self.env,
        )
        self.assertEqual(p_pc_ok.returncode, 0, p_pc_ok.stderr)
        subprocess.run(
            ["git", "-C", str(repo), "commit", "-m", "feat: add services api"],
            check=True,
            capture_output=True,
            env=self.env,
        )

        # git-pre-push BLOCKS when verify-result.json is missing
        p_pp_missing = subprocess.run(
            [sys.executable, str(vbin), "hook", "--adapter", "git-pre-push"],
            cwd=str(repo),
            capture_output=True,
            text=True,
            env=self.env,
        )
        self.assertNotEqual(p_pp_missing.returncode, 0)
        self.assertIn("Missing", p_pp_missing.stderr)

        # Run verigate verify on current HEAD -> git-pre-push PASSES
        subprocess.run(
            [sys.executable, str(vbin), "verify", "--project", str(repo), "--change", "PROJ-202"],
            check=True,
            capture_output=True,
            env=self.env,
        )
        p_pp_ok = subprocess.run(
            [sys.executable, str(vbin), "hook", "--adapter", "git-pre-push"],
            cwd=str(repo),
            capture_output=True,
            text=True,
            env=self.env,
        )
        self.assertEqual(p_pp_ok.returncode, 0, p_pp_ok.stderr)

        # Modifying a gated file invalidates tree_digest -> git-pre-push BLOCKS
        (repo / "services/api.py").write_text("def v1(): return 2\n", encoding="utf-8")
        p_pp_digest = subprocess.run(
            [sys.executable, str(vbin), "hook", "--adapter", "git-pre-push"],
            cwd=str(repo),
            capture_output=True,
            text=True,
            env=self.env,
        )
        self.assertNotEqual(p_pp_digest.returncode, 0)
        self.assertIn("digest mismatch", p_pp_digest.stderr)

        # Committing the change invalidates head_commit -> git-pre-push BLOCKS until re-verified
        subprocess.run(["git", "-C", str(repo), "add", "services/api.py"], check=True)
        subprocess.run(
            ["git", "-C", str(repo), "commit", "-m", "feat: update api return value"],
            check=True,
            capture_output=True,
            env=self.env,
        )
        p_pp_stale = subprocess.run(
            [sys.executable, str(vbin), "hook", "--adapter", "git-pre-push"],
            cwd=str(repo),
            capture_output=True,
            text=True,
            env=self.env,
        )
        self.assertNotEqual(p_pp_stale.returncode, 0)
        self.assertIn("Stale", p_pp_stale.stderr)

        # Re-running verify on new HEAD -> git-pre-push PASSES again
        subprocess.run(
            [sys.executable, str(vbin), "verify", "--project", str(repo), "--change", "PROJ-202"],
            check=True,
            capture_output=True,
            env=self.env,
        )
        p_pp_ok2 = subprocess.run(
            [sys.executable, str(vbin), "hook", "--adapter", "git-pre-push"],
            cwd=str(repo),
            capture_output=True,
            text=True,
            env=self.env,
        )
        self.assertEqual(p_pp_ok2.returncode, 0, p_pp_ok2.stderr)

    def test_v30_ci_check_recomputes_from_scratch_ignores_forged_verify_result(self) -> None:
        cfg = {
            "version": "3.0.0",
            "require_spec_approval": True,
            "require_change_folder_for_gated_paths": True,
            "fail_on_missing_tool": True,
            "gated_paths": [
                {
                    "pattern": "services/**",
                    "verify": [f"{sys.executable} -m unittest discover -s tests"],
                    "cwd": ".",
                }
            ],
        }
        repo, vbin = self._init_v3_repo("v3-cicheck", cfg)

        # Branch off main for a PR
        subprocess.run(["git", "-C", str(repo), "checkout", "-b", "feature/PROJ-303-ci"], check=True, capture_output=True)
        (repo / "services").mkdir()
        (repo / "tests").mkdir()
        (repo / "services/api.py").write_text("def compute():\n    return 0\n", encoding="utf-8")
        (repo / "tests/test_api.py").write_text(
            "import unittest\n"
            "from services.api import compute\n"
            "class T(unittest.TestCase):\n"
            "    def test_compute(self):\n"
            "        self.assertEqual(compute(), 42)\n",
            encoding="utf-8",
        )

        cdir = repo / ".sdlc/changes/PROJ-303"
        cdir.mkdir(parents=True, exist_ok=True)
        (cdir / "intent.md").write_text(VALID_INTENT_MD, encoding="utf-8")
        (cdir / "spec.md").write_text(VALID_SPEC_MD, encoding="utf-8")
        subprocess.run(
            [sys.executable, str(vbin), "approve", "--project", str(repo), "--change", "PROJ-303", "--stage", "S1_S2"],
            check=True,
            capture_output=True,
            env=self.env,
        )

        # Forge a laptop verify-result.json claiming passed: true!
        (cdir / "verify-result.json").write_text(
            json.dumps({"passed": True, "head_commit": "forged", "tree_digest": "forged", "results": []}, indent=2),
            encoding="utf-8",
        )
        subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
        subprocess.run(
            ["git", "-C", str(repo), "commit", "--no-verify", "-m", "feat: failing code with forged verify-result"],
            check=True,
            capture_output=True,
            env=self.env,
        )

        # ci-check MUST ignore forged verify-result.json, recompute tests, and FAIL!
        p_ci_fail = subprocess.run(
            [sys.executable, str(vbin), "ci-check", "--project", str(repo), "--base", "main"],
            capture_output=True,
            text=True,
            env=self.env,
        )
        self.assertNotEqual(p_ci_fail.returncode, 0)
        d_fail = json.loads(p_ci_fail.stdout)
        self.assertEqual(d_fail["status"], "FAILED")
        self.assertFalse(d_fail["trusted_laptop_verify_result"])
        self.assertTrue(d_fail["checks"]["verify"]["recomputed"])
        self.assertFalse(d_fail["checks"]["verify"]["passed"])

        # Fix the actual code so the test passes, but omit review-findings.json -> ci-check STILL FAILS (require_review_in_ci=true)!
        (repo / "services/api.py").write_text("def compute():\n    return 42\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(repo), "add", "services/api.py"], check=True)
        subprocess.run(
            ["git", "-C", str(repo), "commit", "-m", "fix: return 42"],
            check=True,
            capture_output=True,
            env=self.env,
        )
        p_ci_no_rev = subprocess.run(
            [sys.executable, str(vbin), "ci-check", "--project", str(repo), "--base", "main"],
            capture_output=True,
            text=True,
            env=self.env,
        )
        self.assertNotEqual(p_ci_no_rev.returncode, 0)
        d_no_rev = json.loads(p_ci_no_rev.stdout)
        self.assertTrue(d_no_rev["checks"]["verify"]["passed"])
        self.assertFalse(d_no_rev["checks"]["merge_policy"]["passed"])

        # Add passing review-findings.json -> ci-check PASSES!
        (cdir / "review-findings.json").write_text(
            json.dumps({"verdict": "APPROVE", "quality_score": 96, "findings": []}, indent=2),
            encoding="utf-8",
        )
        subprocess.run(["git", "-C", str(repo), "add", str(cdir / "review-findings.json")], check=True)
        subprocess.run(
            ["git", "-C", str(repo), "commit", "-m", "chore: add review-findings.json"],
            check=True,
            capture_output=True,
            env=self.env,
        )
        p_ci_ok = subprocess.run(
            [sys.executable, str(vbin), "ci-check", "--project", str(repo), "--base", "main"],
            capture_output=True,
            text=True,
            env=self.env,
        )
        self.assertEqual(p_ci_ok.returncode, 0, p_ci_ok.stdout + p_ci_ok.stderr)
        d_ok = json.loads(p_ci_ok.stdout)
        self.assertEqual(d_ok["status"], "PASSED")
        self.assertFalse(d_ok["trusted_laptop_verify_result"])
        self.assertTrue(d_ok["checks"]["verify"]["recomputed"])
        self.assertTrue(d_ok["checks"]["verify"]["passed"])
        self.assertTrue(d_ok["checks"]["change_folder"]["passed"])
        self.assertTrue(d_ok["checks"]["merge_policy"]["passed"])

    def test_v30_pinned_release_ci_templates_and_pre_push_install(self) -> None:
        pin_repo = self.tmp_dir / "v3-pinned-install"
        pin_repo.mkdir()
        p_inst = subprocess.run(
            [
                sys.executable,
                str(KIT_ROOT / "install_verigate.py"),
                "--target",
                str(pin_repo),
                "--targets",
                "git,ci",
                "--verigate-ref",
                "v3.0.1-rc1",
                "--verigate-repo",
                "https://example.com/org/verigate-sdlc.git",
            ],
            check=True,
            capture_output=True,
            text=True,
            env=self.env,
        )
        inst_out = json.loads(p_inst.stdout)
        self.assertEqual(inst_out["verigate_ref"], "v3.0.1-rc1")
        self.assertEqual(inst_out["verigate_repo"], "https://example.com/org/verigate-sdlc.git")

        # Both .githooks/pre-commit and .githooks/pre-push installed and executable
        pre_commit = pin_repo / ".githooks/pre-commit"
        pre_push = pin_repo / ".githooks/pre-push"
        self.assertTrue(pre_commit.is_file())
        self.assertTrue(pre_push.is_file())
        self.assertIn("git-pre-commit", pre_commit.read_text(encoding="utf-8"))
        self.assertIn("git-pre-push", pre_push.read_text(encoding="utf-8"))
        if os.name != "nt":
            self.assertTrue(os.access(pre_push, os.X_OK))

        # Both CI templates check out pinned VERIGATE_REF and invoke ci-check (never PR-branch .sdlc/bin/verigate.py)
        gh_yml = (pin_repo / ".github/workflows/verigate-gate.yml").read_text(encoding="utf-8")
        az_yml = (pin_repo / "azure-pipelines.yml").read_text(encoding="utf-8")
        for name, yml in (("github", gh_yml), ("azure", az_yml)):
            self.assertIn("VERIGATE_REF", yml, f"{name} missing VERIGATE_REF")
            self.assertIn("v3.0.1-rc1", yml, f"{name} missing custom pinned ref")
            self.assertIn("https://example.com/org/verigate-sdlc.git", yml, f"{name} missing custom repo")
            self.assertIn("ci-check --project . --base", yml, f"{name} must invoke ci-check")
            self.assertNotIn(".sdlc/bin/verigate.py", yml, f"{name} must NOT run PR-branch .sdlc/bin/verigate.py")

    def test_v30_readme_tool_agnostic_positioning(self) -> None:
        readme = (KIT_ROOT / "README.md").read_text(encoding="utf-8")
        lower = readme.lower()

        # Leads with tool-agnostic Git commit/push + PR pipeline gating BEFORE optional AI hooks
        idx_lead = lower.find("gates at git commit/push and the pr pipeline")
        idx_hooks = lower.find("## optional early-feedback adapters")
        self.assertNotEqual(idx_lead, -1, "README must lead with Git commit/push + PR pipeline gating")
        self.assertNotEqual(idx_hooks, -1, "README must frame AI hooks as Optional Early-Feedback Adapters")
        self.assertLess(idx_lead, idx_hooks, "Tool-agnostic Git/PR positioning must come before AI hooks section")

        # Covers all v3.0 core pillars
        for token in (
            "verigate verify",
            "verigate ci-check",
            "VERIGATE_REF",
            "gated_paths",
            "fail_on_missing_tool",
            "verify-result.json",
            "head_commit",
            "tree_digest",
            "CODEOWNERS",
            ".sdlc/changes/**",
            "[VeriGate Guide Rail — Not a crash]",
        ):
            self.assertIn(token, readme, f"README.md missing v3.0 pillar token: {token}")

    def test_v31_windows_split_base_config_review_gitignore_and_merge_base(self) -> None:
        vmod = _load_module("verigate_v31", KIT_ROOT / "bin/verigate.py")

        # 1. Windows backslash paths preserved in string form + list form supported
        argv1, _ = vmod._split_verify_command(r"C:\Python314\python.exe -m unittest discover -s tests")
        self.assertEqual(argv1[0], r"C:\Python314\python.exe")
        argv2, _ = vmod._split_verify_command(r'"C:\Program Files\Python314\python.exe" -m unittest')
        self.assertEqual(argv2[0], r"C:\Program Files\Python314\python.exe")
        argv3, _ = vmod._split_verify_command([sys.executable, "-c", "import sys; sys.exit(0)"])
        self.assertEqual(argv3[0], sys.executable)

        # 2. pytest --help / --version / --collect-only rejected as real test runs
        for help_cmd in ("pytest --help", "pytest -h", "pytest --version", "pytest -V", "pytest --collect-only", "terraform validate -h"):
            self.assertFalse(vmod.is_real_test_runner_command(help_cmd), f"Should reject: {help_cmd}")

        # 3. ci-check loads config from target branch (`main`), NOT untrusted PR branch!
        repo = self.tmp_dir / "v31-base-config"
        repo.mkdir()
        subprocess.run(["git", "init", "-b", "main", str(repo)], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(repo), "config", "user.email", "ci@example.com"], check=True)
        subprocess.run(["git", "-C", str(repo), "config", "user.name", "CI"], check=True)
        subprocess.run(
            [sys.executable, str(KIT_ROOT / "install_verigate.py"), "--target", str(repo), "--targets", "git,ci", "--activate-git-hooks"],
            check=True,
            capture_output=True,
            env=self.env,
        )
        vbin = repo / ".sdlc/bin/verigate.py"

        # Verify .gitignore ignores verify-result.json and Azure Pipelines uses pr: none + Build Validation (no CODEOWNERS)
        gi = (repo / ".gitignore").read_text(encoding="utf-8")
        self.assertIn(".sdlc/verify-result.json", gi)
        self.assertIn(".sdlc/changes/*/verify-result.json", gi)
        az_yml = (repo / "azure-pipelines.yml").read_text(encoding="utf-8")
        self.assertIn("pr: none", az_yml)
        self.assertIn("Build Validation", az_yml)
        self.assertIn("Automatically included reviewers", az_yml)

        # Commit strict verigate.json on `main` using list-form verify command
        (repo / "verigate.json").write_text(
            json.dumps(
                {
                    "version": "3.1.0",
                    "require_change_folder_for_gated_paths": True,
                    "fail_on_missing_tool": True,
                    "gated_paths": [{"pattern": "services/**", "verify": [[sys.executable, "-c", "import sys; sys.exit(1)"]]}],
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
        subprocess.run(["git", "-C", str(repo), "commit", "--no-verify", "-m", "chore: strict main config"], check=True, capture_output=True, env=self.env)

        # PR branch tries to weaken verigate.json to gated_paths: [] AND commits across 2 commits (no upstream)
        subprocess.run(["git", "-C", str(repo), "checkout", "-b", "feature/PROJ-901-tamper"], check=True, capture_output=True)
        (repo / "verigate.json").write_text(json.dumps({"gated_paths": []}, indent=2), encoding="utf-8")
        (repo / "services").mkdir()
        (repo / "services/svc.py").write_text("x = 1\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
        subprocess.run(["git", "-C", str(repo), "commit", "--no-verify", "-m", "commit 1: gated file + weakened config"], check=True, capture_output=True, env=self.env)

        # Commit 2 only touches non-gated docs/note.md -> _git_pre_push_files must STILL see services/svc.py via merge-base!
        (repo / "docs").mkdir()
        (repo / "docs/note.md").write_text("# note\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(repo), "add", "docs/note.md"], check=True)
        subprocess.run(["git", "-C", str(repo), "commit", "--no-verify", "-m", "commit 2: docs only"], check=True, capture_output=True, env=self.env)

        pre_push_files = vmod._git_pre_push_files(str(repo))
        self.assertIn("services/svc.py", pre_push_files)
        self.assertIn("docs/note.md", pre_push_files)

        # ci-check --base main MUST load verigate.json from `main` and FAIL (PR cannot disable its own gate!)
        p_ci = subprocess.run([sys.executable, str(vbin), "ci-check", "--project", str(repo), "--base", "main"], capture_output=True, text=True, env=self.env)
        self.assertNotEqual(p_ci.returncode, 0)
        d_ci = json.loads(p_ci.stdout)
        self.assertEqual(d_ci["config_source"], "base_ref:main")
        self.assertIn("services/svc.py", d_ci["gated_paths_touched"])
        self.assertFalse(d_ci["passed"])

    def test_v311_fail_closed_base_ref_broken_base_config_and_empty_verify(self) -> None:
        # 1. Unresolvable --base ref MUST fail closed (never fall back to PR branch)
        repo = self.tmp_dir / "vg_v311_base"
        repo.mkdir()
        subprocess.run(["git", "-C", str(repo), "init", "-b", "main"], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(repo), "config", "user.email", "test@example.com"], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(repo), "config", "user.name", "Test User"], check=True, capture_output=True)
        subprocess.run(
            [sys.executable, str(KIT_ROOT / "install_verigate.py"), "--target", str(repo), "--targets", "git,ci,azdo-ci"],
            check=True,
            capture_output=True,
            env=self.env,
        )
        vbin = repo / ".sdlc" / "bin" / "verigate.py"

        # Generated CI workflows must NOT swallow `git fetch` failures with `|| true`
        gh_yml = (repo / ".github" / "workflows" / "verigate-gate.yml").read_text(encoding="utf-8")
        az_yml = (repo / "azure-pipelines.yml").read_text(encoding="utf-8")
        self.assertNotIn("git fetch --no-tags origin \"$BASE\" 2>/dev/null || true", gh_yml)
        self.assertNotIn("git fetch --no-tags origin \"$BASE\" 2>/dev/null || true", az_yml)
        self.assertIn('git fetch --no-tags origin "$BASE"', gh_yml)
        self.assertIn('git fetch --no-tags origin "$BASE"', az_yml)

        (repo / "verigate.json").write_text(
            json.dumps(
                {
                    "version": "3.1.1",
                    "require_change_folder_for_gated_paths": True,
                    "gated_paths": [{"pattern": "services/**", "verify": [[sys.executable, "-c", "import sys; sys.exit(0)"]]}],
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(repo), "commit", "--no-verify", "-m", "chore: base main"], check=True, capture_output=True, env=self.env)

        # PR branch empties gated_paths, then runs ci-check with a nonexistent base ref -> MUST FAIL CLOSED
        subprocess.run(["git", "-C", str(repo), "checkout", "-b", "feature/PROJ-911-missing-base"], check=True, capture_output=True)
        (repo / "verigate.json").write_text(json.dumps({"gated_paths": []}, indent=2), encoding="utf-8")
        (repo / "services").mkdir()
        (repo / "services/app.py").write_text("x = 1\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(repo), "commit", "--no-verify", "-m", "feat: tamper"], check=True, capture_output=True, env=self.env)

        p_missing = subprocess.run(
            [sys.executable, str(vbin), "ci-check", "--project", str(repo), "--base", "origin/does-not-exist"],
            capture_output=True,
            text=True,
            env=self.env,
        )
        self.assertNotEqual(p_missing.returncode, 0)
        d_missing = json.loads(p_missing.stdout)
        self.assertFalse(d_missing["passed"])
        self.assertEqual(d_missing["config_source"], "unresolvable_base_ref:origin/does-not-exist")
        self.assertTrue(any("BASE_REF_CONFIG_ERROR" in r for r in d_missing["blocking_reasons"]))

        # 2. Malformed verigate.json on target base branch MUST fail closed (never fall back to PR branch)
        subprocess.run(["git", "-C", str(repo), "checkout", "main"], check=True, capture_output=True)
        (repo / "verigate.json").write_text("{ broken json", encoding="utf-8")
        subprocess.run(["git", "-C", str(repo), "add", "verigate.json"], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(repo), "commit", "--no-verify", "-m", "chore: broken base config"], check=True, capture_output=True, env=self.env)
        subprocess.run(["git", "-C", str(repo), "checkout", "feature/PROJ-911-missing-base"], check=True, capture_output=True)

        p_broken = subprocess.run(
            [sys.executable, str(vbin), "ci-check", "--project", str(repo), "--base", "main"],
            capture_output=True,
            text=True,
            env=self.env,
        )
        self.assertNotEqual(p_broken.returncode, 0)
        d_broken = json.loads(p_broken.stdout)
        self.assertFalse(d_broken["passed"])
        self.assertEqual(d_broken["config_source"], "invalid_base_config:main")
        self.assertTrue(any("Malformed JSON" in r for r in d_broken["blocking_reasons"]))

        # 3. First-adoption PR: base branch resolves and has NO config -> working_tree_fallback allowed
        repo_adopt = self.tmp_dir / "vg_v311_adopt"
        repo_adopt.mkdir()
        subprocess.run(["git", "-C", str(repo_adopt), "init", "-b", "main"], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(repo_adopt), "config", "user.email", "test@example.com"], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(repo_adopt), "config", "user.name", "Test User"], check=True, capture_output=True)
        (repo_adopt / "README.md").write_text("hello\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(repo_adopt), "add", "-A"], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(repo_adopt), "commit", "--no-verify", "-m", "init"], check=True, capture_output=True, env=self.env)
        subprocess.run(["git", "-C", str(repo_adopt), "checkout", "-b", "feature/PROJ-912-adopt"], check=True, capture_output=True)
        subprocess.run(
            [sys.executable, str(KIT_ROOT / "install_verigate.py"), "--target", str(repo_adopt), "--targets", "git"],
            check=True,
            capture_output=True,
            env=self.env,
        )
        vbin_adopt = repo_adopt / ".sdlc" / "bin" / "verigate.py"
        (repo_adopt / "verigate.json").write_text(
            json.dumps({"gated_paths": [{"pattern": "services/**", "verify": [[sys.executable, "-c", "import sys; sys.exit(0)"]]}]}, indent=2),
            encoding="utf-8",
        )
        (repo_adopt / "docs").mkdir()
        (repo_adopt / "docs/info.md").write_text("docs only\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(repo_adopt), "add", "-A"], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(repo_adopt), "commit", "--no-verify", "-m", "chore: adopt verigate"], check=True, capture_output=True, env=self.env)

        p_adopt = subprocess.run(
            [sys.executable, str(vbin_adopt), "ci-check", "--project", str(repo_adopt), "--base", "main"],
            capture_output=True,
            text=True,
            env=self.env,
        )
        self.assertEqual(p_adopt.returncode, 0, p_adopt.stdout + p_adopt.stderr)
        d_adopt = json.loads(p_adopt.stdout)
        self.assertEqual(d_adopt["config_source"], "working_tree_fallback")
        self.assertTrue(d_adopt["passed"])

        # 4. Empty `verify: []` on a gated path MUST fail closed unless `allow_empty_verify: true`
        (repo_adopt / "verigate.json").write_text(
            json.dumps({"gated_paths": [{"pattern": "services/**", "verify": []}]}, indent=2),
            encoding="utf-8",
        )
        p_empty = subprocess.run(
            [sys.executable, str(vbin_adopt), "verify", "--project", str(repo_adopt), "--change", "PROJ-912"],
            capture_output=True,
            text=True,
            env=self.env,
        )
        self.assertNotEqual(p_empty.returncode, 0)
        d_empty = json.loads(p_empty.stdout)
        self.assertFalse(d_empty["passed"])
        self.assertTrue(any(r.get("empty_verify") for r in d_empty["results"]))

        (repo_adopt / "verigate.json").write_text(
            json.dumps({"gated_paths": [{"pattern": "services/**", "verify": [], "allow_empty_verify": True}]}, indent=2),
            encoding="utf-8",
        )
        p_allow = subprocess.run(
            [sys.executable, str(vbin_adopt), "verify", "--project", str(repo_adopt), "--change", "PROJ-912"],
            capture_output=True,
            text=True,
            env=self.env,
        )
        self.assertEqual(p_allow.returncode, 0, p_allow.stdout + p_allow.stderr)
        self.assertTrue(json.loads(p_allow.stdout)["passed"])


if __name__ == "__main__":
    unittest.main()
