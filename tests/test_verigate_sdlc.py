#!/usr/bin/env python3
"""Bundled zero-dependency unittest suite for VeriGate AI-SDLC (`REV-001`..`REV-007`).

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

    def _hook(self, payload: dict, raw_override: str | None = None) -> dict:
        p = subprocess.run(
            [sys.executable, str(self.aisdlc_bin), "hook", "--adapter", "auto"],
            input=raw_override if raw_override is not None else json.dumps(payload),
            text=True,
            capture_output=True,
            cwd=str(self.repo),
            env=self.env,
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
        (self.repo / ".sdlc/intent.md").write_text(
            "# Billing Service Intent\nScope: Multi-tenant invoice generation with strict tenant isolation and idempotency.\n- AC-1: Return HTTP 200 with tenant-scoped invoice JSON payload.\n",
            encoding="utf-8",
        )
        (self.repo / ".sdlc/spec.md").write_text(
            "# Billing Architecture Spec\nModule `src/app.py` defines the invoice handler schema and tenant authorization contract.\n## Verification Matrix\n- AC-1 -> unit test `test_tenant_invoice_200`\n",
            encoding="utf-8",
        )
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
        self._hook({"session_id": "s6", "hook_event_name": "PostToolUse", "tool_name": "Bash", "tool_input": {"command": "python3 -m unittest"}, "cwd": str(self.repo)})
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


if __name__ == "__main__":
    unittest.main()
