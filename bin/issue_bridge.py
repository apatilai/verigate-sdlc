#!/usr/bin/env python3
"""Universal GitHub Issues & Azure DevOps Work Items CLI Bridge for AI-SDLC.

Subcommands:
  detect  --repo <dir>
  preview --findings <.sdlc/review-findings.json> --provider <auto|github|azdo> [--ids REV-001,...] [--min-severity Medium]
  create  --findings <.sdlc/review-findings.json> --provider <auto|github|azdo> [--ids REV-001,...] [--min-severity Medium]
          [--gh-repo owner/repo] [--azdo-org https://dev.azure.com/org] [--azdo-project Project] [--work-item-type Bug] [--force]
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from urllib.parse import unquote

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "nit": 0}
AZDO_PRIORITY = {"critical": "1", "high": "1", "medium": "2", "low": "3", "nit": "4"}


def _parse_remote_url(url: str, info: dict) -> bool:
    clean = url.strip().rstrip("/")
    gh_match = re.search(r"github\.com[:/]([^/]+/[^/\s]+?)(?:\.git)?$", clean, re.I)
    if gh_match:
        info["detected_provider"] = "github"
        info["gh_repo"] = gh_match.group(1)
        info["remote_url"] = clean
        return True
    az_https = re.search(r"(https://dev\.azure\.com/[^/]+)/([^/]+)/_git/", clean, re.I)
    if az_https:
        info["detected_provider"] = "azdo"
        info["azdo_org"] = az_https.group(1)
        info["azdo_project"] = unquote(az_https.group(2))
        info["remote_url"] = clean
        return True
    az_ssh = re.search(r"ssh\.dev\.azure\.com:v3/([^/]+)/([^/]+)/", clean, re.I)
    if az_ssh:
        info["detected_provider"] = "azdo"
        info["azdo_org"] = f"https://dev.azure.com/{az_ssh.group(1)}"
        info["azdo_project"] = unquote(az_ssh.group(2))
        info["remote_url"] = clean
        return True
    vs_https = re.search(r"(https://[^/]+\.visualstudio\.com)/(?:DefaultCollection/)?([^/]+)/_git/", clean, re.I)
    if vs_https:
        info["detected_provider"] = "azdo"
        info["azdo_org"] = vs_https.group(1)
        info["azdo_project"] = unquote(vs_https.group(2))
        info["remote_url"] = clean
        return True
    return False


def _detect_git_remote(repo_dir: str) -> dict:
    info = {
        "detected_provider": "unknown",
        "remote_url": "",
        "gh_repo": "",
        "azdo_org": "",
        "azdo_project": "",
        "gh_installed": bool(shutil.which("gh")),
        "az_installed": bool(shutil.which("az")),
    }
    try:
        proc = subprocess.run(["git", "-C", repo_dir, "remote", "-v"], capture_output=True, text=True, timeout=5)
        if proc.returncode != 0:
            return info
        remotes: list[tuple[str, str]] = []
        for line in proc.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                remotes.append((parts[0], parts[1]))
        # Prioritize `origin` remote first
        remotes.sort(key=lambda pair: (0 if pair[0] == "origin" else 1, pair[0]))
        for _, url in remotes:
            if _parse_remote_url(url, info):
                return info
    except (OSError, subprocess.TimeoutExpired):
        pass
    return info


def _filter_findings(findings: list[dict], ids_csv: str | None, min_sev: str) -> list[dict]:
    wanted_ids = {x.strip().upper() for x in ids_csv.split(",") if x.strip()} if ids_csv else None
    threshold = SEVERITY_RANK.get(min_sev.lower(), 1)
    selected = []
    for item in findings:
        fid = str(item.get("id") or "").upper()
        if wanted_ids is not None:
            if fid in wanted_ids:
                selected.append(item)
            continue
        sev = str(item.get("severity") or "Medium").lower()
        if SEVERITY_RANK.get(sev, 2) >= threshold:
            selected.append(item)
    return selected


def _format_title(f: dict) -> str:
    return f"[{f.get('id', 'REV')}][{f.get('severity', 'Medium')}][{f.get('category', 'Review')}] {f.get('title', 'Code review finding')}"


def _format_markdown_body(f: dict) -> str:
    loc = f"{f.get('rel_file') or f.get('file', 'unknown')}:{f.get('start_line', 1)}"
    if f.get("end_line") and f.get("end_line") != f.get("start_line"):
        loc += f"-{f.get('end_line')}"
    return (
        f"### Automated Code Review Finding (`{f.get('id', 'REV')}`)\n\n"
        f"- **Severity:** `{f.get('severity', 'Medium')}`\n"
        f"- **Category:** `{f.get('category', 'Code Review')}`\n"
        f"- **Location:** `{loc}`\n\n"
        f"#### Root Cause\n{f.get('root_cause', 'N/A')}\n\n"
        f"#### Operational / Product Impact\n{f.get('impact', 'N/A')}\n\n"
        f"#### Recommended Fix\n```text\n{f.get('suggested_fix', 'N/A')}\n```\n\n"
        f"#### Verification Criteria\n{f.get('acceptance_test', 'Run automated verification suite.')}\n"
    )


def _create_github_issue(f: dict, gh_repo: str | None) -> dict:
    cmd = ["gh", "issue", "create", "--title", _format_title(f), "--body", _format_markdown_body(f)]
    if gh_repo:
        cmd.extend(["--repo", gh_repo])
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"id": f.get("id"), "status": "error", "error": str(exc)}
    if proc.returncode != 0:
        return {"id": f.get("id"), "status": "error", "error": (proc.stderr or proc.stdout).strip()}
    url = proc.stdout.strip().splitlines()[-1] if proc.stdout.strip() else ""
    issue_num = url.rstrip("/").split("/")[-1] if "/issues/" in url else ""
    return {"id": f.get("id"), "status": "created", "provider": "github", "tracker_id": f"#{issue_num}" if issue_num else url, "url": url}


def _create_azdo_work_item(f: dict, org: str | None, project: str | None, wi_type: str) -> dict:
    sev = str(f.get("severity") or "Medium").lower()
    priority = AZDO_PRIORITY.get(sev, "2")
    tags = ";".join(f.get("labels") or ["verigate-review", sev])
    body = _format_markdown_body(f)
    fields = [f"Microsoft.VSTS.Common.Priority={priority}", f"System.Tags={tags}"]
    if wi_type.strip().lower() == "bug":
        fields.append(f"Microsoft.VSTS.TCM.ReproSteps={body}")

    cmd = [
        "az",
        "boards",
        "work-item",
        "create",
        "--type",
        wi_type,
        "--title",
        _format_title(f),
        "--description",
        body,
        "--fields",
        *fields,
        "--output",
        "json",
    ]
    if org:
        cmd.extend(["--org", org])
    if project:
        cmd.extend(["--project", project])
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if proc.returncode != 0:
            return {"id": f.get("id"), "status": "error", "error": (proc.stderr or proc.stdout).strip()}
        data = json.loads(proc.stdout)
    except (OSError, subprocess.TimeoutExpired, ValueError) as exc:
        return {"id": f.get("id"), "status": "error", "error": str(exc)}

    wi_id = data.get("id")
    web_url = ((data.get("_links") or {}).get("html") or {}).get("href") or data.get("url", "")
    return {"id": f.get("id"), "status": "created", "provider": "azdo", "tracker_id": f"AB#{wi_id}" if wi_id else "", "url": web_url}


def _resolve_repo_from_findings(findings_path: str) -> str:
    cur = os.path.dirname(os.path.realpath(findings_path))
    while cur and cur != os.path.dirname(cur):
        if os.path.exists(os.path.join(cur, ".git")) or os.path.basename(cur) == ".sdlc":
            return os.path.dirname(cur) if os.path.basename(cur) == ".sdlc" else cur
        cur = os.path.dirname(cur)
    return os.path.dirname(os.path.realpath(findings_path))


def main() -> None:
    parser = argparse.ArgumentParser(description="Universal GitHub & Azure DevOps Issue Bridge")
    sub = parser.add_subparsers(dest="subcommand", required=True)
    p_det = sub.add_parser("detect")
    p_det.add_argument("--repo", default=".")

    for name in ("preview", "create"):
        p = sub.add_parser(name)
        p.add_argument("--findings", required=True)
        p.add_argument("--provider", choices=["auto", "github", "azdo"], default="auto")
        p.add_argument("--ids", default=None)
        p.add_argument("--min-severity", default="Low", choices=["Critical", "High", "Medium", "Low", "Nit"])
        p.add_argument("--gh-repo", default=None)
        p.add_argument("--azdo-org", default=None)
        p.add_argument("--azdo-project", default=None)
        p.add_argument("--work-item-type", default="Bug")
        if name == "create":
            p.add_argument("--force", action="store_true", help="Re-create tickets even if tracker_id already exists")

    args = parser.parse_args()
    if args.subcommand == "detect":
        print(json.dumps(_detect_git_remote(os.path.realpath(args.repo)), indent=2))
        return

    findings_path = os.path.realpath(args.findings)
    report = json.loads(Path(findings_path).read_text(encoding="utf-8"))
    repo_dir = _resolve_repo_from_findings(findings_path)
    remote_info = _detect_git_remote(repo_dir)
    provider = args.provider
    if provider == "auto":
        provider = remote_info["detected_provider"] if remote_info["detected_provider"] != "unknown" else report.get("detected_provider", "github")
        if provider not in ("github", "azdo"):
            provider = "github"

    selected = _filter_findings(report.get("findings") or [], args.ids, args.min_severity)
    if args.subcommand == "preview":
        items = [{"id": f.get("id"), "provider": provider, "title": _format_title(f), "severity": f.get("severity"), "body_preview": _format_markdown_body(f)} for f in selected]
        print(json.dumps({"provider": provider, "count": len(items), "items": items}, indent=2))
        return

    results = []
    for f in selected:
        if f.get("tracker_id") and not getattr(args, "force", False):
            results.append({"id": f.get("id"), "status": "skipped_existing", "tracker_id": f.get("tracker_id"), "url": f.get("tracker_url", "")})
            continue
        res = (
            _create_github_issue(f, args.gh_repo or remote_info.get("gh_repo") or None)
            if provider == "github"
            else _create_azdo_work_item(f, args.azdo_org or remote_info.get("azdo_org") or None, args.azdo_project or remote_info.get("azdo_project") or None, args.work_item_type)
        )
        results.append(res)
        if res.get("status") == "created":
            f["tracker_provider"] = provider
            f["tracker_id"] = res.get("tracker_id")
            f["tracker_url"] = res.get("url")

    tmp = f"{findings_path}.tmp"
    Path(tmp).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, findings_path)
    print(json.dumps({"provider": provider, "results": results}, indent=2))


if __name__ == "__main__":
    main()
