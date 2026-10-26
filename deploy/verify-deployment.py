"""Verify an explicit native release before artifacts or servers are used.

REST contracts: docs.github.com/en/rest/actions/workflow-runs and
/workflows. Pending checks reject; dispatch again after they succeed.
"""
import json
from datetime import datetime
import os
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

WORKFLOWS = {
    "ci": ".github/workflows/ci.yml",
    "security": ".github/workflows/security.yml",
    "codeql": "dynamic/github-code-scanning/codeql",
}


class ReleaseRejected(ValueError):
    pass


def positive_integer(value):
    if type(value) is not int or value < 1:
        raise ReleaseRejected("Invalid GitHub run/workflow identity")
    return value


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ReleaseRejected("Duplicate JSON keys")
        result[key] = value
    return result


def reject_constant(_value):
    raise ReleaseRejected("Nonstandard JSON value")


def parse_json(text):
    return json.loads(text, object_pairs_hook=unique_object, parse_constant=reject_constant)


class GitHub:
    def __init__(self, token):
        if not token:
            raise ReleaseRejected("GITHUB_TOKEN is required")
        self.token = token

    def get(self, path, **query):
        url = "https://api.github.com" + path
        if query:
            url += "?" + urllib.parse.urlencode(query)
        request = urllib.request.Request(url, headers={
            "Accept": "application/vnd.github+json",
            "Authorization": "Bearer " + self.token,
            "X-GitHub-Api-Version": "2026-03-10",
            "User-Agent": "cipherscan-release-verifier",
        })
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                raw = response.read(2_000_001)
                if response.status != 200 or len(raw) > 2_000_000:
                    raise ReleaseRejected("Invalid or oversized GitHub response")
                return parse_json(raw.decode("utf-8"))
        except urllib.error.HTTPError as error:
            raise ReleaseRejected(f"GitHub API failed (HTTP {error.code})") from None
        except (urllib.error.URLError, TimeoutError, UnicodeError, json.JSONDecodeError):
            raise ReleaseRejected("GitHub API response could not be verified") from None


def collection(api, path, key, **query):
    items, total = [], None
    for page in range(1, 11):
        data = api.get(path, per_page=100, page=page, **query)
        if not isinstance(data, dict) or type(data.get("total_count")) is not int:
            raise ReleaseRejected("Malformed GitHub collection")
        count = data["total_count"]
        if count < 0 or count > 1000 or (total is not None and total != count):
            raise ReleaseRejected("GitHub collection changed or exceeds bounds")
        total = count
        batch = data.get(key)
        if not isinstance(batch, list) or len(batch) > 100 or any(not isinstance(x, dict) for x in batch):
            raise ReleaseRejected("Malformed GitHub collection page")
        items.extend(batch)
        if len(items) >= total:
            if len(items) != total:
                raise ReleaseRejected("GitHub collection count mismatch")
            ids = [positive_integer(x.get("id")) for x in items]
            if len(set(ids)) != len(ids):
                raise ReleaseRejected("Duplicate GitHub collection identities")
            return items
        if not batch:
            break
    raise ReleaseRejected("Incomplete GitHub collection")


def verify_dispatch(event, repository, event_name, ref, context_sha):
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository or ""):
        raise ReleaseRejected("Invalid repository identity")
    if event_name != "workflow_dispatch" or ref != "refs/heads/main":
        raise ReleaseRejected("Native deployment requires explicit dispatch on main")
    if not isinstance(event, dict) or not isinstance(event.get("repository"), dict):
        raise ReleaseRejected("Missing dispatch repository")
    if event["repository"].get("full_name") != repository or event["repository"].get("default_branch") != "main":
        raise ReleaseRejected("Dispatch repository/default branch mismatch")
    inputs = event.get("inputs")
    if not isinstance(inputs, dict):
        raise ReleaseRejected("Missing deployment inputs")
    sha, run_id = inputs.get("target_sha"), inputs.get("ci_run_id")
    if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise ReleaseRejected("target_sha must be a full commit identity")
    if sha != context_sha:
        raise ReleaseRejected("Dispatch commit differs from target_sha")
    if not isinstance(run_id, str) or not re.fullmatch(r"[1-9][0-9]*", run_id):
        raise ReleaseRejected("ci_run_id must be a positive run identity")
    return sha, int(run_id)


def require_current_main(api, repository, sha):
    data = api.get(f"/repos/{repository}/git/ref/heads/main")
    if not isinstance(data, dict) or data.get("ref") != "refs/heads/main":
        raise ReleaseRejected("Cannot verify current main reference")
    obj = data.get("object")
    if not isinstance(obj, dict) or obj.get("type") != "commit" or obj.get("sha") != sha:
        raise ReleaseRejected("target_sha is not the exact current main commit")


def require_checkout(sha):
    current = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    if current != sha:
        raise ReleaseRejected("Checked-out verifier source differs from target_sha")


def workflow_ids(api, repository):
    found = {}
    for workflow in collection(api, f"/repos/{repository}/actions/workflows", "workflows"):
        for name, path in WORKFLOWS.items():
            if workflow.get("path") == path:
                if name in found or workflow.get("state") != "active":
                    raise ReleaseRejected("Required workflow is ambiguous/inactive")
                found[name] = positive_integer(workflow.get("id"))
    if set(found) != set(WORKFLOWS):
        raise ReleaseRejected("Required CI, Security audit or CodeQL workflow missing")
    return found


def validate_run(run, repository, sha, workflow_id, events):
    if not isinstance(run, dict):
        raise ReleaseRejected("Malformed GitHub workflow run")
    for field in ("repository", "head_repository"):
        if not isinstance(run.get(field), dict) or run[field].get("full_name") != repository:
            raise ReleaseRejected("Workflow run repository mismatch")
    if (run.get("head_sha") != sha or run.get("head_branch") != "main"
            or run.get("workflow_id") != workflow_id or run.get("event") not in events):
        raise ReleaseRejected("Workflow run does not match trusted release")
    for field in ("id", "run_number", "run_attempt"):
        positive_integer(run.get(field))
    positive_integer(run.get("workflow_id"))


def updated_at(run):
    value = run.get("updated_at")
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", value):
        raise ReleaseRejected("Missing/malformed workflow update time")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        raise ReleaseRejected("Invalid workflow update time") from None


def latest_run(api, repository, sha, workflow_id, events, push_only=False):
    query = {"head_sha": sha, "branch": "main"}
    if push_only:
        query["event"] = "push"
    runs = collection(api, f"/repos/{repository}/actions/workflows/{workflow_id}/runs", "workflow_runs", **query)
    if not runs:
        raise ReleaseRejected("Required exact-commit workflow run missing")
    for run in runs:
        validate_run(run, repository, sha, workflow_id, events)
        updated_at(run)
        if run.get("status") != "completed":
            raise ReleaseRejected("Required exact-commit workflow has a pending execution")
    if len({run["run_number"] for run in runs}) != len(runs):
        raise ReleaseRejected("Workflow run identities are ambiguous")
    # Rerunning an older run updates it without increasing its run_number.
    ordered = sorted(runs, key=updated_at, reverse=True)
    if len(ordered) > 1 and updated_at(ordered[0]) == updated_at(ordered[1]):
        raise ReleaseRejected("Latest workflow execution is ambiguous")
    listed = ordered[0]
    detail = api.get(f"/repos/{repository}/actions/runs/{listed['id']}")
    validate_run(detail, repository, sha, workflow_id, events)
    updated_at(detail)
    if any(detail[field] != listed[field] for field in ("id", "run_number", "run_attempt", "updated_at")):
        raise ReleaseRejected("Workflow run/attempt changed during verification")
    if detail.get("status") != "completed" or detail.get("conclusion") != "success":
        raise ReleaseRejected("Latest required workflow run/attempt has not succeeded")
    return {"id": detail["id"], "attempt": detail["run_attempt"], "updated_at": detail["updated_at"]}


def verify_release(api, repository, sha, ci_run_id):
    require_current_main(api, repository, sha)
    workflows = workflow_ids(api, repository)
    ci = latest_run(api, repository, sha, workflows["ci"], {"push"}, push_only=True)
    if ci["id"] != ci_run_id:
        raise ReleaseRejected("ci_run_id is not latest exact-commit push CI run")
    security_push = latest_run(api, repository, sha, workflows["security"], {"push"}, push_only=True)
    # An older green push must not hide a newer scheduled/manual audit failure.
    security = latest_run(api, repository, sha, workflows["security"], {"push", "schedule", "workflow_dispatch"})
    codeql = latest_run(api, repository, sha, workflows["codeql"], {"dynamic", "push"})
    require_current_main(api, repository, sha)
    return {"target_sha": sha, "ci": ci, "security_push": security_push, "security": security, "codeql": codeql}


def main():
    try:
        event = parse_json(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
        repository = os.environ["GITHUB_REPOSITORY"]
        sha, ci_run_id = verify_dispatch(event, repository, os.environ["GITHUB_EVENT_NAME"],
                                        os.environ["GITHUB_REF"], os.environ["GITHUB_SHA"])
        require_checkout(sha)
        release = verify_release(GitHub(os.environ.get("GITHUB_TOKEN")), repository, sha, ci_run_id)
        expected = os.environ.get("EXPECTED_RELEASE")
        if expected and parse_json(expected) != release:
            raise ReleaseRejected("Verified runs/attempts changed before server access")
        with Path(os.environ["GITHUB_OUTPUT"]).open("a") as output:
            print(f"target_sha={sha}", file=output)
            print(f"ci_run_id={ci_run_id}", file=output)
            print(f"ci_run_attempt={release['ci']['attempt']}", file=output)
            print("release=" + json.dumps(release, separators=(",", ":")), file=output)
        print("Verified explicit native release: " + json.dumps(release, sort_keys=True))
    except (KeyError, OSError, ValueError, TypeError, RecursionError, subprocess.CalledProcessError) as error:
        print(f"Release rejected: {error}", file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
