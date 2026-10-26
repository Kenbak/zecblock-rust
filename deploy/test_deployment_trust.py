"""Exercise explicit-release trust against isolated GitHub API fixtures."""
import copy
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import textwrap
import tempfile
import time
import unittest
import urllib.error
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

SPEC = importlib.util.spec_from_file_location(
    "verify_deployment", Path(__file__).with_name("verify-deployment.py")
)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
REPO = "owner/repo"
SHA = "a" * 40
OTHER_SHA = "b" * 40


def run(workflow_id, run_id, number, event="push", **changes):
    value = {
        "id": run_id, "workflow_id": workflow_id, "run_number": number,
        "run_attempt": 1, "event": event, "head_sha": SHA, "head_branch": "main",
        "repository": {"full_name": REPO}, "head_repository": {"full_name": REPO},
        "status": "completed", "conclusion": "success",
        "updated_at": f"2026-10-26T00:00:{number:02d}Z",
    }
    value.update(changes)
    return value


class FakeGitHub:
    def __init__(self):
        self.main = SHA
        self.workflows = [
            {"id": 11, "path": MODULE.WORKFLOWS["ci"], "state": "active"},
            {"id": 22, "path": MODULE.WORKFLOWS["security"], "state": "active"},
            {"id": 33, "path": MODULE.WORKFLOWS["codeql"], "state": "active"},
        ]
        self.runs = {11: [run(11, 101, 1)], 22: [run(22, 201, 1)],
                     33: [run(33, 301, 1, event="dynamic")]}
        self.details = {}
        self.calls = []
        self.error = None
        self.advance_main = False

    def get(self, path, **query):
        self.calls.append((path, query))
        if self.error:
            raise self.error
        if path.endswith("/git/ref/heads/main"):
            sha = self.main
            if self.advance_main:
                self.main = OTHER_SHA
            return {"ref": "refs/heads/main", "object": {"type": "commit", "sha": sha}}
        if path.endswith("/actions/workflows"):
            return {"total_count": len(self.workflows), "workflows": copy.deepcopy(self.workflows)}
        if "/actions/workflows/" in path:
            workflow_id = int(path.split("/")[-2])
            runs = self.runs[workflow_id]
            if query.get("event"):
                runs = [x for x in runs if x["event"] == query["event"]]
            return {"total_count": len(runs), "workflow_runs": copy.deepcopy(runs)}
        run_id = int(path.split("/")[-1])
        if run_id in self.details:
            return copy.deepcopy(self.details[run_id])
        return copy.deepcopy(next(x for runs in self.runs.values() for x in runs if x["id"] == run_id))


class DispatchTrustTests(unittest.TestCase):
    def setUp(self):
        self.event = {"repository": {"full_name": REPO, "default_branch": "main"},
                      "inputs": {"target_sha": SHA, "ci_run_id": "101"}}

    def verify(self, event=None, **changes):
        args = {"repository": REPO, "event_name": "workflow_dispatch",
                "ref": "refs/heads/main", "context_sha": SHA}
        args.update(changes)
        return MODULE.verify_dispatch(self.event if event is None else event, **args)

    def test_explicit_main_dispatch_accepts_exact_inputs(self):
        self.assertEqual(self.verify(), (SHA, 101))

    def test_automatic_or_non_main_dispatch_rejected(self):
        for changes in [{"event_name": "workflow_run"}, {"event_name": "push"},
                        {"ref": "refs/heads/feature"}, {"ref": "refs/tags/main"}]:
            with self.subTest(changes=changes), self.assertRaises(MODULE.ReleaseRejected):
                self.verify(**changes)

    def test_untrusted_repository_or_default_branch_rejected(self):
        for key, value in [("full_name", "fork/repo"), ("default_branch", "dev")]:
            event = copy.deepcopy(self.event)
            event["repository"][key] = value
            with self.subTest(key=key), self.assertRaises(MODULE.ReleaseRejected):
                self.verify(event)

    def test_missing_malformed_or_shell_inputs_rejected(self):
        for value in [None, {}, {"target_sha": "--all", "ci_run_id": "101"},
                      {"target_sha": SHA, "ci_run_id": "1;evil"},
                      {"target_sha": SHA, "ci_run_id": 101},
                      {"target_sha": SHA, "ci_run_id": "0"}]:
            event = copy.deepcopy(self.event)
            event["inputs"] = value
            with self.subTest(value=value), self.assertRaises(MODULE.ReleaseRejected):
                self.verify(event)

    def test_missing_payload_rejected(self):
        with self.assertRaises(MODULE.ReleaseRejected):
            self.verify({})

    def test_dispatch_commit_mismatch_rejected(self):
        with self.assertRaises(MODULE.ReleaseRejected):
            self.verify(context_sha=OTHER_SHA)

    def test_repository_path_injection_rejected(self):
        with self.assertRaises(MODULE.ReleaseRejected):
            self.verify(repository="owner/repo/../../other")

    def test_checkout_must_match_target(self):
        with mock.patch.object(MODULE.subprocess, "check_output", return_value=OTHER_SHA + "\n"):
            with self.assertRaises(MODULE.ReleaseRejected):
                MODULE.require_checkout(SHA)


class ReleaseChecksTests(unittest.TestCase):
    def setUp(self):
        self.api = FakeGitHub()

    def verify(self, ci_run_id=101):
        return MODULE.verify_release(self.api, REPO, SHA, ci_run_id)

    def test_latest_exact_ci_security_and_codeql_success(self):
        release = self.verify()
        self.assertEqual(release["ci"], {"id": 101, "attempt": 1, "updated_at": "2026-10-26T00:00:01Z"})
        self.assertEqual(release["security"], {"id": 201, "attempt": 1, "updated_at": "2026-10-26T00:00:01Z"})
        self.assertEqual(release["codeql"], {"id": 301, "attempt": 1, "updated_at": "2026-10-26T00:00:01Z"})
        self.assertTrue(any(query.get("head_sha") == SHA for _, query in self.api.calls))

    def test_stale_main_sha_rejected_before_run_lookup(self):
        self.api.main = OTHER_SHA
        with self.assertRaises(MODULE.ReleaseRejected):
            self.verify()
        self.assertEqual(len(self.api.calls), 1)

    def test_main_advancing_during_verification_rejected(self):
        self.api.advance_main = True
        with self.assertRaises(MODULE.ReleaseRejected):
            self.verify()

    def test_explicit_ci_run_must_be_latest(self):
        self.api.runs[11].append(run(11, 102, 2))
        with self.assertRaises(MODULE.ReleaseRejected):
            self.verify()

    def test_newer_failed_ci_cannot_fall_back_to_older_success(self):
        self.api.runs[11].append(run(11, 102, 2, conclusion="failure"))
        with self.assertRaises(MODULE.ReleaseRejected):
            self.verify(102)

    def test_missing_security_or_codeql_rejected(self):
        for workflow_id in [22, 33]:
            with self.subTest(workflow_id=workflow_id):
                self.api = FakeGitHub()
                self.api.runs[workflow_id] = []
                with self.assertRaises(MODULE.ReleaseRejected):
                    self.verify()

    def test_required_failed_pending_or_cancelled_run_rejected(self):
        for workflow_id in [11, 22, 33]:
            for status, conclusion in [("completed", "failure"), ("in_progress", None),
                                       ("queued", None), ("completed", "cancelled"),
                                       ("completed", "timed_out"), ("completed", "skipped")]:
                with self.subTest(workflow_id=workflow_id, status=status, conclusion=conclusion):
                    self.api = FakeGitHub()
                    self.api.runs[workflow_id][0].update(status=status, conclusion=conclusion)
                    with self.assertRaises(MODULE.ReleaseRejected):
                        self.verify()

    def test_newer_scheduled_audit_failure_blocks_older_green_push(self):
        self.api.runs[22].append(run(22, 202, 2, event="schedule", conclusion="failure"))
        with self.assertRaises(MODULE.ReleaseRejected):
            self.verify()

    def test_pending_manual_audit_blocks_older_green_push(self):
        self.api.runs[22].append(run(22, 202, 2, event="workflow_dispatch", status="in_progress", conclusion=None))
        with self.assertRaises(MODULE.ReleaseRejected):
            self.verify()

    def test_newer_successful_manual_audit_is_recorded(self):
        self.api.runs[22].append(run(22, 202, 2, event="workflow_dispatch"))
        self.assertEqual(self.verify()["security"], {"id": 202, "attempt": 1, "updated_at": "2026-10-26T00:00:02Z"})

    def test_manual_audit_cannot_replace_missing_push_audit(self):
        self.api.runs[22] = [run(22, 202, 2, event="workflow_dispatch")]
        with self.assertRaises(MODULE.ReleaseRejected):
            self.verify()

    def test_detail_latest_attempt_failure_blocks_stale_list_success(self):
        self.api.details[201] = run(22, 201, 1, run_attempt=2, conclusion="failure")
        with self.assertRaises(MODULE.ReleaseRejected):
            self.verify()

    def test_attempt_change_even_to_success_requires_new_verification(self):
        self.api.details[101] = run(11, 101, 1, run_attempt=2)
        with self.assertRaises(MODULE.ReleaseRejected):
            self.verify()

    def test_latest_completed_rerun_is_accepted_when_consistent(self):
        self.api.runs[11][0]["run_attempt"] = 2
        self.assertEqual(self.verify()["ci"]["attempt"], 2)

    def test_older_created_failed_rerun_blocks_newer_number_green_audit(self):
        self.api.runs[22].append(run(22, 202, 2, event="workflow_dispatch"))
        self.api.runs[22][0].update(run_attempt=2, conclusion="failure",
                                   updated_at="2026-10-26T00:01:00Z")
        with self.assertRaises(MODULE.ReleaseRejected):
            self.verify()

    def test_pending_overlap_blocks_later_green_completion(self):
        self.api.runs[22][0].update(status="in_progress", conclusion=None)
        self.api.runs[22].append(run(22, 202, 2, event="workflow_dispatch"))
        with self.assertRaises(MODULE.ReleaseRejected):
            self.verify()

    def test_historical_failure_allows_later_completed_success(self):
        self.api.runs[22][0]["conclusion"] = "failure"
        self.api.runs[22].append(run(22, 202, 2))
        self.assertEqual(self.verify(101)["security"]["id"], 202)

    def test_missing_malformed_or_changed_update_time_rejected(self):
        for value in [None, "2026-10-26", "2026-13-26T00:00:01Z", "2026-10-26T00:00:01+00:00"]:
            with self.subTest(value=value):
                self.api = FakeGitHub()
                self.api.runs[22][0]["updated_at"] = value
                with self.assertRaises(MODULE.ReleaseRejected):
                    self.verify()
        self.api = FakeGitHub()
        self.api.details[201] = run(22, 201, 1, updated_at="2026-10-26T00:00:02Z")
        with self.assertRaises(MODULE.ReleaseRejected):
            self.verify()

    def test_wrong_run_source_or_identity_rejected(self):
        changes = [{"head_sha": OTHER_SHA}, {"head_branch": "feature"},
                   {"head_repository": {"full_name": "fork/repo"}},
                   {"repository": {"full_name": "fork/repo"}},
                   {"workflow_id": 99}, {"run_attempt": True}, {"run_number": 0}]
        for change in changes:
            with self.subTest(change=change):
                self.api = FakeGitHub()
                self.api.runs[22][0].update(change)
                with self.assertRaises(MODULE.ReleaseRejected):
                    self.verify()

    def test_pr_ci_run_cannot_supply_artifact(self):
        self.api.runs[11][0]["event"] = "pull_request"
        with self.assertRaises(MODULE.ReleaseRejected):
            self.verify()

    def test_unknown_codeql_event_rejected(self):
        self.api.runs[33][0]["event"] = "workflow_dispatch"
        with self.assertRaises(MODULE.ReleaseRejected):
            self.verify()

    def test_missing_inactive_or_duplicate_required_workflow_rejected(self):
        cases = [self.api.workflows[:-1], self.api.workflows + [copy.deepcopy(self.api.workflows[0])],
                 [dict(x, state="disabled_manually") for x in self.api.workflows]]
        for workflows in cases:
            with self.subTest(workflows=workflows):
                self.api = FakeGitHub()
                self.api.workflows = workflows
                with self.assertRaises(MODULE.ReleaseRejected):
                    self.verify()

    def test_ambiguous_latest_run_number_rejected(self):
        self.api.runs[11].append(run(11, 102, 1))
        with self.assertRaises(MODULE.ReleaseRejected):
            self.verify()

    def test_api_failure_never_passes(self):
        self.api.error = MODULE.ReleaseRejected("HTTP 403")
        with self.assertRaises(MODULE.ReleaseRejected):
            self.verify()


class APIContractTests(unittest.TestCase):
    def test_missing_token_rejected(self):
        with self.assertRaises(MODULE.ReleaseRejected):
            MODULE.GitHub("")

    def test_http_or_transport_error_rejected_without_token(self):
        errors = [urllib.error.HTTPError("https://api.github.com", 403, "denied", None, None),
                  urllib.error.URLError("offline"), TimeoutError()]
        for error in errors:
            with self.subTest(error=type(error).__name__), mock.patch.object(MODULE.urllib.request, "urlopen", side_effect=error):
                with self.assertRaises(MODULE.ReleaseRejected) as caught:
                    MODULE.GitHub("sentinel-token").get("/test")
                self.assertNotIn("sentinel-token", str(caught.exception))

    def test_malformed_duplicate_nonstandard_or_oversized_json_rejected(self):
        for raw in [b"{bad", b'{"id":1,"id":2}', b'{"id":NaN}', b" " * 2_000_001]:
            response = mock.MagicMock()
            response.__enter__.return_value = response
            response.status, response.read.return_value = 200, raw
            with self.subTest(size=len(raw)), mock.patch.object(MODULE.urllib.request, "urlopen", return_value=response):
                with self.assertRaises(MODULE.ReleaseRejected):
                    MODULE.GitHub("sentinel-token").get("/test")

    def test_invalid_collection_or_duplicate_identity_rejected(self):
        for data in [{}, {"total_count": True, "items": []}, {"total_count": 1, "items": []},
                     {"total_count": 1001, "items": []}, {"total_count": 1, "items": [None]},
                     {"total_count": 2, "items": [{"id": 1}, {"id": 1}]}]:
            api = mock.Mock()
            api.get.return_value = data
            with self.subTest(data=data), self.assertRaises(MODULE.ReleaseRejected):
                MODULE.collection(api, "/test", "items")

    def test_collection_reads_remaining_pages(self):
        api = mock.Mock()
        api.get.side_effect = [
            {"total_count": 101, "items": [{"id": i} for i in range(1, 101)]},
            {"total_count": 101, "items": [{"id": 101}]},
        ]
        self.assertEqual(len(MODULE.collection(api, "/test", "items")), 101)


class EntrypointTests(unittest.TestCase):
    def invoke(self, api, expected=None):
        with tempfile.TemporaryDirectory() as temp:
            event = Path(temp) / "event.json"
            output = Path(temp) / "output"
            event.write_text(json.dumps({"repository": {"full_name": REPO, "default_branch": "main"},
                                         "inputs": {"target_sha": SHA, "ci_run_id": "101"}}))
            env = {"GITHUB_EVENT_PATH": str(event), "GITHUB_REPOSITORY": REPO,
                   "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REF": "refs/heads/main",
                   "GITHUB_SHA": SHA, "GITHUB_TOKEN": "sentinel-token", "GITHUB_OUTPUT": str(output)}
            if expected is not None:
                env["EXPECTED_RELEASE"] = json.dumps(expected)
            stdout, stderr = io.StringIO(), io.StringIO()
            with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(MODULE, "GitHub", return_value=api), \
                    mock.patch.object(MODULE, "require_checkout"), redirect_stdout(stdout), redirect_stderr(stderr):
                try:
                    MODULE.main()
                    code = 0
                except SystemExit as error:
                    code = error.code
            self.assertNotIn("sentinel-token", stdout.getvalue() + stderr.getvalue())
            return code, output.read_text() if output.exists() else ""

    def test_outputs_only_verified_artifact_inputs(self):
        code, output = self.invoke(FakeGitHub())
        self.assertEqual(code, 0)
        fields = dict(line.split("=", 1) for line in output.splitlines())
        self.assertEqual(fields["target_sha"], SHA)
        self.assertEqual(fields["ci_run_id"], "101")
        self.assertEqual(fields["ci_run_attempt"], "1")
        self.assertEqual(json.loads(fields["release"])["ci"]["attempt"], 1)

    def test_failed_security_writes_no_usable_outputs(self):
        api = FakeGitHub()
        api.runs[22][0]["conclusion"] = "failure"
        self.assertEqual(self.invoke(api), (1, ""))

    def test_changed_checks_before_ssh_are_rejected(self):
        expected = MODULE.verify_release(FakeGitHub(), REPO, SHA, 101)
        api = FakeGitHub()
        api.runs[22][0]["run_attempt"] = 2
        self.assertEqual(self.invoke(api, expected), (1, ""))

    def test_unchanged_second_verification_succeeds(self):
        expected = MODULE.verify_release(FakeGitHub(), REPO, SHA, 101)
        self.assertEqual(self.invoke(FakeGitHub(), expected)[0], 0)


class TransactionHost:
    """Run the workflow's exact shell transaction with synthetic files/commands."""
    def __init__(self, base, role):
        self.role = role
        self.base = Path(base) / role
        self.root = self.base / "source"
        self.root.joinpath("target/release").mkdir(parents=True)
        self.root.joinpath("deploy").mkdir()
        self.etc = self.base / "systemd"
        self.etc.mkdir()
        self.tmp = self.base / "tmp"
        self.tmp.mkdir()
        self.bin = self.base / "commands"
        self.bin.mkdir()
        self.release_id = "123-1"
        self.old_sha = "c" * 40
        self.binary = self.root / "target/release/cipherscan-indexer"
        self.binary.write_text("#!/bin/sh\nexit 0\n# original " + role + "\n")
        self.binary.chmod(0o755)
        self.old_binary = self.binary.read_bytes()
        self.unit = self.etc / "cipherscan-rust.service"
        self.unit.write_text("original unit " + role)
        self.old_unit = self.unit.read_bytes()
        self.root.joinpath("deploy/cipherscan-rust.service").write_text("candidate unit")
        self.root.joinpath(".env").write_text("")
        self.head = self.root / ".mock-head"
        self.head.write_text(self.old_sha + "\n")
        self.candidate = self.tmp / ("cipherscan-indexer-" + self.release_id)
        self.candidate.write_text("#!/bin/sh\nexit 0\n# candidate\n")
        self.candidate.chmod(0o755)
        self.state = self.root / ".deploy-releases" / self.release_id
        self.log = self.base / "commands.log"
        self.log.touch()
        text = Path(__file__).parents[1].joinpath(".github/workflows/deploy.yml").read_text()
        script = textwrap.dedent(text.split("# BEGIN RELEASE TRANSACTION\n", 1)[1]
                                 .split("# END RELEASE TRANSACTION", 1)[0])
        script = script.replace("/root/cipherscan-rust", str(self.root))
        script = script.replace("/etc/systemd/system", str(self.etc))
        script = script.replace("/tmp/cipherscan-indexer-", str(self.tmp / "cipherscan-indexer-"))
        self.lock = self.base / "transaction.lock"
        script = script.replace("/run/cipherscan-release-transaction.lock", str(self.lock))
        self.script = self.base / "transaction.sh"
        self.script.write_text(script)
        self.env = dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ["PATH"],
                        MOCK_CALLS=str(self.log), MOCK_REMOTE_SHA=SHA,
                        MOCK_RECOVERY="f" if role == "primary" else "t",
                        MOCK_ACTIVE="active" if role == "primary" else "inactive",
                        MOCK_ENABLED="enabled" if role == "primary" else "disabled",
                        MOCK_ROOT=str(self.root), REAL_CP=shutil.which("cp"),
                        REAL_MV=shutil.which("mv"), REAL_INSTALL=shutil.which("install"),
                        MOCK_PYTHON=sys.executable)
        pause = self.base / "pause.py"
        pause.write_text(textwrap.dedent('''
            import pathlib, sys, time
            path = pathlib.Path(sys.argv[1])
            path.with_suffix(".entered").touch()
            deadline = time.monotonic() + 10
            while not path.with_suffix(".resume").exists():
                if time.monotonic() > deadline:
                    raise SystemExit("Test pause was not released")
                time.sleep(0.01)
        '''))
        self.env["MOCK_PAUSE_SCRIPT"] = str(pause)
        # macOS lacks the util-linux command. Exercise the same inherited-FD
        # flock semantics with its real OS lock, keeping the fixture portable.
        lock_command = self.bin / "flock"
        lock_command.write_text("#!" + sys.executable + "\n" + textwrap.dedent('''
            import fcntl, os, pathlib, sys, time
            assert sys.argv[1:] == ["-x", "-w", "120", "9"]
            deadline = time.monotonic() + float(os.environ.get("MOCK_LOCK_TIMEOUT", "120"))
            while True:
                try:
                    fcntl.flock(9, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    waiting = os.environ.get("MOCK_LOCK_WAITING")
                    if waiting:
                        pathlib.Path(waiting).touch()
                    if time.monotonic() >= deadline:
                        raise SystemExit(1)
                    time.sleep(0.01)
        '''))
        lock_command.chmod(0o755)
        self.command("sudo", '''
            test "$*" = "-u postgres psql -qtAX -v ON_ERROR_STOP=1 -c SELECT pg_is_in_recovery();"
            printf '%s\\n' "$MOCK_RECOVERY"
        ''')
        self.command("systemctl", '''
            printf '%s\\n' "$*" >> "$MOCK_CALLS"
            case "$1" in
              is-active)
                [ "${2:-}" = --quiet ] || printf '%s\\n' "$MOCK_ACTIVE"
                [ "$MOCK_ACTIVE" = active ] || exit 3 ;;
              is-enabled)
                printf '%s\\n' "$MOCK_ENABLED"
                [ "$MOCK_ENABLED" = enabled ] || exit 1 ;;
              restart)
                if [ -n "${MOCK_PAUSE_RESTART:-}" ]; then
                  "$MOCK_PYTHON" "$MOCK_PAUSE_SCRIPT" "$MOCK_PAUSE_RESTART"
                fi
                [ "${MOCK_RESTART_FAIL:-0}" != 1 ] ;;
              daemon-reload) : ;;
              *) exit 90 ;;
            esac
        ''')
        self.command("git", '''
            if [ "$1" = -C ]; then cd "$2"; shift 2; fi
            case "$1" in
              diff) [ "${MOCK_DIRTY:-0}" != 1 ] ;;
              fetch) [ "${MOCK_FETCH_FAIL:-0}" != 1 ] ;;
              rev-parse)
                if [ "$2" = HEAD ]; then cat "$MOCK_ROOT/.mock-head";
                elif [ "$2" = origin/main ]; then printf '%s\\n' "$MOCK_REMOTE_SHA";
                else exit 91; fi ;;
              reset)
                if [ -n "${MOCK_PAUSE_RESET:-}" ]; then
                  "$MOCK_PYTHON" "$MOCK_PAUSE_SCRIPT" "$MOCK_PAUSE_RESET"
                fi
                printf '%s\\n' "$3" > "$MOCK_ROOT/.mock-head"
                if [ "${MOCK_RESET_FAIL_ONCE:-0}" = 1 ] && [ ! -f "$MOCK_ROOT/.reset-failed" ]; then
                  touch "$MOCK_ROOT/.reset-failed"; exit 92
                fi ;;
              *) exit 93 ;;
            esac
        ''')
        self.command("install", '''
            for destination do :; done
            case "${MOCK_INSTALL_FAIL:-}:$destination" in
              binary:*cipherscan-indexer.candidate-*|unit:*cipherscan-rust.service.candidate-*)
                printf partial > "$destination"; exit 94 ;;
            esac
            exec "$REAL_INSTALL" "$@"
        ''')
        self.command("mv", '''
            for destination do :; done
            case "${MOCK_RENAME_FAIL:-}:$destination" in
              binary:*cipherscan-indexer|unit:*cipherscan-rust.service) exit 95 ;;
            esac
            exec "$REAL_MV" "$@"
        ''')
        self.command("cp", '''
            for destination do :; done
            case "${MOCK_COPY_FAIL:-}:$destination" in
              backup:*unit.previous|rollback:*.rollback-*)
                printf partial > "$destination"; exit 96 ;;
            esac
            exec "$REAL_CP" "$@"
        ''')
        self.command("sleep", ":")

    def command(self, name, script):
        path = self.bin / name
        path.write_text("#!/bin/bash\nset -euo pipefail\n" + textwrap.dedent(script))
        path.chmod(0o755)

    def invoke(self, action, **changes):
        env = dict(self.env, **changes)
        return subprocess.run(["bash", str(self.script), action, self.release_id, SHA, self.role],
                              env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def snapshot(self):
        return self.binary.read_bytes(), self.unit.read_bytes(), self.head.read_text().strip()

    def original(self):
        return self.old_binary, self.old_unit, self.old_sha


class ReleaseTransactionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.primary = TransactionHost(self.temp.name, "primary")
        self.standby = TransactionHost(self.temp.name, "standby")

    def success(self, host, action, **changes):
        result = host.invoke(action, **changes)
        self.assertEqual(result.returncode, 0, result.stderr)

    def failed(self, host, action, **changes):
        result = host.invoke(action, **changes)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

    def wait_for(self, path):
        deadline = time.monotonic() + 5
        while not path.exists():
            self.assertLess(time.monotonic(), deadline, "Transaction fixture did not reach barrier")
            time.sleep(0.01)

    def concurrent_rollback(self, action, pause_variable):
        host = self.primary
        control = host.base / "paused"
        waiting = host.base / "rollback.waiting"
        commands = ["bash", str(host.script)]
        processes = []
        try:
            operation = subprocess.Popen(commands + [action, host.release_id, SHA, host.role],
                                         env=dict(host.env, **{pause_variable: str(control)}),
                                         text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            processes.append(operation)
            self.wait_for(control.with_suffix(".entered"))
            rollback = subprocess.Popen(commands + ["rollback", host.release_id, SHA, host.role],
                                        env=dict(host.env, MOCK_LOCK_WAITING=str(waiting)),
                                        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            processes.append(rollback)
            self.wait_for(waiting)
            self.assertIsNone(rollback.poll())
            self.assertFalse(host.state.joinpath("rollback.done").exists())
        finally:
            control.with_suffix(".resume").touch()
            for process in processes:
                try:
                    process.communicate(timeout=15)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.communicate(timeout=15)
        self.assertEqual([p.returncode for p in processes], [0, 0])
        self.assertEqual(host.snapshot(), host.original())
        self.success(host, "rollback")
        self.assertEqual(host.snapshot(), host.original())

    def test_rollback_waits_for_inflight_prepare_after_ssh_interruption(self):
        self.concurrent_rollback("prepare", "MOCK_PAUSE_RESET")

    def test_rollback_waits_for_inflight_activation_after_ssh_interruption(self):
        self.success(self.primary, "prepare")
        self.concurrent_rollback("activate", "MOCK_PAUSE_RESTART")

    def test_busy_transaction_lock_fails_without_mutation(self):
        import fcntl
        with self.primary.lock.open("w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            self.failed(self.primary, "prepare", MOCK_LOCK_TIMEOUT="0.05")
        self.assertEqual(self.primary.snapshot(), self.primary.original())
        self.assertFalse(self.primary.state.exists())

    def test_expected_roles_are_read_only_and_passive(self):
        for host in [self.primary, self.standby]:
            self.success(host, "check")
            self.assertEqual(host.snapshot(), host.original())
            self.assertFalse(host.state.exists())
            self.assertNotIn("restart", host.log.read_text())

    def test_role_change_active_or_enabled_standby_rejected_before_mutation(self):
        for host, changes in [(self.primary, {"MOCK_RECOVERY": "t"}),
                              (self.standby, {"MOCK_RECOVERY": "f"}),
                              (self.standby, {"MOCK_ACTIVE": "active"}),
                              (self.standby, {"MOCK_ENABLED": "enabled"})]:
            with self.subTest(role=host.role, changes=changes):
                self.failed(host, "prepare", **changes)
                self.assertEqual(host.snapshot(), host.original())
                self.assertFalse(host.state.exists())

    def test_failed_staging_only_removes_own_temporary_file(self):
        for host in [self.primary, self.standby]:
            persistent = host.binary.with_suffix(".previous")
            persistent.write_text("stale prior release")
            unrelated = host.tmp / "cipherscan-indexer-999-1"
            unrelated.write_text("other run")
            self.success(host, "rollback")
            self.assertEqual(host.snapshot(), host.original())
            self.assertEqual(persistent.read_text(), "stale prior release")
            self.assertTrue(unrelated.exists())
            self.assertFalse(host.candidate.exists())
            self.assertEqual(host.log.read_text(), "")

    def test_exact_main_failure_never_uses_stale_backups(self):
        self.standby.binary.with_suffix(".previous").write_text("older incompatible binary")
        self.failed(self.standby, "prepare", MOCK_REMOTE_SHA=OTHER_SHA)
        self.success(self.standby, "rollback")
        self.assertEqual(self.standby.snapshot(), self.standby.original())
        self.assertFalse(self.standby.state.exists())

    def test_first_host_changed_second_untouched_rollback_is_per_host(self):
        self.success(self.primary, "prepare")
        self.failed(self.standby, "prepare", MOCK_REMOTE_SHA=OTHER_SHA)
        self.success(self.primary, "rollback")
        self.success(self.standby, "rollback")
        for host in [self.primary, self.standby]:
            self.assertEqual(host.snapshot(), host.original())
            self.assertNotIn("restart", host.log.read_text())

    def test_incomplete_backup_cannot_authorize_restore_or_mutation(self):
        self.failed(self.primary, "prepare", MOCK_COPY_FAIL="backup")
        self.assertFalse(self.primary.state.joinpath("source.changed").exists())
        self.success(self.primary, "rollback")
        self.assertEqual(self.primary.snapshot(), self.primary.original())

    def test_partial_source_reset_is_marked_and_restored(self):
        self.failed(self.primary, "prepare", MOCK_RESET_FAIL_ONCE="1")
        self.assertTrue(self.primary.state.joinpath("source.changed").exists())
        self.success(self.primary, "rollback")
        self.assertEqual(self.primary.snapshot(), self.primary.original())

    def test_binary_install_failure_after_backup_restores_only_mutated_source(self):
        self.failed(self.primary, "prepare", MOCK_INSTALL_FAIL="binary")
        self.assertFalse(self.primary.state.joinpath("binary.changed").exists())
        self.success(self.primary, "rollback")
        self.assertEqual(self.primary.snapshot(), self.primary.original())
        self.assertFalse(self.primary.binary.with_name(self.primary.binary.name + ".candidate-123-1").exists())
        self.assertNotIn("restart", self.primary.log.read_text())

    def test_binary_rename_failure_is_recoverable_from_this_run_backup(self):
        self.failed(self.primary, "prepare", MOCK_RENAME_FAIL="binary")
        self.assertTrue(self.primary.state.joinpath("binary.changed").exists())
        self.success(self.primary, "rollback")
        self.assertEqual(self.primary.snapshot(), self.primary.original())

    def test_standby_unit_install_failure_restores_binary_without_starting_writer(self):
        self.failed(self.standby, "prepare", MOCK_INSTALL_FAIL="unit")
        self.assertTrue(self.standby.state.joinpath("binary.changed").exists())
        self.assertFalse(self.standby.state.joinpath("unit.changed").exists())
        self.success(self.standby, "rollback")
        self.assertEqual(self.standby.snapshot(), self.standby.original())
        self.assertNotIn("restart", self.standby.log.read_text())

    def test_standby_unit_rename_failure_restores_unit_and_stays_passive(self):
        self.failed(self.standby, "prepare", MOCK_RENAME_FAIL="unit")
        self.assertTrue(self.standby.state.joinpath("unit.changed").exists())
        self.success(self.standby, "rollback")
        self.assertEqual(self.standby.snapshot(), self.standby.original())
        self.assertNotIn("restart", self.standby.log.read_text())

    def test_failed_primary_restart_recovers_original_binary_unit_and_service(self):
        self.success(self.primary, "prepare")
        self.failed(self.primary, "activate", MOCK_RESTART_FAIL="1")
        self.assertTrue(self.primary.state.joinpath("restart.attempted").exists())
        self.success(self.primary, "rollback")
        self.assertEqual(self.primary.snapshot(), self.primary.original())
        self.assertEqual(self.primary.log.read_text().count("restart cipherscan-rust.service"), 2)

    def test_primary_activation_unit_failure_does_not_restart_untouched_service(self):
        self.success(self.primary, "prepare")
        self.failed(self.primary, "activate", MOCK_INSTALL_FAIL="unit")
        self.success(self.primary, "rollback")
        self.assertEqual(self.primary.snapshot(), self.primary.original())
        self.assertNotIn("restart", self.primary.log.read_text())

    def test_standby_cannot_be_activated(self):
        self.success(self.standby, "prepare")
        self.failed(self.standby, "activate")
        self.assertNotIn("restart", self.standby.log.read_text())

    def test_rollback_failure_is_visible_and_retry_remains_possible(self):
        self.success(self.primary, "prepare")
        self.failed(self.primary, "rollback", MOCK_COPY_FAIL="rollback")
        self.assertFalse(self.primary.state.joinpath("rollback.done").exists())
        self.success(self.primary, "rollback")
        self.assertEqual(self.primary.snapshot(), self.primary.original())

    def test_rollback_refuses_changed_database_role_without_starting_writer(self):
        self.success(self.primary, "prepare")
        self.failed(self.primary, "activate", MOCK_RESTART_FAIL="1")
        self.failed(self.primary, "rollback", MOCK_RECOVERY="t")
        self.assertFalse(self.primary.state.joinpath("rollback.done").exists())
        self.assertEqual(self.primary.log.read_text().count("restart cipherscan-rust.service"), 1)

    def test_successful_standby_prepare_and_idempotent_rollback_never_start_writer(self):
        self.success(self.standby, "prepare")
        self.success(self.standby, "rollback")
        self.success(self.standby, "rollback")
        self.assertEqual(self.standby.snapshot(), self.standby.original())
        self.assertNotIn("restart", self.standby.log.read_text())


class WorkflowBoundaryTests(unittest.TestCase):
    def test_dispatch_gates_precede_artifact_and_server_access(self):
        text = Path(__file__).parents[1].joinpath(".github/workflows/deploy.yml").read_text()
        self.assertIn("workflow_dispatch:", text)
        self.assertNotIn("workflow_run:", text)
        self.assertNotIn("github.event.workflow_run", text)
        self.assertLess(text.index("id: release"), text.index("uses: actions/download-artifact"))
        self.assertLess(text.index("Revalidate release checks"), text.index("name: Set up SSH"))
        self.assertIn("run-id: ${{ steps.release.outputs.ci_run_id }}", text)
        self.assertIn("-attempt-${{ steps.release.outputs.ci_run_attempt }}", text)
        ci = Path(__file__).parents[1].joinpath(".github/workflows/ci.yml").read_text()
        self.assertIn("-attempt-${{ github.run_attempt }}", ci)
        self.assertLess(text.index("Require expected database"), text.index("id: stage"))
        final_gate = text.index("Revalidate release checks after staging")
        self.assertGreater(final_gate, text.index("name: Prepare candidate on standby"))
        self.assertLess(final_gate, text.index("name: Apply additive migrations"))
        self.assertNotIn("pg_primary=standby", text)
        self.assertIn("exit \"$rollback_failed\"", text)
        self.assertIn("steps.stage.outcome == 'failure'", text)
        self.assertIn("steps.stage.outcome == 'success'", text)


if __name__ == "__main__":
    unittest.main()
