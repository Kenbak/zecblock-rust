"""Exercise monitor deduplication, recovery and command stalls without Telegram."""
import importlib.util
import json
import os
import shutil
import time
from pathlib import Path
import subprocess
import tempfile
import unittest

DEPLOY = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("fingerprint", DEPLOY / "health-alert-fingerprint.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


MSPEC = importlib.util.spec_from_file_location("metrics", DEPLOY / "health-alert-metrics.py")
METRICS = importlib.util.module_from_spec(MSPEC)
MSPEC.loader.exec_module(METRICS)


class MetricsTests(unittest.TestCase):
    def failing(self, *codes):
        return "trace\n" + json.dumps({"healthy": False, "reason_codes": list(codes), "status": {"height": 9}})

    def test_healthy_and_failing_render_only_categories(self):
        ok = METRICS.render("active", 0, 1700000000, "{}")
        self.assertIn('zecblock_indexer_healthy{reasons=""} 1', ok)
        self.assertIn("zecblock_indexer_service_active 1", ok)
        self.assertIn("zecblock_indexer_health_last_run_timestamp_seconds 1700000000", ok)
        bad = METRICS.render("active", 1, 1700000000, self.failing("lag_exceeded", "ingest_stalled", "lag_exceeded"))
        self.assertIn('zecblock_indexer_healthy{reasons="ingest_stalled,lag_exceeded"} 0', bad)
        self.assertNotIn("height", bad)

    def test_inactive_timeout_and_unparseable(self):
        self.assertEqual(METRICS.reasons("failed", 1, ""), ["service_inactive"])
        self.assertEqual(METRICS.reasons("active", 124, ""), ["health_command_timeout"])
        self.assertEqual(METRICS.reasons("active", 1, "DB down"), ["health_command_failed"])
        # Codes that could break label syntax or leak text are not trusted.
        self.assertEqual(METRICS.reasons("active", 1, self.failing('x"} 1\nevil')), ["health_command_failed"])

    def test_script_can_run_without_telegram_and_writes_metrics(self):
        script = (DEPLOY / "check-indexer-health.sh").read_text()
        self.assertIn('TELEGRAM_ALERTS="${INDEXER_TELEGRAM_ALERTS:-on}"', script)
        self.assertIn('[[ "${TELEGRAM_ALERTS}" == "on" ]] || return 0', script)
        self.assertIn("write_metrics", script)


class FingerprintTests(unittest.TestCase):
    def assessment(self, age, code="ingest_stalled"):
        return "trace message\n" + json.dumps({"healthy": False, "reasons": [f"age {age}s"],
            "reason_codes": [code], "status": {"height": age}}) + "\nError: stale"

    def test_clocks_heights_and_metrics_do_not_change_failure_identity(self):
        self.assertEqual(MODULE.fingerprint("active", 1, self.assessment(601)),
                         MODULE.fingerprint("active", 1, self.assessment(901)))

    def test_new_failure_and_timeout_have_distinct_identities(self):
        identities = {MODULE.fingerprint("active", 1, self.assessment(601)),
                      MODULE.fingerprint("active", 1, self.assessment(601, "tip_heartbeat_stale")),
                      MODULE.fingerprint("failed", 1, "service failed"),
                      MODULE.fingerprint("active", 124, ""),
                      MODULE.fingerprint("active", 1, "DB unavailable")}
        self.assertEqual(len(identities), 5)

    def test_malformed_json_is_a_stable_command_failure(self):
        self.assertEqual(MODULE.fingerprint("active", 1, "{broken"),
                         MODULE.fingerprint("active", 1, "other error at 999"))

    @unittest.skipUnless(shutil.which("timeout"), "GNU timeout is required (Linux CI/server)")
    def test_hung_health_command_is_bounded_and_alert_is_deduplicated(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            commands = root / "bin"
            commands.mkdir()
            for name, body in {
                "systemctl": "#!/bin/sh\necho active\n",
                "curl": '#!/bin/sh\nprintf "message\\n" >> "$MESSAGES"\n',
                "indexer": "#!/bin/sh\nexec sleep 30\n",
            }.items():
                path = commands / name
                path.write_text(body)
                path.chmod(0o755)
            messages = root / "messages"
            env = {**os.environ, "PATH": str(commands) + os.pathsep + os.environ["PATH"],
                "INDEXER_BIN": str(commands / "indexer"), "INDEXER_MONITOR_STATE_DIR": str(root / "state"),
                "TELEGRAM_BOT_TOKEN": "test", "TELEGRAM_CHAT_ID": "test", "MESSAGES": str(messages),
                "INDEXER_HEALTH_TIMEOUT_SECONDS": "1"}
            started = time.monotonic()
            for _ in range(2):
                result = subprocess.run(["bash", str(DEPLOY / "check-indexer-health.sh")],
                    env=env, capture_output=True, text=True, timeout=10, check=False)
                self.assertEqual(result.returncode, 1, result.stderr)
            self.assertLess(time.monotonic() - started, 8)
            self.assertEqual(len(messages.read_text().splitlines()), 1)

    def test_monitor_suppresses_repeat_then_sends_recovery_once(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            commands = root / "bin"
            commands.mkdir()
            scripts = {
                "systemctl": "#!/bin/sh\necho active\n",
                "timeout": '#!/bin/sh\nshift 2\nexec "$@"\n',
                "curl": '#!/bin/sh\nprintf "message\\n" >> "$MESSAGES"\n',
                "indexer": '#!/bin/sh\ncat "$HEALTH_JSON"\nexit "$HEALTH_RC"\n',
            }
            for name, body in scripts.items():
                path = commands / name
                path.write_text(body)
                path.chmod(0o755)
            health_json = root / "health.json"
            messages = root / "messages"
            env = {**os.environ, "PATH": str(commands) + os.pathsep + os.environ["PATH"],
                "INDEXER_BIN": str(commands / "indexer"), "INDEXER_MONITOR_STATE_DIR": str(root / "state"),
                "TELEGRAM_BOT_TOKEN": "test", "TELEGRAM_CHAT_ID": "test", "HEALTH_JSON": str(health_json),
                "MESSAGES": str(messages), "HEALTH_RC": "1"}
            def run(output, rc=1):
                health_json.write_text(output)
                env["HEALTH_RC"] = str(rc)
                return subprocess.run(["bash", str(DEPLOY / "check-indexer-health.sh")], env=env,
                    capture_output=True, text=True, check=False)
            self.assertEqual(run(self.assessment(601)).returncode, 1)
            self.assertEqual(run(self.assessment(901)).returncode, 1)
            self.assertEqual(len(messages.read_text().splitlines()), 1)
            self.assertEqual(run(self.assessment(901, "tip_heartbeat_stale")).returncode, 1)
            self.assertEqual(len(messages.read_text().splitlines()), 2)
            self.assertEqual(run('{"healthy":true}', 0).returncode, 0)
            self.assertEqual(run('{"healthy":true}', 0).returncode, 0)
            self.assertEqual(len(messages.read_text().splitlines()), 3)


if __name__ == "__main__":
    unittest.main()
