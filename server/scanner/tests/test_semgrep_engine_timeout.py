"""The engine's time limit must really stop the engine, and stop it promptly.

The engine is a launcher that starts worker processes. ``subprocess.run(timeout=...)`` killed only the
launcher; on Windows it then waited for the output pipe, which the surviving workers kept open, so an
overrun scan could not report its timeout until the engine finished on its own (measured against the
real engine: limit 10 s, raised after 142 s, with the results thrown away). These tests use a stand-in
engine whose child process outlives it, which reproduces that without the real engine.
"""
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from django.test import SimpleTestCase

from scanner.rag import semgrep_detector as sd

# Parent (the "launcher") starts a long-lived child (the "worker") that inherits stdout, records the
# worker's pid, then waits for a long time itself.
_ENGINE = """\
import pathlib, subprocess, sys, time
child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"])
pathlib.Path(sys.argv[1]).write_text(str(child.pid))
time.sleep(120)
"""


def _alive(pid: int) -> bool:
    if os.name == "nt":
        out = subprocess.run(["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
                             capture_output=True, text=True).stdout
        return f'"{pid}"' in out
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


class RunEngineTests(SimpleTestCase):
    def test_returns_the_output_and_exit_code(self):
        code = "import sys; print('out'); print('err', file=sys.stderr); sys.exit(3)"
        result = sd._run_engine([sys.executable, "-c", code], env=os.environ.copy(), cwd=None, timeout=60)
        self.assertEqual((result.returncode, result.stdout.strip(), result.stderr.strip()), (3, "out", "err"))

    def test_timeout_kills_the_worker_processes_and_returns_promptly(self):
        with tempfile.TemporaryDirectory() as tmp:
            script, pid_file = Path(tmp) / "engine.py", Path(tmp) / "worker.pid"
            script.write_text(_ENGINE, encoding="utf-8")
            started = time.monotonic()
            with self.assertRaises(subprocess.TimeoutExpired):
                sd._run_engine([sys.executable, str(script), str(pid_file)], env=os.environ.copy(),
                               cwd=None, timeout=3)
            elapsed = time.monotonic() - started
            worker = int(pid_file.read_text())
            try:
                # The old behaviour waited for the 120 s worker; the fix returns within seconds.
                self.assertLess(elapsed, 30, f"took {elapsed:.0f}s to give up on an engine that overran")
                deadline = time.monotonic() + 10
                while _alive(worker) and time.monotonic() < deadline:
                    time.sleep(0.2)
                self.assertFalse(_alive(worker), "the engine's worker process was left running")
            finally:
                if _alive(worker):                      # never leave a test process behind
                    if os.name == "nt":
                        subprocess.run(["taskkill", "/F", "/PID", str(worker)], capture_output=True)
                    else:
                        os.kill(worker, 9)

    def test_gives_up_on_pipes_that_never_close(self):
        # Something escaped the kill and still holds the pipe: do not wait for it forever.
        proc = mock.Mock(pid=123)
        proc.communicate.side_effect = [subprocess.TimeoutExpired("x", 1), subprocess.TimeoutExpired("x", 1)]
        with mock.patch.object(sd.subprocess, "Popen", return_value=proc), \
             mock.patch.object(sd, "_kill_process_tree") as kill, \
             mock.patch.object(sd, "_REAP_SECONDS", 0.01):
            with self.assertRaises(subprocess.TimeoutExpired):
                sd._run_engine(["engine"], env={}, cwd=None, timeout=1)
        kill.assert_called_once_with(proc)

    def test_interrupt_kills_the_tree_too(self):
        proc = mock.Mock(pid=123)
        proc.communicate.side_effect = KeyboardInterrupt
        with mock.patch.object(sd.subprocess, "Popen", return_value=proc), \
             mock.patch.object(sd, "_kill_process_tree") as kill:
            with self.assertRaises(KeyboardInterrupt):
                sd._run_engine(["engine"], env={}, cwd=None, timeout=1)
        kill.assert_called_once_with(proc)


class RunSemgrepTimeoutTests(SimpleTestCase):
    @mock.patch("scanner.rag.semgrep_detector.get_privacy_rules_dir", return_value="")
    @mock.patch("scanner.rag.semgrep_detector.get_semgrep_rules_dir", return_value="/rules")
    @mock.patch("scanner.rag.semgrep_detector.get_semgrep_bin", return_value="/bin/semgrep")
    def test_timeout_is_reported_as_a_detection_error_with_the_limit(self, _bin, _rules, _privacy):
        with mock.patch.object(sd, "_run_engine", side_effect=subprocess.TimeoutExpired("x", 5)), \
             mock.patch.object(sd, "_TIMEOUT_SECONDS", 5):
            with self.assertRaisesRegex(sd.SemgrepDetectionError, "did not finish within 5s"):
                sd.run_semgrep("/code")


if __name__ == "__main__":
    unittest.main()
