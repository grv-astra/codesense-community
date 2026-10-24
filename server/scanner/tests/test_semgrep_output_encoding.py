"""Regression: run_semgrep() must decode the engine's stdout as UTF-8 whatever the host locale is.

Found on a Windows machine using the cp1252 code page: `subprocess.run(..., text=True)` with no
explicit encoding decodes the pipe with the *locale* codec. The engine emits UTF-8 JSON, and the
first byte cp1252 leaves undefined (0x8d in "Í", 0x8f, 0x81, 0x90, 0x9d) raised
UnicodeDecodeError inside subprocess's reader thread. The thread died, stdout came back empty,
"Could not parse Semgrep JSON output" was logged, and every scan reported 0 findings even though
the engine ran fine (rc=0).

The PYTHONUTF8=1 already put in the *child's* environment does not help: it only changes how the
engine reads its own inputs, not how this process decodes the pipe.
"""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from django.test import SimpleTestCase

from scanner.rag.semgrep_detector import run_semgrep

FIXTURE = Path(__file__).parent / "fixtures" / "semgrep" / "sample_sqli.json"

# "Í" is UTF-8 c3 8d -> 0x8d is undefined in cp1252. The curly quotes and em dash add more
# non-ASCII bytes, as real rule messages and code snippets routinely contain.
NON_CP1252_TEXT = "Íñigo — “quoted” 中文"


def _fake_engine(tmp: Path, payload: bytes) -> str:
    """A stand-in for the engine executable that writes `payload` to stdout as raw bytes."""
    (tmp / "payload.json").write_bytes(payload)
    script = tmp / "fake_engine.py"
    script.write_text(
        "import pathlib, sys\n"
        "sys.stdout.buffer.write(pathlib.Path(__file__).with_name('payload.json').read_bytes())\n"
        "sys.stdout.buffer.flush()\n",
        encoding="utf-8",
    )
    if os.name == "nt":
        wrapper = tmp / "fake_engine.cmd"
        wrapper.write_text(f'@echo off\r\n"{sys.executable}" "{script}" %*\r\n', encoding="utf-8")
    else:
        wrapper = tmp / "fake_engine"
        wrapper.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{script}" "$@"\n', encoding="utf-8")
        wrapper.chmod(0o755)
    return str(wrapper)


class RunSemgrepOutputEncodingTests(SimpleTestCase):
    @mock.patch("scanner.rag.semgrep_detector.get_privacy_rules_dir", return_value="")
    @mock.patch("scanner.rag.semgrep_detector.get_semgrep_rules_dir", return_value="/rules")
    @mock.patch("scanner.rag.semgrep_detector.get_semgrep_bin", return_value="/bin/semgrep")
    @mock.patch("scanner.rag.semgrep_detector.subprocess.Popen")
    def test_requests_utf8_decoding_with_replacement(self, mock_popen, _bin, _rules, _privacy):
        """Locale-independent guard: the call itself must pin the codec, and must not crash the
        whole scan on a stray malformed byte."""
        proc = mock_popen.return_value
        proc.communicate.return_value = ('{"results":[]}', "")
        proc.returncode = 0
        run_semgrep("/code")
        kwargs = mock_popen.call_args.kwargs
        self.assertEqual(kwargs.get("encoding"), "utf-8")
        self.assertEqual(kwargs.get("errors"), "replace")

    def test_non_cp1252_engine_output_still_yields_findings(self):
        """End to end through a real subprocess. On a cp1252 host this failed before the fix
        (findings == []); on UTF-8 hosts it passes either way, which is why the guard above exists."""
        doc = json.loads(FIXTURE.read_text(encoding="utf-8"))
        doc["results"][0]["extra"]["message"] = NON_CP1252_TEXT
        payload = json.dumps(doc, ensure_ascii=False).encode("utf-8")
        self.assertIn(b"\xc3\x8d", payload)  # the byte pair that cp1252 cannot decode

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            engine = _fake_engine(tmp_path, payload)
            with mock.patch("scanner.rag.semgrep_detector.get_semgrep_bin", return_value=engine), \
                 mock.patch("scanner.rag.semgrep_detector.get_semgrep_rules_dir", return_value=str(tmp_path)), \
                 mock.patch("scanner.rag.semgrep_detector.get_privacy_rules_dir", return_value=""):
                findings = run_semgrep(str(tmp_path))

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].message, NON_CP1252_TEXT)


if __name__ == "__main__":
    unittest.main()
