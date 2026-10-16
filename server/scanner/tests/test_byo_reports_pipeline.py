"""Mitigation advice written by the user's own LLM, through the real scan loop (step 7).

Runs under Community edition: this must work there. Replies are queued on the fake LLM
server in call order (LSAST_MAX_WORKERS=1): preflight ping, then per finding one
verification reply and, for findings that stay visible, one mitigation reply.
"""
from unittest import mock

from scanner.rag.lsast_scanner import lsast_scan_folder
from scanner.rag.lsast_types import FindingReport, VerifierVerdict
from scanner.tests.edition_test_support import skip_unless_llm_present
from scanner.tests.test_byo_resolve_and_pipeline import ByoTestBase, fp, tp
from scanner.tests.test_lsast_scanner import _safe_orm_finding, _sqli_finding

REPORT = ('{"name": "SQL injection in user lookup", "description": "The query is built by string concatenation.", '
          '"impact": "An attacker can read or modify the database.", '
          '"remediation": "Use a parameterised query instead of concatenating input."}')


class ReportPipelineTests(ByoTestBase):
    def run_scan(self, findings):
        saved, progress = [], []
        with mock.patch("scanner.rag.lsast_scanner.run_semgrep", return_value=findings), \
             mock.patch("scanner.rag.lsast_scanner.save_findings_to_db", side_effect=saved.append), \
             mock.patch("scanner.rag.lsast_scanner.update_progress",
                        side_effect=lambda *a, **k: progress.append(k)):
            visible, filtered = lsast_scan_folder(folder_path="/tmp/code", scan_id="s1", triggered_by="u1")
        metrics = [p["extra_metrics"]["llm"] for p in progress
                   if p.get("extra_metrics") and "llm" in p["extra_metrics"]]
        return visible, filtered, metrics

    def queue(self, *replies):
        for r in replies:
            if isinstance(r, tuple):                       # (status, body) for an error reply
                self.server.reply(r[0], r[1])
            else:
                self.server.reply_openai(r)

    def test_mitigation_is_written_labelled_and_facts_are_untouched(self):
        self.configure(reports=True)
        self.queue("", tp(), REPORT)                       # preflight, verification, mitigation
        visible, _f, metrics = self.run_scan([_sqli_finding()])
        f = visible[0]
        self.assertEqual(f["mitigation"], "Use a parameterised query instead of concatenating input.")
        self.assertEqual(f["title"], "SQL injection in user lookup")
        self.assertEqual(f["description"], "The query is built by string concatenation.")
        self.assertEqual(f["security_risk"], "An attacker can read or modify the database.")
        self.assertEqual(f["report_source"], "ai")
        self.assertEqual((f["cwe"], f["severity"], f["confidence"]), ("CWE-89", "high", 0.9))
        self.assertIn("app/views.py", f["file_path"])      # the location is the detector's, untouched
        final = metrics[-1]
        self.assertEqual((final["calls"], final["report_calls"], final["reports_written"],
                          final["verified"], final["enrich_reports"]), (1, 1, 1, 1, True))
        self.assertEqual(len(self.server.requests), 3)

    def test_the_mitigation_prompt_has_no_file_path_or_file_line_reference(self):
        self.configure(reports=True)
        self.queue("", tp(), REPORT)
        self.run_scan([_sqli_finding()])
        sent = self.server.requests[2]["json"]
        text = " ".join(m["content"] for m in sent["messages"])
        self.assertNotIn("views.py", text)
        self.assertIn("Possible SQL injection", text)      # the analyzer message (covered by consent)
        self.assertIn("cursor.execute(query)", text)
        self.assertNotIn(":12", text)

    def test_switch_off_makes_no_report_calls(self):
        conn = self.configure(reports=True)
        conn.enrich_reports = False
        conn.save()
        self.queue("", tp())
        visible, _f, metrics = self.run_scan([_sqli_finding()])
        self.assertEqual(len(self.server.requests), 2)
        self.assertEqual(visible[0].get("report_source", ""), "")
        self.assertFalse(metrics[-1]["enrich_reports"])
        self.assertEqual(metrics[-1]["report_calls"], 0)

    def test_without_consent_for_reports_only_verification_runs(self):
        conn = self.configure(reports=True)
        conn.consent_reports = False                       # e.g. consent given before step 7
        conn.save()
        self.queue("", tp())
        visible, _f, metrics = self.run_scan([_sqli_finding()])
        self.assertEqual(len(self.server.requests), 2)
        self.assertEqual(visible[0].get("report_source", ""), "")
        self.assertFalse(metrics[-1]["enrich_reports"])

    def test_junk_reply_keeps_the_rule_text_and_verification_is_unaffected(self):
        self.configure(reports=True)
        self.queue("", tp(), "Sorry, I can't help with that.")
        visible, _f, metrics = self.run_scan([_sqli_finding()])
        f = visible[0]
        self.assertEqual(f.get("report_source", ""), "")
        self.assertNotEqual(f["title"], "SQL injection in user lookup")
        self.assertEqual((f["confidence"], metrics[-1]["verified"], metrics[-1]["reports_skipped"]), (0.9, 1, 1))

    def test_failing_report_calls_never_cost_verification_anything(self):
        self.configure(reports=True)
        self.queue("", tp(), (422, {"error": "bad request"}), tp(), (422, {"error": "bad request"}))
        visible, _f, metrics = self.run_scan([_sqli_finding(), _safe_orm_finding()])
        final = metrics[-1]
        self.assertEqual(len(visible), 2)
        self.assertEqual((final["verified"], final["unverified"], final["failures"]), (2, 0, 0))
        self.assertEqual((final["report_calls"], final["report_failures"]), (2, 2))
        self.assertFalse(final["breaker_open"])
        self.assertEqual([f.get("report_source", "") for f in visible], ["", ""])

    def test_a_filtered_false_positive_gets_no_mitigation(self):
        self.configure(reports=True)
        self.queue("", fp(0.95))
        visible, filtered, _m = self.run_scan([_safe_orm_finding()])
        self.assertEqual((len(visible), len(filtered)), (0, 1))
        self.assertEqual(len(self.server.requests), 2)     # ping + verification only

    def test_needs_review_keeps_its_verifier_marker_in_the_new_title(self):
        self.configure(reports=True)
        self.queue("", fp(0.95), REPORT)                   # high severity FP -> needs_review
        visible, _f, _m = self.run_scan([_sqli_finding()])
        self.assertEqual(visible[0]["status"], "needs_review")
        self.assertEqual(visible[0]["title"], "[verifier:FP] SQL injection in user lookup")

    def test_a_dead_connection_means_no_report_attempt(self):
        self.configure(reports=True)
        self.queue("", (401, {"error": "bad key"}))        # preflight ok, then the key is revoked
        visible, _f, metrics = self.run_scan([_sqli_finding()])
        self.assertEqual(len(visible), 1)
        self.assertEqual(len(self.server.requests), 2)     # no report request after the breaker opened
        self.assertTrue(metrics[-1]["breaker_open"])

    def test_model_text_is_cleaned_and_the_cwe_prefix_is_not_kept_in_the_title(self):
        self.configure(reports=True)
        self.queue("", tp(), '{"remediation": "Use bound parameters.\\u0007\\nSecond step.", '
                             '"name": "CWE-89: Injection"}')
        visible, _f, _m = self.run_scan([_sqli_finding()])
        self.assertNotIn("\x07", visible[0]["mitigation"])
        self.assertEqual(visible[0]["mitigation"].count("\n"), 1)
        self.assertEqual(visible[0]["title"], "Injection")


@skip_unless_llm_present()
class BundledReportMarkerTests(ByoTestBase):
    """The bundled-model path labels model-written advice too (report_source)."""

    EDITION = "pro"

    def scan_with_bundled(self, report):
        with mock.patch("scanner.rag.llm.llm_health", return_value=(True, "ok")), \
             mock.patch("scanner.rag.llm_verifier.verify",
                        return_value=VerifierVerdict("TP", "reaches the sink", 0.9)), \
             mock.patch("scanner.rag.report_enricher.generate_report", return_value=report), \
             mock.patch("scanner.rag.lsast_scanner.run_semgrep", return_value=[_sqli_finding()]), \
             mock.patch("scanner.rag.lsast_scanner.save_findings_to_db"), \
             mock.patch("scanner.rag.lsast_scanner.update_progress"):
            visible, _f = lsast_scan_folder(folder_path="/tmp/code", scan_id="s1", triggered_by="u1")
        return visible[0]

    def test_bundled_enrichment_marks_the_finding_as_ai_written(self):
        f = self.scan_with_bundled(FindingReport("N", "D", "I", "Bundled advice."))
        self.assertEqual(f["mitigation"], "Bundled advice.")
        self.assertEqual(f["report_source"], "ai")
        self.assertEqual(self.server.requests, [])         # no BYO call was made

    def test_bundled_path_without_a_report_leaves_it_unlabelled(self):
        f = self.scan_with_bundled(None)
        self.assertEqual(f.get("report_source", ""), "")
