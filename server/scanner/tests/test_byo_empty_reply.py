"""A reasoning model can spend its whole reply budget thinking and answer with nothing. That used to be
a hard failure: five in a row opened the circuit breaker and every remaining finding was left unverified
(seen with a z-ai GLM model on OpenRouter: 4 verified, 89 unverified). The provider now retries an empty
reply with a bigger budget and remembers the budget that worked."""
import threading

from scanner.byo_llm.client import ByoClient
from scanner.byo_llm.providers.base import ProviderBadResponse, ProviderEmptyReply
from scanner.tests.test_byo_providers import ProviderTestBase


class EmptyReplyBudgetTests(ProviderTestBase):
    def empty(self, finish="length"):
        self.server.reply(200, {
            "choices": [{"message": {"role": "assistant", "content": ""}, "finish_reason": finish}],
            "usage": {"prompt_tokens": 40, "completion_tokens": 512},
        })

    def sent(self):
        return [r["json"]["max_tokens"] for r in self.server.requests]

    def test_empty_reply_is_retried_with_a_bigger_budget(self):
        self.empty()
        self.server.reply_openai('{"verdict":"TP"}')
        res = self.provider().complete_json("s", "u", 512)
        self.assertEqual(res.text, '{"verdict":"TP"}')
        self.assertEqual(self.sent(), [512, 2048])

    def test_the_budget_that_worked_is_remembered_for_the_next_calls(self):
        self.empty()
        self.server.reply_openai('{"verdict":"TP"}')
        provider = self.provider()
        provider.complete_json("s", "u", 512)
        self.server.reply_openai('{"verdict":"FP"}')
        provider.complete_json("s", "u", 512)
        # two findings cost three requests, not four: the second starts from the learned budget
        self.assertEqual(self.sent(), [512, 2048, 2048])

    def test_escalates_to_the_cap_then_fails_with_a_message_that_says_what_to_do(self):
        for _ in range(3):
            self.empty()
        with self.assertRaises(ProviderEmptyReply) as ctx:
            self.provider().complete_json("s", "u", 512)
        self.assertEqual(self.sent(), [512, 2048, 4096])
        self.assertIsInstance(ctx.exception, ProviderBadResponse)
        self.assertIn("reasoning model", str(ctx.exception))
        self.assertIn("answers directly", str(ctx.exception))

    def test_a_larger_requested_budget_is_never_reduced_and_stays_under_the_cap(self):
        for _ in range(3):
            self.empty()
        with self.assertRaises(ProviderEmptyReply):
            self.provider().complete_json("s", "u", 900)      # the mitigation-advice budget
        self.assertEqual(self.sent(), [900, 3600, 4096])

    def test_a_connection_test_that_may_be_empty_does_not_escalate(self):
        self.empty()
        self.provider().ping()
        self.assertEqual(self.sent(), [64])

    def test_a_normal_reply_never_escalates(self):
        self.server.reply_openai('{"verdict":"TP"}')
        self.provider().complete_json("s", "u", 512)
        self.assertEqual(self.sent(), [512])


class ClientSurvivesAReasoningModelTests(ProviderTestBase):
    def test_empty_replies_no_longer_open_the_circuit_breaker(self):
        # Six findings. The first reply is empty (budget exhausted), after that the model answers.
        self.server.reply(200, {"choices": [{"message": {"content": ""}, "finish_reason": "length"}]})
        for _ in range(6):
            self.server.reply_openai('{"verdict":"TP","reason":"x","confidence":0.9}')
        client = ByoClient(self.provider(), max_concurrency=1)
        for _ in range(6):
            client.complete_json("s", "u")
        self.assertFalse(client.tripped)
        self.assertEqual(client.stats.failures, 0)
        self.assertEqual(client.stats.calls, 6)
        self.assertEqual(len(self.server.requests), 7)         # one wasted attempt in total

    def test_a_model_that_never_answers_still_trips_the_breaker_with_the_clear_message(self):
        for _ in range(5 * 3):
            self.server.reply(200, {"choices": [{"message": {"content": ""}, "finish_reason": "length"}]})
        client = ByoClient(self.provider(), max_concurrency=1, breaker_threshold=5)
        from scanner.byo_llm.client import ByoCallFailed
        for _ in range(5):
            with self.assertRaises(ByoCallFailed):
                client.complete_json("s", "u")
        self.assertTrue(client.tripped)
        self.assertIn("reasoning model", client.trip_reason)


class ParallelWorkersEscalateOnceTests(ProviderTestBase):
    """The scanner's workers share one provider. Workers that fail at the same step must raise the
    budget once between them, not once each (two workers used to jump from x1 straight to x8)."""

    def test_escalation_is_compare_and_set(self):
        provider = self.provider()
        self.assertTrue(provider._escalate(0))
        self.assertEqual(provider._budget_step, 1)
        self.assertTrue(provider._escalate(0))          # a second worker that also failed at step 0
        self.assertEqual(provider._budget_step, 1)      # ... does not raise it again
        self.assertTrue(provider._escalate(1))
        self.assertEqual(provider._budget_step, 2)
        self.assertFalse(provider._escalate(2))         # nothing above the top step
        self.assertEqual(provider._budget_step, 2)
        self.assertTrue(provider._escalate(1))          # a late worker from a lower step just retries
        self.assertEqual(provider._budget_step, 2)

    def test_two_workers_failing_together_raise_the_budget_once(self):
        empty = {"choices": [{"message": {"content": ""}, "finish_reason": "length"}]}
        for _ in range(2):                              # both first attempts are in flight at once
            self.server.reply(200, empty, delay=0.4)
        for _ in range(2):
            self.server.reply_openai('{"verdict":"TP"}')
        provider = self.provider()
        results = []
        workers = [threading.Thread(target=lambda: results.append(provider.complete_json("s", "u", 512).text))
                   for _ in range(2)]
        for w in workers:
            w.start()
        for w in workers:
            w.join(30)
        self.assertEqual(results, ['{"verdict":"TP"}'] * 2)
        self.assertEqual(provider._budget_step, 1)
        sent = sorted(r["json"]["max_tokens"] for r in self.server.requests)
        self.assertEqual(sent, [512, 512, 2048, 2048])   # never 4096: it did not escalate twice
