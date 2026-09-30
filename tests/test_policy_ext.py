"""Tests for the extended gate: evaluate(), approval flow, rate limits,
policy loading/validation, the gated decorator, and the new rule types."""

import copy
import json
import os
import tempfile
import time
import unittest

import policy_gate as pg

try:
    import yaml  # noqa: F401
    HAS_YAML = True
except ImportError:
    HAS_YAML = False


class GateStateMixin:
    """Save and restore all module-level gate state around each test."""

    def setUp(self):
        self._policy = copy.deepcopy(pg.POLICY)
        self._tools = dict(pg.TOOLS)
        pg.AUDIT_LOG.clear()
        pg.reset_rate_limits()

    def tearDown(self):
        pg.POLICY.clear()
        pg.POLICY.update(self._policy)
        pg.TOOLS.clear()
        pg.TOOLS.update(self._tools)
        pg.AUDIT_LOG.clear()
        pg.reset_rate_limits()


class TestEvaluate(GateStateMixin, unittest.TestCase):
    def test_allow_returns_decision_object(self):
        d = pg.evaluate("read_file", {"path": "/tmp/work/notes.txt"})
        self.assertEqual(d.decision, pg.ALLOW)
        self.assertEqual(d.tool, "read_file")
        self.assertEqual(d.args, {"path": "/tmp/work/notes.txt"})
        self.assertTrue(d.reason)

    def test_deny_returns_decision_object(self):
        d = pg.evaluate("read_file", {"path": "/etc/passwd"})
        self.assertEqual(d.decision, pg.DENY)

    def test_needs_approval_decision(self):
        pg.POLICY["send_email"]["approval_patterns"] = [".*"]
        d = pg.evaluate("send_email", {"to": "a@internal.example.com"})
        self.assertEqual(d.decision, pg.NEEDS_APPROVAL)
        self.assertIn("approval pattern", d.reason)

    def test_needs_approval_for_whole_tool(self):
        pg.POLICY["read_file"]["needs_approval"] = True
        d = pg.evaluate("read_file", {"path": "/tmp/work/notes.txt"})
        self.assertEqual(d.decision, pg.NEEDS_APPROVAL)

    def test_denied_calls_never_ask_for_approval(self):
        # A call that would be denied anyway must not become needs_approval.
        pg.POLICY["send_email"]["approval_patterns"] = [".*"]
        d = pg.evaluate("send_email", {"to": "attacker@evil.com"})
        self.assertEqual(d.decision, pg.DENY)

    def test_check_call_maps_approval_to_false(self):
        pg.POLICY["send_email"]["approval_patterns"] = [".*"]
        allowed, reason = pg.check_call(
            "send_email", {"to": "a@internal.example.com"}
        )
        self.assertFalse(allowed)
        self.assertIn("approval", reason)

    def test_non_dict_args_never_throws(self):
        d = pg.evaluate("read_file", ["not", "a", "dict"])
        self.assertEqual(d.decision, pg.DENY)

    def test_required_args(self):
        d = pg.evaluate("run_shell", {})
        self.assertEqual(d.decision, pg.DENY)
        self.assertIn("missing required argument 'command'", d.reason)

    def test_tool_with_policy_but_no_implementation_denied(self):
        pg.POLICY["ghost_tool"] = {"allowed": True}
        d = pg.evaluate("ghost_tool", {})
        self.assertEqual(d.decision, pg.DENY)
        self.assertIn("no registered implementation", d.reason)


class TestNewRuleTypes(GateStateMixin, unittest.TestCase):
    def test_blocked_path_beats_allowed_prefix(self):
        d = pg.evaluate("read_file", {"path": "/tmp/work/secrets/api.key"})
        self.assertEqual(d.decision, pg.DENY)
        self.assertIn("blocked", d.reason)

    def test_blocked_recipient_beats_allowed_domain(self):
        d = pg.evaluate("send_email", {"to": "root@internal.example.com"})
        self.assertEqual(d.decision, pg.DENY)
        self.assertIn("blocked", d.reason)

    def test_max_command_length(self):
        d = pg.evaluate("run_shell", {"command": "ls " + "x" * 500})
        self.assertEqual(d.decision, pg.DENY)
        self.assertIn("max length", d.reason)

    def test_generic_tool_explicit_allow(self):
        pg.register_tool("calc", lambda args: "42", {"allowed": True})
        d = pg.evaluate("calc", {"expr": "1+1"})
        self.assertEqual(d.decision, pg.ALLOW)

    def test_generic_tool_blocked_pattern(self):
        pg.register_tool(
            "calc",
            lambda args: "42",
            {"allowed": True, "blocked_patterns": [r"__"]},
        )
        d = pg.evaluate("calc", {"expr": "__import__('os')"})
        self.assertEqual(d.decision, pg.DENY)
        self.assertIn("blocked pattern", d.reason)


class TestApprovalDispatch(GateStateMixin, unittest.TestCase):
    def setUp(self):
        super().setUp()
        pg.POLICY["send_email"]["approval_patterns"] = [".*"]

    def test_no_approver_fails_closed(self):
        calls = []
        pg.TOOLS["send_email"] = lambda args: calls.append(args) or "sent"
        result = pg.dispatch("send_email", {"to": "a@internal.example.com"})
        self.assertTrue(result.startswith("DENIED:"))
        self.assertIn("no approver", result)
        self.assertEqual(calls, [])

    def test_approver_yes_runs_tool_and_logs_approval(self):
        result = pg.dispatch(
            "send_email",
            {"to": "a@internal.example.com", "subject": "hi"},
            approver=lambda decision: True,
        )
        self.assertIn("stub: email", result)
        entry = pg.AUDIT_LOG[-1]
        self.assertEqual(entry["decision"], "allow")
        self.assertIn("approved by operator", entry["reason"])

    def test_approver_no_denies_and_logs(self):
        result = pg.dispatch(
            "send_email",
            {"to": "a@internal.example.com"},
            approver=lambda decision: False,
        )
        self.assertTrue(result.startswith("DENIED:"))
        entry = pg.AUDIT_LOG[-1]
        self.assertEqual(entry["decision"], "deny")
        self.assertIn("approval denied by operator", entry["reason"])

    def test_approver_receives_the_decision(self):
        seen = []
        pg.dispatch(
            "send_email",
            {"to": "a@internal.example.com"},
            approver=lambda decision: seen.append(decision) or True,
        )
        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0].decision, pg.NEEDS_APPROVAL)


class TestRateLimits(GateStateMixin, unittest.TestCase):
    def setUp(self):
        super().setUp()
        pg.POLICY["read_file"]["rate_limit"] = {
            "max_calls": 2,
            "window_seconds": 60,
        }

    def test_allows_up_to_max_then_denies(self):
        args = {"path": "/tmp/work/a.txt"}
        self.assertEqual(pg.evaluate("read_file", args).decision, pg.ALLOW)
        self.assertEqual(pg.evaluate("read_file", args).decision, pg.ALLOW)
        d = pg.evaluate("read_file", args)
        self.assertEqual(d.decision, pg.DENY)
        self.assertIn("rate limit exceeded", d.reason)

    def test_denied_calls_do_not_consume_budget(self):
        pg.evaluate("read_file", {"path": "/etc/passwd"})  # denied
        pg.evaluate("read_file", {"path": "/etc/shadow"})  # denied
        args = {"path": "/tmp/work/a.txt"}
        self.assertEqual(pg.evaluate("read_file", args).decision, pg.ALLOW)
        self.assertEqual(pg.evaluate("read_file", args).decision, pg.ALLOW)
        self.assertEqual(pg.evaluate("read_file", args).decision, pg.DENY)

    def test_budget_refills_after_window(self):
        pg.POLICY["read_file"]["rate_limit"] = {
            "max_calls": 1,
            "window_seconds": 0.2,
        }
        args = {"path": "/tmp/work/a.txt"}
        self.assertEqual(pg.evaluate("read_file", args).decision, pg.ALLOW)
        self.assertEqual(pg.evaluate("read_file", args).decision, pg.DENY)
        time.sleep(0.25)
        self.assertEqual(pg.evaluate("read_file", args).decision, pg.ALLOW)

    def test_reset_rate_limits_clears_budget(self):
        args = {"path": "/tmp/work/a.txt"}
        pg.evaluate("read_file", args)
        pg.evaluate("read_file", args)
        self.assertEqual(pg.evaluate("read_file", args).decision, pg.DENY)
        pg.reset_rate_limits()
        self.assertEqual(pg.evaluate("read_file", args).decision, pg.ALLOW)


class TestPolicyLoading(GateStateMixin, unittest.TestCase):
    def _write(self, tmp, name, text):
        path = os.path.join(tmp, name)
        with open(path, "w") as f:
            f.write(text)
        return path

    def test_load_json_policy(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(
                tmp, "p.json", json.dumps({"read_file": {"allowed": True}})
            )
            policy = pg.load_policy(path)
        self.assertEqual(policy, {"read_file": {"allowed": True}})

    @unittest.skipUnless(HAS_YAML, "PyYAML not installed")
    def test_load_yaml_policy(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(
                tmp, "p.yaml", "read_file:\n  allowed: true\n"
            )
            policy = pg.load_policy(path)
        self.assertEqual(policy, {"read_file": {"allowed": True}})

    def test_load_rejects_unknown_extension(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(tmp, "p.toml", "x = 1")
            with self.assertRaises(ValueError):
                pg.load_policy(path)

    def test_load_validates_before_returning(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(
                tmp, "p.json", json.dumps({"read_file": {"bogus_rule": 1}})
            )
            with self.assertRaises(ValueError):
                pg.load_policy(path)

    def test_set_policy_swaps_live_policy(self):
        pg.register_tool("shout", lambda args: args["text"].upper())
        pg.set_policy({"shout": {"allowed": True}})
        self.assertNotIn("run_shell", pg.POLICY)
        d = pg.evaluate("shout", {"text": "hi"})
        self.assertEqual(d.decision, pg.ALLOW)

    def test_set_policy_rejects_bad_policy_and_keeps_old(self):
        with self.assertRaises(ValueError):
            pg.set_policy({"read_file": {"bogus_rule": 1}})
        self.assertIn("run_shell", pg.POLICY)


class TestValidatePolicy(unittest.TestCase):
    def test_unknown_rule_key_rejected(self):
        with self.assertRaises(ValueError) as cm:
            pg.validate_policy({"run_shell": {"allowlist_commands": ["ls"]}})
        self.assertIn("unknown rule", str(cm.exception))

    def test_bad_regex_rejected(self):
        with self.assertRaises(ValueError) as cm:
            pg.validate_policy({"send_email": {"allowed_recipients": ["([bad"]}})
        self.assertIn("bad regex", str(cm.exception))

    def test_non_string_in_string_list_rejected(self):
        with self.assertRaises(ValueError):
            pg.validate_policy({"read_file": {"allowed_prefixes": [42]}})

    def test_bad_rate_limit_rejected(self):
        for spec in (
            {"max_calls": 0, "window_seconds": 60},
            {"max_calls": 5, "window_seconds": -1},
            {"max_calls": "many", "window_seconds": 60},
            "not-a-dict",
        ):
            with self.subTest(spec=spec):
                with self.assertRaises(ValueError):
                    pg.validate_policy({"read_file": {"rate_limit": spec}})

    def test_non_bool_needs_approval_rejected(self):
        with self.assertRaises(ValueError):
            pg.validate_policy({"x": {"needs_approval": "yes"}})

    def test_non_dict_policy_rejected(self):
        with self.assertRaises(ValueError):
            pg.validate_policy(["not", "a", "dict"])

    def test_valid_policy_returned_unchanged(self):
        policy = {"read_file": {"allowed_prefixes": ["/tmp/work/"]}}
        self.assertIs(pg.validate_policy(policy), policy)


class TestRegisterTool(GateStateMixin, unittest.TestCase):
    def test_registered_tool_without_policy_is_denied(self):
        pg.register_tool("shout", lambda args: args["text"].upper())
        d = pg.evaluate("shout", {"text": "hi"})
        self.assertEqual(d.decision, pg.DENY)
        self.assertIn("unknown tool", d.reason)

    def test_register_tool_with_policy_entry(self):
        pg.register_tool(
            "shout", lambda args: args["text"].upper(), {"allowed": True}
        )
        self.assertEqual(
            pg.dispatch("shout", {"text": "hi"}), "HI"
        )

    def test_register_tool_validates_entry(self):
        with self.assertRaises(ValueError):
            pg.register_tool("shout", lambda args: "x", {"bogus": True})
        self.assertNotIn("shout", pg.TOOLS)


class TestGatedDecorator(GateStateMixin, unittest.TestCase):
    def test_decorated_tool_denied_without_policy(self):
        def summarize(args):
            return "summary"

        gated_summarize = pg.gated("summarize")(summarize)
        result = gated_summarize({"path": "/tmp/work/notes.txt"})
        self.assertTrue(result.startswith("DENIED:"))

    def test_decorated_tool_runs_with_policy(self):
        def summarize(args):
            return "summary of %s" % args["path"]

        gated_summarize = pg.gated("summarize")(summarize)
        pg.register_tool("summarize", summarize, {"allowed": True})
        result = gated_summarize({"path": "/tmp/work/notes.txt"})
        self.assertIn("summary of /tmp/work/notes.txt", result)

    def test_decorator_uses_function_name_by_default(self):
        def my_tool(args):
            return "ran"

        wrapped = pg.gated()(my_tool)
        self.assertEqual(wrapped.__name__, "my_tool")
        self.assertIn("my_tool", pg.TOOLS)
        self.assertTrue(wrapped({}).startswith("DENIED:"))

    def test_decorator_passes_approver_through(self):
        def release(args):
            return "released"

        gated_release = pg.gated("release", approver=lambda d: True)(release)
        pg.register_tool(
            "release", release, {"allowed": True, "needs_approval": True}
        )
        self.assertEqual(gated_release({"v": "1"}), "released")


if __name__ == "__main__":
    unittest.main()
