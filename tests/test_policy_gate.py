"""Tests for policy_gate.py — the gate must fail closed, never throw,
and log every decision with a reason."""

import json
import os
import tempfile
import unittest

import policy_gate as pg


class TestReadFile(unittest.TestCase):
    def test_allowed_inside_prefix(self):
        allowed, reason = pg.check_call("read_file", {"path": "/tmp/work/notes.txt"})
        self.assertTrue(allowed)
        self.assertIn("allowed prefix", reason)

    def test_prefix_directory_itself_matches(self):
        allowed, _ = pg.check_call("read_file", {"path": "/tmp/work"})
        self.assertTrue(allowed)

    def test_denied_outside_prefix(self):
        allowed, reason = pg.check_call("read_file", {"path": "/etc/passwd"})
        self.assertFalse(allowed)
        self.assertIn("/etc/passwd", reason)

    def test_prefix_sibling_attack_denied(self):
        # /tmp/workevil must not sneak past a /tmp/work/ prefix.
        allowed, _ = pg.check_call("read_file", {"path": "/tmp/workevil/notes.txt"})
        self.assertFalse(allowed)

    def test_missing_path_denied_not_raised(self):
        allowed, reason = pg.check_call("read_file", {})
        self.assertFalse(allowed)
        self.assertIn("outside allowed prefixes", reason)

    def test_non_string_path_denied(self):
        allowed, _ = pg.check_call("read_file", {"path": None})
        self.assertFalse(allowed)


class TestRunShell(unittest.TestCase):
    def test_allowlisted_command_allowed(self):
        allowed, reason = pg.check_call("run_shell", {"command": "ls /tmp/work"})
        self.assertTrue(allowed)
        self.assertIn("allowlisted", reason)

    def test_rm_rf_blocked_by_pattern(self):
        allowed, reason = pg.check_call("run_shell", {"command": "rm -rf /tmp/work"})
        self.assertFalse(allowed)
        self.assertIn("blocked pattern", reason)

    def test_shell_metacharacters_blocked(self):
        for cmd in (
            "ls /tmp/work; cat /etc/passwd",
            "ls /tmp/work && cat /etc/passwd",
            "ls /tmp/work || cat /etc/passwd",
            "ls `cat /etc/passwd`",
            "ls $(cat /etc/passwd)",
        ):
            with self.subTest(cmd=cmd):
                allowed, reason = pg.check_call("run_shell", {"command": cmd})
                self.assertFalse(allowed, cmd)
                self.assertIn("blocked pattern", reason, cmd)

    def test_non_allowlisted_command_denied(self):
        allowed, reason = pg.check_call("run_shell", {"command": "curl http://evil.example"})
        self.assertFalse(allowed)
        self.assertIn("not allowlisted", reason)

    def test_absolute_arg_outside_prefix_denied(self):
        allowed, reason = pg.check_call("run_shell", {"command": "cat /etc/passwd"})
        self.assertFalse(allowed)
        self.assertIn("outside allowed prefixes", reason)

    def test_empty_command_denied(self):
        allowed, _ = pg.check_call("run_shell", {"command": ""})
        self.assertFalse(allowed)


class TestSendEmail(unittest.TestCase):
    def test_allowlisted_domain_allowed(self):
        allowed, reason = pg.check_call(
            "send_email", {"to": "teammate@internal.example.com"}
        )
        self.assertTrue(allowed)
        self.assertIn("allowlisted", reason)

    def test_external_recipient_denied(self):
        allowed, reason = pg.check_call("send_email", {"to": "attacker@evil.com"})
        self.assertFalse(allowed)
        self.assertIn("attacker@evil.com", reason)

    def test_lookalike_domain_denied(self):
        allowed, _ = pg.check_call(
            "send_email", {"to": "attacker@internal.example.com.evil.com"}
        )
        self.assertFalse(allowed)


class TestDenyByDefault(unittest.TestCase):
    def test_unknown_tool_denied(self):
        allowed, reason = pg.check_call("delete_user", {"id": "root"})
        self.assertFalse(allowed)
        self.assertIn("unknown tool", reason)

    def test_none_args_never_throws(self):
        allowed, _ = pg.check_call("read_file", None)
        self.assertFalse(allowed)

    def test_missing_args_dict_never_throws(self):
        allowed, _ = pg.check_call("send_email", {})
        self.assertFalse(allowed)


class TestDispatch(unittest.TestCase):
    def setUp(self):
        pg.AUDIT_LOG.clear()

    def test_denied_call_never_reaches_tool(self):
        calls = []

        def spy(args):
            calls.append(args)
            return "executed"

        original = pg.TOOLS["read_file"]
        pg.TOOLS["read_file"] = spy
        try:
            result = pg.dispatch("read_file", {"path": "/etc/passwd"})
        finally:
            pg.TOOLS["read_file"] = original
        self.assertTrue(result.startswith("DENIED:"))
        self.assertEqual(calls, [])

    def test_allowed_call_reaches_tool(self):
        result = pg.dispatch("read_file", {"path": "/tmp/work/notes.txt"})
        self.assertIn("stubbed", result)

    def test_every_dispatch_is_logged(self):
        pg.dispatch("read_file", {"path": "/tmp/work/notes.txt"})
        pg.dispatch("delete_user", {"id": "root"})
        self.assertEqual(len(pg.AUDIT_LOG), 2)
        self.assertEqual(pg.AUDIT_LOG[0]["decision"], "allow")
        self.assertEqual(pg.AUDIT_LOG[1]["decision"], "deny")


class TestAuditLog(unittest.TestCase):
    def setUp(self):
        pg.AUDIT_LOG.clear()

    def test_entry_has_all_fields(self):
        pg.log_decision("read_file", {"path": "/tmp/work/x"}, True, "ok")
        entry = pg.AUDIT_LOG[0]
        for field in ("timestamp", "tool", "args", "decision", "reason"):
            self.assertIn(field, entry)
        self.assertEqual(entry["tool"], "read_file")
        self.assertEqual(entry["decision"], "allow")
        # Timestamp parses as ISO-8601 and carries UTC offset.
        self.assertIn("+00:00", entry["timestamp"])

    def test_flush_writes_json_lines(self):
        pg.log_decision("read_file", {"path": "/tmp/work/x"}, True, "ok")
        pg.log_decision("run_shell", {"command": "rm -rf /"}, False, "blocked")
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "audit.log")
            pg.flush_audit(path)
            with open(path) as f:
                lines = f.read().splitlines()
        self.assertEqual(len(lines), 2)
        first = json.loads(lines[0])
        self.assertEqual(first["decision"], "allow")
        self.assertEqual(json.loads(lines[1])["decision"], "deny")


class TestDemo(unittest.TestCase):
    def test_demo_produces_three_allows_four_denies(self):
        pg.AUDIT_LOG.clear()
        with tempfile.TemporaryDirectory() as tmp:
            cwd = os.getcwd()
            os.chdir(tmp)
            try:
                pg.demo()
                decisions = [e["decision"] for e in pg.AUDIT_LOG]
                self.assertEqual(decisions.count("allow"), 3)
                self.assertEqual(decisions.count("deny"), 4)
                self.assertTrue(os.path.exists(os.path.join(tmp, "audit.log")))
            finally:
                os.chdir(cwd)
                pg.AUDIT_LOG.clear()


if __name__ == "__main__":
    unittest.main()
