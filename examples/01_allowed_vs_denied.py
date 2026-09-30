"""Example 1: allowed vs denied.

Runs a batch of tool calls through the gate and prints each decision
with its reason. Shows allowlists, denylists, and deny-by-default.

Run from the repo root:  python3 examples/01_allowed_vs_denied.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from policy_gate import dispatch

CALLS = [
    ("read_file", {"path": "/tmp/work/notes.txt"}),
    ("run_shell", {"command": "ls /tmp/work"}),
    ("send_email", {"to": "teammate@internal.example.com", "subject": "hi"}),
    # Denied: a denylist beats the allowlist.
    ("read_file", {"path": "/tmp/work/secrets/api.key"}),
    ("send_email", {"to": "root@internal.example.com", "subject": "hi"}),
    # Denied: command injection and an external recipient.
    ("run_shell", {"command": "rm -rf /tmp/work"}),
    ("send_email", {"to": "attacker@evil.com", "subject": "hi"}),
    # Denied: the tool is not in the policy at all.
    ("drop_table", {"table": "users"}),
]

for tool, args in CALLS:
    print("%-10s %-50s" % (tool, args))
    print("  -> %s" % dispatch(tool, args))
