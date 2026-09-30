"""Example 3: rate limits.

A policy caps read_file at 3 allowed calls per 2-second rolling window.
The first three calls run; the next two are denied without reaching the
tool; after the window passes, calls are allowed again. Only calls that
would actually run consume budget: denied calls do not.

Run from the repo root:  python3 examples/03_rate_limits.py
"""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from policy_gate import evaluate, reset_rate_limits, set_policy

set_policy({
    "read_file": {
        "allowed_prefixes": ["/tmp/work/"],
        "rate_limit": {"max_calls": 3, "window_seconds": 2},
    },
})
reset_rate_limits()

for i in range(5):
    d = evaluate("read_file", {"path": "/tmp/work/file%d.txt" % i})
    print("call %d: %s (%s)" % (i + 1, d.decision.upper(), d.reason))

print("waiting for the window to pass...")
time.sleep(2.1)
d = evaluate("read_file", {"path": "/tmp/work/file5.txt"})
print("call 6: %s (%s)" % (d.decision.upper(), d.reason))
