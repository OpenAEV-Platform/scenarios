"""Run a command and write its peak resident size, in KiB, to the file named first.

The peak a process reports includes, on Linux, the one of the process it was started from, up to
its exec: started from the test's process, the tools would count the test's memory as theirs.
Started from this small process instead, they count little more than their own. Standard library
only, run with ``python -I``.
"""

import os
import subprocess
import sys
from pathlib import Path

report, *command = sys.argv[1:]
child = subprocess.Popen(command)  # noqa: S603 - the command the test gives
_, status, usage = os.wait4(child.pid, 0)
child.returncode = os.waitstatus_to_exitcode(status)  # reaped here, for its resources
Path(report).write_text(str(usage.ru_maxrss), encoding="ascii")
sys.exit(child.returncode)
