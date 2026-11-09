#!/usr/bin/env python3
"""Linux process peak RSS for one already-built benchmark executable."""
import json
import os
import subprocess
import sys

report_path, *command = sys.argv[1:]
process = subprocess.Popen(command, stdout=subprocess.PIPE, text=True)
stdout = process.stdout.read()
_, status, usage = os.wait4(process.pid, 0)
process.returncode = os.waitstatus_to_exitcode(status)
if process.returncode:
    raise subprocess.CalledProcessError(process.returncode, command)
print(stdout, end="")
report = json.loads(stdout.splitlines()[-1])
report["processPeakRssKiB"] = usage.ru_maxrss
with open(report_path, "w") as output:
    json.dump(report, output, indent=2)
    output.write("\n")
