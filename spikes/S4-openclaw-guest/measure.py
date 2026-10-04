#!/usr/bin/env python3
"""measure.py <out-file> cmd... : run cmd, write wall seconds and peak child RSS."""
import resource
import subprocess
import sys
import time

t = time.monotonic()
rc = subprocess.call(sys.argv[2:])
peak_kb = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
with open(sys.argv[1], "w") as f:
    f.write("%.2f s wall, %d KB peak RSS (largest single process)\n" % (time.monotonic() - t, peak_kb))
sys.exit(rc)
