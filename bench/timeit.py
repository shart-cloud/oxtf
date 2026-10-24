#!/usr/bin/env python3
"""Run a command and print wall time, CPU time and peak RSS (GNU time stand-in).

Usage: timeit.py LABEL STDOUT_FILE -- CMD...
"""
import resource, subprocess, sys, time

def rss_bytes(maxrss, platform=sys.platform):
    """getrusage reports bytes on macOS and KiB on other supported Unix hosts."""
    return int(maxrss) if platform == "darwin" else int(maxrss) * 1024


label, out = sys.argv[1], sys.argv[2]
cmd = sys.argv[sys.argv.index("--") + 1:]
t0 = time.perf_counter()
with open(out, "wb") as f:
    rc = subprocess.run(cmd, stdout=f, stderr=subprocess.DEVNULL).returncode
wall = time.perf_counter() - t0
ru = resource.getrusage(resource.RUSAGE_CHILDREN)
print(f"{label} wall={wall:.2f}s user={ru.ru_utime:.2f}s sys={ru.ru_stime:.2f}s maxrss={rss_bytes(ru.ru_maxrss)}B rc={rc}", flush=True)
