#!/usr/bin/env python3
"""Run the Linux test suites in parallel and report verdicts.

Tests self-allocate their real ports (testutil.free_ports) so any
subset can run concurrently. A test passes iff its output contains an
'*_ALL_PASS' or 'ALL PASS' marker. Exit code 0 only when all pass.

usage: python3 runtests.py [-j N|auto] [name-substring ...]

N defaults to auto = number of CPUs; SHADOWLAN_TEST_JOBS overrides too.
"""
import os, re, subprocess, sys, threading

ROOT = os.path.dirname(os.path.abspath(__file__))
FILES = []
for d in (ROOT, os.path.join(ROOT, "hook")):
    for f in sorted(os.listdir(d)):
        if f.startswith("test_") and f.endswith(".py") and f != "test_late.py":
            # test_late drives Wine + the Windows build: only via make test-all
            FILES.append(os.path.join(d, f))

MARK = re.compile(r"[A-Z0-9_]*ALL_PASS|ALL PASS")


def main():
    args = sys.argv[1:]
    jobs = None
    if args and args[0] == "-j":
        jobs_arg = args[1]
        args = args[2:]
        if jobs_arg not in ("auto", "0"):
            jobs = int(jobs_arg)
    if jobs is None:
        env = os.environ.get("SHADOWLAN_TEST_JOBS", "")
        if env.isdigit() and int(env) > 0:
            jobs = int(env)
        else:
            # suites are multi-process and latency-sensitive (lease and
            # watchdog budgets); cap concurrency well below core count
            jobs = max(1, min(4, (os.cpu_count() or 4) // 2))
    files = [f for f in FILES if not args or any(a in os.path.basename(f) for a in args)]

    results = {}
    lock = threading.Lock()

    def _once(path):
        try:
            p = subprocess.run([sys.executable, path], cwd=os.path.dirname(path),
                               capture_output=True, text=True, timeout=400)
            out = p.stdout + p.stderr
            return bool(MARK.search(out)) and p.returncode == 0, out
        except subprocess.TimeoutExpired:
            return False, "TIMEOUT"

    def run(path):
        name = os.path.basename(path)[:-3]
        ok, out = _once(path)
        if not ok:
            # one retry: absorbs the rare kernel race between unrelated
            # processes grabbing a just-freed port; true failures fail twice
            ok, out = _once(path)
            if ok:
                out = "RETRY-recovered\n" + out
        with lock:
            results[name] = ok
            print(("PASS " if ok else "FAIL ") + name, flush=True)
            if not ok:
                tail = [l for l in out.splitlines() if l.strip()][-6:]
                print("  " + "\n  ".join(tail)[:800], flush=True)

    sem = threading.Semaphore(jobs)
    ths = []
    for f in files:
        def w(f=f):
            with sem:
                run(f)
        t = threading.Thread(target=w); t.start(); ths.append(t)
    for t in ths:
        t.join()

    bad = [k for k, v in results.items() if not v]
    print("\n%d/%d passed" % (len(results) - len(bad), len(results)))
    if bad:
        print("failed:", ", ".join(sorted(bad)))
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
