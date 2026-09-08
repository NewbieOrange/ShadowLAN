#!/usr/bin/env python3
"""Process-tree identity: parent + child share ONE node (one vnode).

The hook generates node_id once, publishes it into its own environment
(LAN_HOOK_NODE), and every descendant inherits it — the Windows analogue
is a kernel-created (not manually mapped) file section per process tree,
so there is never a "who is last" question: identity lifetime == tree
lifetime. Verified here:

  1. parent's hook line is "identity pid=.. node=N" (generated), the
     env-inheriting child's is "... node=N (inherited)" with SAME N;
  2. a child launched with a forced-copy env lacking LAN_HOOK_NODE gets
     a DIFFERENT node (tree scoping is by environment, so unrelated
     roots stay separate machines — the P2P tests rely on this);
  3. while both tree members are alive, the relay holds exactly ONE node
     carrying TWO links.
"""
import asyncio
import os
import re
import sys
import tempfile

HOOKDIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HOOKDIR))
from server import Relay

HOOK = os.path.join(HOOKDIR, "lan_hook.so")
PUB = 47841

CHILD = r"""
import socket, time, sys, os
print("child-env-node:", os.environ.get("LAN_HOOK_NODE"), flush=True)
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
u.bind(("127.0.0.1", 0))
u.sendto(b"member-probe", ("127.0.0.1", 9))
time.sleep(float(sys.argv[2]))
print("CHILD_ALIVE_OK", flush=True)
"""

PARENT = r"""
import socket, subprocess, sys, time, os
base = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
base.bind(("127.0.0.1", int(sys.argv[1])))
base.sendto(b"tree-probe", ("127.0.0.1", 9))   # drive the hook into action
time.sleep(0.5)
# inherit (env=None): must see the hook-published LAN_HOOK_NODE
c1 = subprocess.Popen([sys.executable, sys.argv[2], sys.argv[1], "3"],
                      stdout=sys.stdout, stderr=sys.stderr)
# forced-copy env WITHOUT LAN_HOOK_NODE: must start a separate identity,
# but stay alive as long as c1 so the relay peak-sampler can observe it
stripped = {k: v for k, v in os.environ.items() if k != "LAN_HOOK_NODE"}
c2 = subprocess.Popen([sys.executable, sys.argv[2], sys.argv[1], "2.2"],
                      env=stripped, stdout=sys.stdout, stderr=sys.stderr)
time.sleep(1.0)   # both children registered by now; sample window ~1.5s
c1.wait(); c2.wait()
print("PARENT_DONE", flush=True)
"""


async def main():
    relay = Relay(PUB, token="", bind="127.0.0.1")
    relay_task = asyncio.create_task(relay.run())
    await asyncio.sleep(0.3)

    peak = {"links": 0, "nodes": 0}

    async def sampler():
        while True:
            peak["links"] = max([peak["links"]] +
                                [len(e["links"]) for e in relay.nodes.values()])
            peak["nodes"] = max([peak["nodes"]] + [len(relay.nodes)])
            await asyncio.sleep(0.2)

    samp = asyncio.create_task(sampler())
    try:
        with tempfile.TemporaryDirectory() as tmp:
            child = os.path.join(tmp, "child_member.py")
            parent = os.path.join(tmp, "parent_root.py")
            open(child, "w").write(CHILD)
            open(parent, "w").write(PARENT)
            env = dict(os.environ, LD_PRELOAD=HOOK,
                       LAN_HOOK_SERVER="127.0.0.1",
                       LAN_HOOK_PORT=str(PUB), LAN_HOOK_DEBUG="1")
            proc = await asyncio.create_subprocess_exec(
                sys.executable, parent, str(PUB + 10), child,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT, env=env)
            try:
                out, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
            except asyncio.TimeoutError:
                proc.kill()
                print("FAIL: hung")
                sys.exit(1)
            text = out.decode(errors="replace")
    finally:
        samp.cancel()
        await asyncio.gather(samp, return_exceptions=True)

    ids = re.findall(r"identity pid=(\d+) node=(\d+)( \(inherited\))?", text)
    assert ids, "no identity lines:\n" + text
    ordered = [(pid, int(node), bool(inh)) for pid, node, inh in ids]
    print("identities (in init order):", ordered, flush=True)
    assert len(ordered) == 3, ordered          # parent + 2 children
    ppid, pnode, pinh = ordered[0]             # the root initializes first
    assert not pinh, "parent identity should be generated, not inherited"
    kids = ordered[1:]
    inh = [k for k in kids if k[2]]
    fresh = [k for k in kids if not k[2]]
    assert len(inh) == 1 and len(fresh) == 1, \
        f"expected one inherited + one fresh child: {ordered}"
    assert inh[0][1] == pnode, "inheriting child did not share the parent node"
    assert fresh[0][1] != pnode, "stripped-env child wrongly reused parent node"
    child_env = sorted(re.findall(r"child-env-node: (\S+)", text))
    assert child_env == sorted([str(pnode), "None"]), child_env
    print("PASS[hook] env-inheriting child shares the parent node; "
          "stripped-env child gets its own", flush=True)

    assert peak["links"] == 2, f"expected 2 links on the tree node, saw {peak}"
    print("PASS[relay] tree node held exactly 2 links under one vnode",
          flush=True)
    print("TREEID_ALL_PASS", flush=True)
    relay_task.cancel()
    await asyncio.gather(relay_task, return_exceptions=True)



async def _guarded():
    """Hard watchdog: a stuck future must fail loudly in <=20s, never
    pin the suite (Python 3.12 wait_closed and co. can swallow hangs)."""
    await asyncio.wait_for(main(), timeout=20)


if __name__ == "__main__":
    asyncio.run(_guarded())
