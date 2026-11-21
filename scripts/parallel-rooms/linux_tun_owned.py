"""Original same-parent anchors pin eleven bounded run-owned process groups."""
from __future__ import annotations

import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import time

MAX_GROUPS = 11
MAX_HANDLES = MAX_GROUPS * 2
READY = b"linux-tun-group-ready\n"
ANCHOR = (
    "import os,signal\n"
    "signal.signal(signal.SIGTERM,signal.SIG_IGN)\n"
    "signal.signal(signal.SIGINT,signal.SIG_IGN)\n"
    f"os.write(1,{READY!r})\n"
    "while True: signal.pause()\n"
)


def wait_ready(anchor: subprocess.Popen, end: float) -> None:
    # No poll/wait/reap of the original anchor, including EOF and timeout.
    os.set_blocking(anchor.stdout.fileno(), False)
    pending = bytearray()
    with selectors.DefaultSelector() as selector:
        selector.register(anchor.stdout, selectors.EVENT_READ)
        while time.monotonic() < end:
            if selector.select(min(.02, max(0, end - time.monotonic()))):
                data = os.read(anchor.stdout.fileno(), len(READY) + 1)
                if not data:
                    raise RuntimeError("original anchor ended before readiness")
                pending.extend(data)
                if not READY.startswith(pending):
                    raise RuntimeError("original anchor malformed readiness")
                if pending == READY:
                    return
    raise TimeoutError("original anchor readiness deadline")


class OwnedGroups:
    def __init__(self) -> None:
        self.owners: list[dict] = []
        self.cleaned: list[dict] | None = None

    def spawn(self, role: str, argv: list[str], log: Path, *, env: dict[str, str],
              token: str | None = None, socket_tool: bool = False) -> subprocess.Popen:
        if self.cleaned is not None or len(self.owners) >= MAX_GROUPS:
            raise RuntimeError("original process registry closed or full")
        if any(owner["role"] == role for owner in self.owners):
            raise ValueError("duplicate original child role")
        descriptor = os.open(log, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        output = os.fdopen(descriptor, "w")
        owner = {"role": role, "anchor": None, "child": None, "log": output,
                 "socket_tool": socket_tool, "signals": []}
        self.owners.append(owner)
        anchor = subprocess.Popen([sys.executable, "-u", "-c", ANCHOR],
                                  stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                  stderr=subprocess.DEVNULL, process_group=0)
        owner["anchor"] = anchor
        wait_ready(anchor, time.monotonic() + 2)
        child = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=output, stderr=output,
                                 env=env, text=True, shell=False, process_group=anchor.pid)
        owner["child"] = child
        if token is not None:
            child.stdin.write(token + "\n")
            child.stdin.flush()
        child.stdin.close()
        return child

    def cleanup(self, *, grace_seconds: float = 12, join_seconds: float = 3) -> list[dict]:
        if self.cleaned is not None:
            return self.cleaned
        # All signals address original anchors that have never been reaped.
        for owner in self.owners:
            anchor = owner["anchor"]
            if anchor is not None:
                sig = signal.SIGINT if owner["socket_tool"] else signal.SIGTERM
                self._signal(owner, sig)
        end = time.monotonic() + grace_seconds
        while time.monotonic() < end:
            children = [o["child"] for o in self.owners if o["child"] is not None]
            finished = []
            for child in children:
                try:
                    finished.append(child.poll() is not None)
                except OSError:
                    finished.append(False)
            if all(finished):
                break
            time.sleep(min(.02, max(0, end - time.monotonic())))
        # Never wait/reap an anchor before every final group signal is sent.
        for owner in self.owners:
            if owner["anchor"] is not None:
                self._signal(owner, signal.SIGKILL)
        join_end = time.monotonic() + join_seconds
        records = []
        for owner in self.owners:
            joined = []
            for process in (owner["child"], owner["anchor"]):
                if process is None:
                    joined.append(None)
                    continue
                try:
                    process.wait(timeout=max(0, join_end - time.monotonic()))
                    joined.append(True)
                except (subprocess.TimeoutExpired, OSError):
                    joined.append(False)
            anchor = owner["anchor"]
            absent = False
            if anchor is not None:
                try:
                    os.killpg(anchor.pid, 0)  # Observe only; never signal after reap.
                except ProcessLookupError:
                    absent = True
                except OSError:
                    pass
                try:
                    anchor.stdout.close()
                except OSError:
                    absent = False
            try:
                owner["log"].close()
            except OSError:
                absent = False
            good = (anchor is not None and all(x == "sent" for _, x in owner["signals"])
                    and joined == [True, True] and anchor.returncode == -signal.SIGKILL and absent)
            records.append({"role": owner["role"], "original_anchor_pid": anchor.pid if anchor else None,
                            "original_child_pid": owner["child"].pid if owner["child"] else None,
                            "child_returncode": owner["child"].returncode if owner["child"] else None,
                            "anchor_returncode": anchor.returncode if anchor else None,
                            "signals_before_anchor_reap": owner["signals"],
                            "child_reaped": joined[0], "anchor_reaped": joined[1],
                            "group_absent": absent, "complete": good})
        self.cleaned = records
        return records

    @staticmethod
    def _signal(owner: dict, sig: int) -> None:
        try:
            os.killpg(owner["anchor"].pid, sig)
            result = "sent"
        except ProcessLookupError:
            result = "absent"
        except PermissionError:
            result = "permission_denied"
        except OSError:
            result = "signal_error"
        owner["signals"].append((signal.Signals(sig).name, result))
