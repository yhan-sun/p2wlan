#!/usr/bin/env python3
"""DRAFT_NOT_EXECUTED: one real barrier HTTP pair across native TERM.

No old TestCase import/inheritance. Input RELEASE is fixture cleanup only,
never evidence of pre-publication product shutdown. No runtime map frozen.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import select
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest


HERE = Path(__file__).resolve().parent
EXTERNAL_TOOLS = HERE / "fixture_http_pair_signal_tools.py"
SHELL = "/bin/bash"
LOG_CAP = 2 * 1024 * 1024
WIRE_CAP = 512
# Static maxima for fixed ASCII wire schemas, including the newline. Every
# numeric shell field is bounded here by a signed 32-bit positive PID width;
# any unexpected longer actual row is rejected before target classification.
OBSERVER_WIRE_BOUND = 130
HTTP_WIRE_BOUND = 202
PROTOCOL_SECONDS = 20
TEARDOWN_SECONDS = 2
SOURCE_HEAD = "a" * 40
WORKFLOW_HEAD = "b" * 40
FAKE_ROLES = {"nat", "control", "relay-1", "node-a", "node-b"}
CASE_MODES = {"barrier-pair-term": "direct"}
CASES = set(CASE_MODES)


OBSERVER = r"""
if [[ -z "${_B01_PAIR_OWNER_PID:-}" ]]; then
  _B01_PAIR_OWNER_PID=$$
  export _B01_PAIR_OWNER_PID
fi
_B01_PAIR_OBSERVER_BUSY=0
_b01_pair_observe() {
  set +x
  local original_status="$1" command="$2" frame="$3" argument1="$4" sub="$5"
  local observed_pid="$6" recorded_status="$7"
  local original_trace="$8"
  if [[ "$$" == "$_B01_PAIR_OWNER_PID" && "$_B01_PAIR_OBSERVER_BUSY" == 0 ]]; then
    _B01_PAIR_OBSERVER_BUSY=1
    if [[ "$sub" == 0 && "$frame" == fetch_relay_barrier_status_pair && "$command" == 'wait "$a_pid"' ]]; then
      printf '{"tool":"original_wait_entry","pid":%s,"sub":0,"wait_pid":%s,"other_pid":%s,"incoming_status":%s}\n' "$$" "$a_pid" "$b_pid" "$original_status" >&__EVENT_FD__
    elif [[ "$sub" == 0 && "$frame" == fetch_relay_barrier_status_pair && "$command" == 'round_handle_signal 143 terminated' ]]; then
      printf '{"tool":"native_TERM_trap_entry","pid":%s,"sub":0,"incoming_status":%s}\n' "$$" "$original_status" >&__EVENT_FD__
    elif [[ "$sub" == 0 && "$frame" == round_on_exit && "$command" == '(( status == 0 ))' ]]; then
      # This is the first original command AFTER trap '' INT TERM. Capture
      # that builtin's return before this observer executes any command.
      printf '{"tool":"native_trap_ignore_applied","pid":%s,"sub":0,"incoming_status":%s}\n' "$$" "$original_status" >&__EVENT_FD__
    elif [[ "$sub" == 0 && "$frame" == _round_wait_finished && ( "$command" == 'wait "$pid"' || "$command" == 'wait "$pid" 2> /dev/null' || "$command" == 'wait "$pid" 2>/dev/null' ) ]]; then
      printf '{"tool":"closing_wait_entry","pid":%s,"sub":0,"wait_pid":%s}\n' "$$" "$observed_pid" >&__EVENT_FD__
    elif [[ "$sub" == 0 && "$frame" == _round_wait_finished && ( "$command" == 'status=0' || "$command" == 'status=$?' ) ]]; then
      # Observe the native wait's return before the original status assignment.
      # Do not perform that assignment or call wait/round_record_wait here.
      printf '{"tool":"closing_wait_return","pid":%s,"sub":0,"wait_pid":%s,"native_status":%s}\n' "$$" "$observed_pid" "$original_status" >&__EVENT_FD__
    elif [[ "$sub" == 0 && "$frame" == _round_wait_finished && "$command" == 'round_record_wait "$pid" "$status"' ]]; then
      printf '{"tool":"closing_wait_ledger","pid":%s,"sub":0,"wait_pid":%s,"recorded_status":"%s"}\n' "$$" "$observed_pid" "$recorded_status" >&__EVENT_FD__
    elif [[ "$frame" == _round_tool && "$argument1" == publish && "$command" == 'python3 "$ROOT_DIR/scripts/nat-sim/round_finalization.py" "$@"' ]]; then
      printf '{"tool":"original_publish_entry","pid":%s,"sub":%s}\n' "$$" "$sub" >&__EVENT_FD__
    fi
    _B01_PAIR_OBSERVER_BUSY=0
  fi
  if [[ "$original_trace" == *x* ]]; then
    set -x
  fi
  return 0
}
set -o functrace
trap '_b01_pair_observe "$?" "${BASH_COMMAND:-}" "${FUNCNAME[0]:-}" "${1:-}" "${BASH_SUBSHELL:-0}" "${pid:-0}" "${status:-unknown}" "$-"' DEBUG
"""

def unique_JSON_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise AssertionError("B01 duplicate native wire/file key (not a product RED)")
        result[key] = value
    return result


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_repository():
    explicit = os.environ.get("P2WLAN_B01_SOURCE_REPOSITORY")
    root = Path(explicit).resolve() if explicit else HERE.parents[1]
    if not (root / "scripts/nat-sim/nat-sim-smoke.sh").is_file():
        raise AssertionError("B01 fixture source repository is missing (not a product RED)")
    return root


def matrix_module(root):
    script_dir = root / "scripts/nat-sim"
    name = "b01_actual_cli_matrix_" + hashlib.sha256(str(root).encode()).hexdigest()[:12]
    specification = importlib.util.spec_from_file_location(name, script_dir / "run-hard-hard-matrix.py")
    if specification is None or specification.loader is None:
        raise AssertionError("B01 original matrix import missing (not a product RED)")
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    sys.path.insert(0, str(script_dir))
    try:
        specification.loader.exec_module(module)
    finally:
        sys.path.remove(str(script_dir))
    return module


class HttpPairSignalCliFixture:
    def __init__(self, root, source, case, rounds):
        if case not in CASES or rounds != 1:
            raise AssertionError("B01 outer fixture only permits declared one-round cases")
        # Canonicalize once so private layout fences also hold under symlinked temp roots.
        root = root.resolve()
        self.root, self.source, self.case, self.rounds = root, source, case, rounds
        self.roles = set(FAKE_ROLES)
        self.event_read = self.event_write = None
        self.HTTP_input_pipes = {}
        self.protocol_rows = []
        self.protocol_pending = b""
        self.protocol_eof = False
        self.process = None
        self.sentinel = None
        self.closed = False
        self.rescued = False
        self.cli_status = None
        self.repository = root / "private-source"
        self.artifacts = root / "artifacts"
        self.stdout_path = root / "cli.stdout"
        self.stderr_path = root / "cli.stderr-xtrace"
        self.original_sources = {}
        self.protocol_end = None
        self.teardown_end = None
        root.mkdir(mode=0o700)
        try:
            self.prepare()
        except BaseException:
            self.close()
            raise


    def prepare(self):
        preparation_end = time.monotonic() + 4

        def preparation_remaining():
            remaining = preparation_end - time.monotonic()
            if remaining <= 0:
                raise AssertionError("B01 private-layout preparation expired (not a product RED)")
            return remaining

        def git(*arguments, cwd=None):
            remaining = preparation_remaining()
            result = subprocess.run(["git", "-c", "core.hooksPath=/dev/null", *arguments],
                                    cwd=cwd, capture_output=True, timeout=remaining, check=False,
                                    env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C",
                                         "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null"})
            if result.returncode != 0:
                raise AssertionError("B01 private local Git preparation failed (not a product RED): "
                                     + result.stderr.decode(errors="replace")[:1000])
            return result.stdout

        # Local clone reads source Git objects; its index/config/checkout and
        # all fixture writes remain under this exclusive private directory.
        # There is no fetch, remote command, commit, or mutation of source Git.
        git("clone", "--local", "--shared", "--quiet", "--no-checkout",
            str(self.source), str(self.repository))
        source_head = git("rev-parse", "HEAD", cwd=self.source).decode().strip()
        git("checkout", "--quiet", "--detach", source_head, cwd=self.repository)
        paths = [self.source / "scripts/diagnostics-auth.sh"]
        paths.extend(path for path in sorted((self.source / "scripts/nat-sim").iterdir())
                     if path.is_file() and path.suffix in {".py", ".sh", ".json"})
        preparation_remaining()
        for path in paths:
            preparation_remaining()
            relative = path.relative_to(self.source)
            payload = path.read_bytes()
            self.original_sources[str(relative)] = hashlib.sha256(payload).hexdigest()
            target = self.repository / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(payload)
            target.chmod(path.stat().st_mode & 0o777)
        for relative, expected in self.original_sources.items():
            preparation_remaining()
            if digest(self.source / relative) != expected or digest(self.repository / relative) != expected:
                raise AssertionError("B01 source moved while making private layout (not a product RED)")
        (self.repository / "server").mkdir(exist_ok=True)
        preparation_remaining()
        driver = self.root / "fixture-external-tools.py"
        shutil.copyfile(EXTERNAL_TOOLS, driver)
        driver.chmod(0o600)
        self.event_read, self.event_write = os.pipe()
        self.native_pipe_buf = os.fpathconf(self.event_write, "PC_PIPE_BUF")
        if (self.native_pipe_buf < WIRE_CAP
                or max(OBSERVER_WIRE_BOUND, HTTP_WIRE_BOUND) > min(WIRE_CAP, self.native_pipe_buf)):
            raise AssertionError("B01 native pipe atomic capacity invalid (not a product RED)")
        self.HTTP_input_pipes = {s: os.pipe() for s in ("a", "b")}
        settings = {"observer_write_fd": self.event_write,
                    "native_pipe_buf": self.native_pipe_buf,
                    "HTTP_input_read_fds": {s: v[0] for s, v in self.HTTP_input_pipes.items()},
                    "fixture_only": True, "case": self.case, "rounds": self.rounds,
                    "real_python": sys.executable, "private_repository": str(self.repository),
                    "original_source_commit": source_head,
                    "external_tools_sha256": digest(driver),
                    "original_sources": self.original_sources}
        (self.root / "fixture-config.json").write_text(json.dumps(settings, sort_keys=True) + "\n")
        (self.root / "fixture-config.json").chmod(0o600)
        commands = self.root / "fake-path"
        commands.mkdir(mode=0o700)
        for name in ("python3", "cargo", "go", "curl"):
            preparation_remaining()
            # A single fixed shell exec avoids an extra Python interpreter;
            # quoted fixed arguments and "$@" preserve the real argument list.
            payload = "#!/bin/sh\nexec " + " ".join(shlex.quote(value) for value in
                       (sys.executable, "-S", str(driver), str(self.root), name)) + ' "$@"\n'
            with (commands / name).open("x") as stream:
                os.fchmod(stream.fileno(), 0o700)
                stream.write(payload)
        (self.root / "tmp").mkdir(mode=0o700)
        observer = self.root / "fixture-observer.bash"
        observer.write_text(OBSERVER.replace("__EVENT_FD__", str(self.event_write)))
        observer.chmod(0o600)
        self.environment = {"BASH_ENV": str(observer), "PATH": str(commands) + ":/usr/bin:/bin:/usr/sbin:/sbin",
                            "LANG": "C", "LC_ALL": "C", "PYTHONDONTWRITEBYTECODE": "1",
                            "TMPDIR": str(self.root / "tmp"),
                            "MODE": CASE_MODES[self.case], "ROUNDS": str(self.rounds), "RELAY_COUNT": "1",
                            "EGRESS_CAPTURE": "listeners", "UNASSIGNED_EGRESS_LISTENERS": "0",
                            "ROUND_TIMEOUT_S": "30", "DIRECT_TIMEOUT_S": "5", "OVERLAY_TIMEOUT_S": "2",
                            "ROUND_CLEANUP_GRACE_MS": "1000", "NAT_SEED_BASE": "70000",
                            "NAT_SIM_RUN_ID": "b01-actual-http-pair-signal-offline", "NAT_SIM_ARTIFACT_DIR": str(self.artifacts),
                            "NAT_TOPOLOGY_HEAD_SHA": SOURCE_HEAD, "NAT_TOPOLOGY_WORKFLOW_SHA": WORKFLOW_HEAD,
                            "EXPERIMENT_BASELINE_SHA": SOURCE_HEAD,
                            "EXPERIMENT_VARIANT": "b01-http-pair-signal-offline-fixture", "EXPERIMENT_SCENARIO": "b01-http-pair-signal-offline-fixture",
                            # Plain PS4 variable expansion only. The trace
                            # observes actual waits in the owning sub=0 shell.
                            "PS4": "+ B01_CLI pid=$$ sub=$BASH_SUBSHELL line=$LINENO: "}
        preparation_remaining()
        self.sentinel = subprocess.Popen(
            [sys.executable, "-u", "-c",
             "import os,signal; signal.signal(signal.SIGTERM,lambda *_:exit(0)); "
             "os.write(1,b'B01_SENTINEL_READY\\n'); signal.pause()"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if not select.select([self.sentinel.stdout], [], [], min(1, preparation_remaining()))[0]:
            raise AssertionError("B01 unrelated sentinel not ready (not a product RED)")
        if self.sentinel.stdout.readline() != b"B01_SENTINEL_READY\n":
            raise AssertionError("B01 unrelated sentinel response invalid (not a product RED)")
        preparation_remaining()



    def remaining(self):
        remaining = self.protocol_end - time.monotonic()
        if remaining <= 0:
            raise AssertionError("B01 HTTP signal protocol expired (not a product RED)")
        return remaining

    def expand_wire(self, wire):
        observer_fields = {
            "original_wait_entry": {"tool", "pid", "sub", "wait_pid", "other_pid", "incoming_status"},
            "native_TERM_trap_entry": {"tool", "pid", "sub", "incoming_status"},
            "native_trap_ignore_applied": {"tool", "pid", "sub", "incoming_status"},
            "closing_wait_entry": {"tool", "pid", "sub", "wait_pid"},
            "closing_wait_return": {"tool", "pid", "sub", "wait_pid", "native_status"},
            "closing_wait_ledger": {"tool", "pid", "sub", "wait_pid", "recorded_status"},
            "original_publish_entry": {"tool", "pid", "sub"},
        }
        if not isinstance(wire, dict):
            raise AssertionError("B01 native handshake type (not a product RED)")
        kind = wire.get("tool")
        if kind in observer_fields:
            if set(wire) != observer_fields[kind]:
                raise AssertionError("B01 native observer wire schema (not a product RED)")
            for key, value in wire.items():
                if key in {"tool", "recorded_status"}:
                    continue
                if type(value) is not int or not 0 <= value <= 2147483647:
                    raise AssertionError("B01 native observer wire number (not a product RED)")
            if wire["pid"] <= 0 or ("recorded_status" in wire and not isinstance(wire["recorded_status"], str)):
                raise AssertionError("B01 native observer wire identity (not a product RED)")
            return wire
        fields = {"tool", "kind", "side", "pid", "file", "bytes", "sha256"}
        suffixes = {"http_ready": "ready", "http_ended": "ended", "http_guard_timeout": "guard-timeout"}
        if (kind != "HTTP_file" or set(wire) != fields or wire.get("kind") not in suffixes
                or wire.get("side") not in {"a", "b"} or type(wire.get("pid")) is not int
                or not 0 < wire["pid"] <= 2147483647 or type(wire.get("bytes")) is not int
                or not 0 < wire["bytes"] <= 32768 or not isinstance(wire.get("sha256"), str)
                or re.fullmatch(r"[0-9a-f]{64}", wire["sha256"]) is None):
            raise AssertionError("B01 compact HTTP wire schema (not a product RED)")
        name = "http-" + wire["side"] + "-" + suffixes[wire["kind"]] + ".json"
        if wire["file"] != name:
            raise AssertionError("B01 compact HTTP fixed file identity (not a product RED)")
        descriptor = os.open(self.root / name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                             | getattr(os, "O_NONBLOCK", 0))
        with os.fdopen(descriptor, "rb") as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600
                    or info.st_size != wire["bytes"]):
                raise AssertionError("B01 compact HTTP full file type/size (not a product RED)")
            data = stream.read(32769)
        if len(data) != wire["bytes"] or hashlib.sha256(data).hexdigest() != wire["sha256"]:
            raise AssertionError("B01 compact HTTP full file digest (not a product RED)")
        row = json.loads(data, object_pairs_hook=unique_JSON_pairs)
        if (not isinstance(row, dict) or row.get("tool") != wire["kind"]
                or row.get("side") != wire["side"] or type(row.get("pid")) is not int
                or row["pid"] != wire["pid"] or type(row.get("round")) is not int or row["round"] != 1
                or row.get("fixture_only") is not True
                or row.get("output") != str(self.artifacts / "round-1" / ("node-" + wire["side"] + ".barrier.status.json"))):
            raise AssertionError("B01 compact HTTP full file identity (not a product RED)")
        return row

    def protocol_read(self):
        if self.protocol_eof:
            raise AssertionError("B01 native handshake closed prematurely (not a product RED)")
        if not select.select([self.event_read],[],[],self.remaining())[0]:
            raise AssertionError("B01 native handshake timeout (not a product RED)")
        data = os.read(self.event_read,16384)
        if not data:
            self.protocol_eof = True
            if self.protocol_pending:
                raise AssertionError("B01 partial native handshake (not a product RED)")
            return
        self.protocol_pending += data
        if len(self.protocol_pending)>32768:
            raise AssertionError("B01 native handshake buffer cap (not a product RED)")
        while b"\n" in self.protocol_pending:
            row,self.protocol_pending=self.protocol_pending.split(b"\n",1)
            if len(row)+1>min(WIRE_CAP,self.native_pipe_buf) or len(self.protocol_rows)>=128:
                raise AssertionError("B01 native handshake atomic cap (not a product RED)")
            observed = time.monotonic_ns()
            wire = json.loads(row, object_pairs_hook=unique_JSON_pairs)
            value = self.expand_wire(wire)
            self.protocol_rows.append({**value,"observed_monotonic_ns":observed,
                                       "wire_order":len(self.protocol_rows),"wire_bytes":len(row)+1,
                                       "compact_wire":wire})

    def process_identity(self,pid,allow_gone=False):
        completed=subprocess.run(["/bin/ps","-p",str(pid),"-o","pid=,ppid=,pgid=,stat=,lstart=,command="],
                                 capture_output=True,timeout=min(1,self.remaining()),check=False)
        data=completed.stdout
        if len(data)>16384:
            raise AssertionError("B01 native process observation cap (not a product RED)")
        rows=data.decode().splitlines()
        if not rows and allow_gone:
            return None
        if completed.returncode!=0 or len(rows)!=1:
            raise AssertionError("B01 native process observation missing (not a product RED)")
        parts=rows[0].split(None,9)
        if len(parts)!=10 or int(parts[0])!=pid:
            raise AssertionError("B01 native process observation type (not a product RED)")
        return {"pid":pid,"ppid":int(parts[1]),"pgid":int(parts[2]),"state":parts[3],
                "native_lstart_seconds":' '.join(parts[4:9]),
                "command_sha256":hashlib.sha256(parts[9].encode()).hexdigest(),
                "original_shell_source_in_command":str(self.repository/'scripts/nat-sim/nat-sim-smoke.sh') in parts[9]}

    def prove_request_ancestry(self):
        self.request_chains={}
        owner=self.process_identity(self.process.pid)
        for side in ('a','b'):
            ready=self.HTTP_ready[side]; cursor=ready['pid']; chain=[]
            for _ in range(6):
                item=self.process_identity(cursor)
                if item['pgid']<=0 or item['pid'] in {x['pid'] for x in chain}:
                    raise AssertionError("B01 request ancestry/group differs (not a product RED)")
                chain.append(item)
                if cursor==self.process.pid:
                    break
                cursor=item['ppid']
            pair=self.wait_entry['wait_pid' if side=='a' else 'other_pid']
            ids=[x['pid'] for x in chain]
            if (chain[0]['ppid']!=ready['ppid'] or chain[0]['pgid']!=ready['pgid']
                    or ids[-1]!=self.process.pid or pair not in ids or pair==ready['pid']
                    or not chain[-1]['original_shell_source_in_command']):
                raise AssertionError("B01 original pair/curl ancestry not proved (not a product RED)")
            self.request_chains[side]=chain
        if self.wait_entry['wait_pid']==self.wait_entry['other_pid']:
            raise AssertionError("B01 original A/B owners alias (not a product RED)")

    def execute(self):
        self.protocol_end=time.monotonic()+PROTOCOL_SECONDS
        self.teardown_end=self.protocol_end+TEARDOWN_SECONDS
        with self.stdout_path.open('xb') as out,self.stderr_path.open('xb') as err:
            os.fchmod(out.fileno(),0o600);os.fchmod(err.fileno(),0o600)
            inherited=(self.event_write,*[v[0] for v in self.HTTP_input_pipes.values()])
            self.process=subprocess.Popen([SHELL,'-x',str(self.repository/'scripts/nat-sim/nat-sim-smoke.sh')],
                cwd=self.repository,env=self.environment,stdin=subprocess.DEVNULL,stdout=out,stderr=err,
                start_new_session=True,pass_fds=inherited)
            os.close(self.event_write);self.event_write=None
            for side,(rd,writer) in self.HTTP_input_pipes.items():
                os.close(rd)
                self.HTTP_input_pipes[side]=(None,writer)
            self.HTTP_ready={};self.wait_entry=None
            while len(self.HTTP_ready)!=2 or self.wait_entry is None:
                self.protocol_read()
                if self.protocol_eof:
                    raise AssertionError("B01 original request did not become ready (not a product RED)")
                rows=self.protocol_rows
                ready=[x for x in rows if x['tool']=='http_ready']
                if len(ready)>2 or len({x['side'] for x in ready})!=len(ready):
                    raise AssertionError("B01 duplicate barrier request (not a product RED)")
                self.HTTP_ready={x['side']:x for x in ready}
                waits=[x for x in rows if x['tool']=='original_wait_entry']
                if len(waits)>1:
                    raise AssertionError("B01 duplicate original first wait (not a product RED)")
                self.wait_entry=waits[0] if waits else None
            if self.wait_entry['pid']!=self.process.pid or self.wait_entry['sub']!=0:
                raise AssertionError("B01 original owner wait identity invalid (not a product RED)")
            self.prove_request_ancestry()
            self.signal_sent_monotonic_ns=time.monotonic_ns()
            os.kill(self.process.pid,signal.SIGTERM)
            self.cli_status=self.process.wait(timeout=self.remaining())
        while not self.protocol_eof:
            # Stop consuming at the available queue boundary while requests
            # remain blocked. No sleep or wait for an input guard expiration.
            if not select.select([self.event_read],[],[],0)[0]:break
            self.protocol_read()
        directory=self.artifacts/'round-1'
        final=directory/'round-finalization.json';cleanup=directory/'cleanup.json'
        if self.cli_status!=143 or not final.is_file() or not cleanup.is_file():
            raise AssertionError("B01 original TERM finalization missing (not a product RED)")
        traps=[x for x in self.protocol_rows if x['tool']=='native_TERM_trap_entry']
        if len(traps)!=1 or traps[0]['pid']!=self.process.pid or traps[0]['sub']!=0 or traps[0]['incoming_status']!=143:
            raise AssertionError("B01 TERM did not interrupt original native wait143 (not a product RED)")
        publication=[x for x in self.protocol_rows if x['tool']=='original_publish_entry']
        if len(publication)!=1 or publication[0]['pid']!=self.process.pid:
            raise AssertionError("B01 original native publication handshake missing (not a product RED)")
        # Snapshot BEFORE the only normal input RELEASE. Missing ownership is
        # a target finding, not a prerequisite requiring registration first.
        states={}
        for side,chain in self.request_chains.items():
            states[side]=[]
            for previous in chain[:-1]:
                current=self.process_identity(previous['pid'],allow_gone=True)
                if current is not None and (current['native_lstart_seconds']!=previous['native_lstart_seconds']
                         or current['command_sha256']!=previous['command_sha256']):
                    raise AssertionError("B01 request PID identity changed (not a product RED)")
                states[side].append({'initial_identity':previous,'identity_at_cli143':current,'live_at_cli143':current is not None})
        self.product_snapshot={'fixture_only':True,'observed_monotonic_ns':time.monotonic_ns(),
            'CLI_exit_status':self.cli_status,'CLI_native_wait_completed':True,
            'round_finalization_sha256':digest(final),'cleanup_sha256':digest(cleanup),
            'cleanup_before_release':self.bounded_json(cleanup),'requests':states,'stimulus_release_used':False}
        self.write_json('HTTP-product-snapshot-before-release.json',self.product_snapshot)
        self.released_sides=[]
        for side in ('a','b'):
            live=states[side][0]['live_at_cli143']
            if live:
                if time.monotonic_ns()>=self.HTTP_ready[side]['input_deadline_monotonic_ns']:
                    raise AssertionError("B01 original HTTP max-time expired before RELEASE (not a product RED)")
                if os.write(self.HTTP_input_pipes[side][1],b'RELEASE_NORMAL_HTTP\n')!=20:
                    raise AssertionError("B01 normal HTTP input RELEASE was partial (not a product RED)")
                self.released_sides.append(side)
        self.write_json('HTTP-input-release-control.json',{'fixture_only':True,'sides':self.released_sides,
            'monotonic_ns':time.monotonic_ns(),'product_closure_proof':False,'TERM_or_KILL_sent_to_HTTP':False})
        while not self.protocol_eof:self.protocol_read()
        self.stdout,self.stderr=self.read_log(self.stdout_path),self.read_log(self.stderr_path)
        self.events=self.read_events()
        if 'B01_FIXTURE_INFRA_FAILURE:' in self.stdout+self.stderr or any(x['tool'] in {'child_fixture_deadline','http_guard_timeout'} for x in self.events):
            raise AssertionError("B01 external input error/timeout (not a product RED)")
        self.prove_HTTP_ended()
        for relative,sha in self.original_sources.items():
            if digest(self.repository/relative)!=sha:raise AssertionError("B01 private source moved (not a product RED)")
        self.prove_children_closed();self.prove_ports_released()
        if self.sentinel.poll() is not None:raise AssertionError("B01 unrelated sentinel stopped (not a product RED)")
        self.write_json('actual-cli-fixture-receipt.json',{'fixture_only':True,'case':self.case,'CLI_exit_status':self.cli_status,
            'cli_pid':self.process.pid,'supervisor_rescue':self.rescued,'HTTP_rescue':False,
            'stimulus_release_used':bool(self.released_sides),'released_sides':self.released_sides,
            'original_sources':self.original_sources,'original_request_chains':self.request_chains,
            'product_snapshot_sha256':digest(self.root/'HTTP-product-snapshot-before-release.json'),
            'protocol_rows':self.protocol_rows,'native_pipe_buf':self.native_pipe_buf,'wire_cap':WIRE_CAP,
            'observer_wire_bound':OBSERVER_WIRE_BOUND,'HTTP_wire_bound':HTTP_WIRE_BOUND,
            'protocol_seconds':20,'round_seconds':30,'work_seconds':15,'stage_seconds':5,'resource_grace_ms':1000,
            'HTTP_after_RELEASE_PIDgone_is_not_product_wait_or_closure':True})
        print('B01_ACTUAL_CLI_FIXTURE='+str(self.root),flush=True)
        return self

    def write_json(self,name,value):
        with (self.root/name).open('x') as stream:
            os.fchmod(stream.fileno(),0o600);json.dump(value,stream,sort_keys=True);stream.write('\n')

    def prove_HTTP_ended(self):
        for side,chain in self.request_chains.items():
            ended=self.bounded_json(self.root/('http-'+side+'-ended.json'),32768)
            ready=self.HTTP_ready[side]
            if (ended['pid']!=ready['pid'] or ended['side']!=side or ended['exit_code']!=0
                    or ended['stimulus_release_used']!=(side in self.released_sides)
                    or ended['signal']!=(None if side in self.released_sides else signal.SIGTERM)
                    or ended['monotonic_ns']>=ready['input_deadline_monotonic_ns']):
                raise AssertionError("B01 HTTP native ending/release/guard differs (not a product RED)")
            for identity in chain[:-1]:
                if self.process_identity(identity['pid'],allow_gone=True) is not None:
                    raise AssertionError("B01 HTTP descendant still exists after normal input (not a product RED)")
            if side in self.released_sides:
                # These original bodies finish naturally AFTER the snapshot.
                # Their normal result is not an owner wait by the ended CLI.
                metadata=self.artifacts/'round-1'/('.barrier-'+side+'-fetch')
                if metadata.read_text().splitlines()!=['1','200','']:
                    raise AssertionError("B01 released original request did not finish normally (not a product RED)")

    def prove_children_closed(self):
        directory=self.artifacts/'round-1';self.child_records={}
        ready_events=[x for x in self.events if x['tool']=='child_ready']
        stopped_events=[x for x in self.events if x['tool']=='child_stopped']
        if (len(ready_events)!=5 or len(stopped_events)!=5
                or {x['role'] for x in ready_events}!=self.roles
                or {x['role'] for x in stopped_events}!=self.roles
                or len({x['pid'] for x in ready_events})!=5):
            raise AssertionError("B01 five actual role lifetimes differ (not a product RED)")
        for role in self.roles:
            ready=self.bounded_json(directory/(role+'.fixture-ready.json'),32768)
            stopped=self.bounded_json(directory/(role+'.fixture-stopped.json'),32768)
            component='daemon' if role.startswith('node-') else 'relay' if role=='relay-1' else role
            if (type(ready['pid']) is not int or ready['pid']<=0 or ready['component']!=component
                    or ready['role']!=role or ready['round']!=1 or ready['fixture_only'] is not True
                    or ready['exit_code'] is not None or stopped['pid']!=ready['pid']
                    or stopped['role']!=role or stopped['component']!=component or stopped['round']!=1
                    or stopped['signal']!=signal.SIGTERM or stopped['exit_code']!=0):
                raise AssertionError("B01 five role native TERM0 differs (not a product RED)")
            self.prove_wait(ready['pid'],0)
            self.child_records[role]=ready
            if role!='nat':
                launch=self.bounded_json(directory/'launches'/(role+'.json'))
                if launch['pid']!=ready['pid'] or launch['role']!=role:
                    raise AssertionError("B01 original role launch differs (not a product RED)")

    @staticmethod
    def read_log(path):
        with path.open("rb") as stream:
            payload = stream.read(LOG_CAP + 1)
        if len(payload) > LOG_CAP:
            raise AssertionError("B01 actual CLI log cap exceeded (not a product RED)")
        return payload.decode(errors="replace")


    def read_events(self):
        with (self.root / "external-events.jsonl").open("rb") as stream:
            payload = stream.read(256 * 1024 + 1)
        if len(payload) > 256 * 1024:
            raise AssertionError("B01 external event cap exceeded (not a product RED)")
        rows = payload.splitlines()
        if len(rows) > 512 or any(len(row) > 4096 for row in rows):
            raise AssertionError("B01 external event count/row cap exceeded (not a product RED)")
        return [json.loads(row) for row in rows]


    @staticmethod
    def bounded_json(path, cap=128 * 1024):
        with path.open("rb") as stream:
            data = stream.read(cap + 1)
        if len(data) > cap:
            raise AssertionError("B01 outer fixture JSON cap exceeded (not a product RED)")
        value = json.loads(data)
        if not isinstance(value, dict):
            raise AssertionError("B01 outer fixture object missing (not a product RED)")
        return value


    def prove_wait(self, pid, status):
        prefix = rf"^\++ B01_CLI pid={self.process.pid} sub=0 line=[0-9]+: "
        if len(re.findall(prefix + rf"wait {pid}$", self.stderr, re.MULTILINE)) != 1:
            raise AssertionError("B01 original owning shell actual wait missing (not a product RED)")
        if len(re.findall(prefix + rf"round_record_wait {pid} {status}$", self.stderr, re.MULTILINE)) != 1:
            raise AssertionError("B01 actual wait status ledger handoff missing (not a product RED)")
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            pass
        else:
            raise AssertionError("B01 original child remains live/unreaped (not a product RED)")


    def prove_ports_released(self):
        reservation_calls = [row for row in self.events if row["tool"] == "original_port_reservation"]
        release_calls = [row for row in self.events if row["tool"] == "original_port_release"]
        if len(reservation_calls) != 1 or len(release_calls) != 1:
            raise AssertionError("B01 original port reserve/release calls missing (not a product RED)")
        expected = self.original_sources["scripts/nat-sim/reserve_port_block.py"]
        if any(row["original_script_sha256"] != expected for row in [*reservation_calls, *release_calls]):
            raise AssertionError("B01 port reservation script bytes differ (not a product RED)")
        locks = self.root / "tmp/p2wlan-natsim-port-locks"
        if not locks.is_dir() or any(locks.iterdir()):
            raise AssertionError("B01 real port reservation was not released (not a product RED)")


    def close(self):
        if self.closed:
            return
        error = None
        teardown_started = time.monotonic()
        teardown_end = min(self.teardown_end or (teardown_started + TEARDOWN_SECONDS),
                           teardown_started + TEARDOWN_SECONDS)
        if self.process is not None and self.process.poll() is None:
            self.rescued = True
            try:
                os.killpg(self.process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                self.process.wait(timeout=max(0, teardown_end - time.monotonic() - 0.1))
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(self.process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    self.process.wait(timeout=max(0, teardown_end - time.monotonic()))
                except subprocess.TimeoutExpired:
                    error = "B01 controller could not be reaped in fixed teardown"
        if self.process is not None and not self.protocol_eof:
            # Failure-only emergency cleanup is recorded as rescue and always
            # rejects the test. It cannot turn missing ownership into RED.
            groups=set()
            for ready in getattr(self,'HTTP_ready',{}).values():
                try: os.kill(ready['pid'],0)
                except ProcessLookupError: continue
                groups.add(ready['pgid'])
            if groups:
                self.rescued=True
                self.write_json('HTTP-emergency-cleanup.json',{'fixture_only':True,
                    'groups':sorted(groups),'HTTP_rescue':True,'accepted_target_RED':False})
                for group in groups:
                    try: os.killpg(group,signal.SIGTERM)
                    except ProcessLookupError: pass
                error="B01 HTTP descendants required emergency rescue"
            while self.event_read is not None and not self.protocol_eof and time.monotonic()<teardown_end:
                if not select.select([self.event_read],[],[],max(0,teardown_end-time.monotonic()))[0]:break
                if not os.read(self.event_read,32768):self.protocol_eof=True
            if not self.protocol_eof:
                error="B01 HTTP descendants did not close in fixed teardown"
        if self.sentinel is not None:
            if self.sentinel.poll() is None:
                self.sentinel.terminate()
            try:
                self.sentinel.wait(timeout=max(0, teardown_end - time.monotonic()))
            except subprocess.TimeoutExpired:
                self.sentinel.kill()
                try:
                    self.sentinel.wait(timeout=max(0, teardown_end - time.monotonic()))
                except subprocess.TimeoutExpired:
                    error = "B01 sentinel could not be reaped in fixed teardown"
            for stream in (self.sentinel.stdout, self.sentinel.stderr):
                if stream is not None:
                    stream.close()
            if self.sentinel.returncode != 0:
                error = "B01 sentinel did not complete cooperative TERM and actual wait 0"
            with (self.root / "sentinel-cleanup.json").open("x") as stream:
                os.fchmod(stream.fileno(), 0o600)
                json.dump({"fixture_only": True, "pid": self.sentinel.pid,
                           "wait_completed": self.sentinel.returncode is not None,
                           "wait_status": self.sentinel.returncode}, stream, sort_keys=True)
                stream.write("\n")
        descriptors = [self.event_read, self.event_write, *[fd for v in self.HTTP_input_pipes.values() for fd in v]]
        for descriptor in descriptors:
            if descriptor is not None:
                try: os.close(descriptor)
                except OSError: pass
        self.closed = True
        if self.rescued or error:
            raise AssertionError((error or "B01 actual CLI needed supervisor rescue") + " (not a product RED)")



class ActualHttpPairSignalTests(unittest.TestCase):
    def fixture(self, case):
        source = source_repository()
        evidence = os.environ.get("P2WLAN_B01_FIXTURE_ARTIFACTS")
        if evidence:
            directory = Path(evidence).resolve() / self._testMethodName
        else:
            temporary = tempfile.TemporaryDirectory(prefix="p2wlan-http-pair-signal-cli-")
            self.addCleanup(temporary.cleanup)
            directory = Path(temporary.name) / "exclusive-case"
        fixture = HttpPairSignalCliFixture(directory, source, case, 1)
        self.addCleanup(fixture.close)
        fixture.execute()
        fixture.close()
        sentinel = fixture.bounded_json(fixture.root / "sentinel-cleanup.json")
        self.assertTrue(sentinel["wait_completed"])
        self.assertEqual(sentinel["wait_status"], 0)
        self.assertFalse(fixture.rescued)
        return fixture


    def invalid_denominator(self, fixture, marker=None):
        message = marker or "B01 original matrix prerequisite (not a product RED)"
        matrix = matrix_module(fixture.repository)
        with self.assertRaises(matrix.EvidenceError, msg=message) as rejected:
            matrix.validate_round(fixture.artifacts / "round-1", matrix.SCENARIO_BY_NAME["equal-step"],
                                  1, SOURCE_HEAD, WORKFLOW_HEAD)
        reason = str(rejected.exception)
        self.assertTrue(reason.startswith(("raw_evidence_missing:", "nat_evidence_rejected:")), message)
        summary = matrix.aggregate_runs([{"exit_code": fixture.cli_status, "rounds": [
            {"result": "invalid", "reason": reason}]}])
        self.assertEqual(summary["requested"]["rounds"], 1, message)
        self.assertEqual(summary["evidence_validity"]["invalid_rounds"], 1, message)
        self.assertEqual(summary["evidence_validity"]["valid_rounds"], 0, message)
        return summary



    def prerequisites(self,fixture):
        directory=fixture.artifacts/'round-1'
        self.assertEqual(fixture.cli_status,143)
        self.assertFalse(fixture.rescued)
        value=fixture.bounded_json(directory/'round-finalization.json')
        self.assertEqual(value['terminal_reason_code'],'terminated')
        self.assertEqual(value['original_exit_code'],143)
        self.assertEqual(value['shell_exit_status'],143)
        self.assertEqual(value['shell_exit_status_source'],'exit_trap')
        self.assertEqual(value['round_result'],'invalid')
        self.assertFalse((directory/'business-validation.start-gate').exists())
        self.assertFalse((directory/'relay-barrier.readiness.json').exists())
        self.assertFalse(any(x['tool']=='original_collector_enter' for x in fixture.events))
        for side in ('a','b'):
            role='node-'+side;ready=fixture.child_records[role]
            for suffix in ('.readiness.json','.baseline.readiness.json'):
                record=fixture.bounded_json(directory/(role+suffix))
                self.assertEqual(record['result'],'ready');self.assertEqual(record['pid'],ready['pid'])
                self.assertTrue(record['process_alive']);self.assertTrue(record['token_present'])
            record=fixture.bounded_json(directory/(role+'.baseline.readiness.json'))
            self.assertEqual(record['http_status'],200);self.assertEqual(record['attempts'],1)
            status=fixture.bounded_json(directory/(role+'.baseline.status.json'),1024*1024)
            self.assertEqual(status['process_id'],ready['pid'])
            self.assertEqual(status['node_id'],role)
            self.assertIsInstance(status['stats']['outbound_drops'],dict)
            self.assertIsInstance(status['stats']['outbound_loss_events'],list)
            self.assertEqual(status['connection_timeline']['events'],[])
            self.assertEqual(status['connection_timeline']['first_usable_summaries'],[])
            task=status['health']['critical_tasks'][0]
            self.assertIs(task['critical'],True);self.assertIs(task['running'],True)
            self.assertIs(task['finished'],False);self.assertIsNone(task['error'])
            calls=[x for x in fixture.events if x['tool']=='curl' and x.get('output')==str(directory/(role+'.baseline.status.json'))]
            self.assertEqual(len(calls),1);self.assertEqual(calls[0]['response_sha256'],digest(directory/(role+'.baseline.status.json')))
            self.assertEqual(fixture.HTTP_ready[side]['original_main_sha256'],fixture.original_sources['scripts/nat-sim/nat-sim-smoke.sh'])
            self.assertEqual(fixture.HTTP_ready[side]['output'],str(directory/(role+'.barrier.status.json')))
            log=fixture.read_log(directory/(role+'.log'))
            self.assertNotIn('overlay_start_gate_released',log);self.assertNotIn('overlay_payload_verified',log)
            self.assertFalse((directory/(role+'.fixture-business.json')).exists())
        cleanup=fixture.product_snapshot['cleanup_before_release']
        rows={x['pid']:x for x in cleanup['owned_processes']}
        for role,ready in fixture.child_records.items():
            self.assertIn(ready['pid'],rows);self.assertEqual(rows[ready['pid']]['role'],role)
            self.assertTrue(rows[ready['pid']]['wait_completed']);self.assertEqual(rows[ready['pid']]['wait_status'],0)
        self.invalid_denominator(fixture)

    def assert_HTTP_target(self,fixture,marker):
        snapshot=fixture.product_snapshot
        self.assertTrue(all(not row['live_at_cli143'] for rows in snapshot['requests'].values() for row in rows),
                        marker+': original requests must be closed by product before CLI143, before any input RELEASE')
        self.assertFalse(fixture.released_sides,marker+': post-publication input release is not product closure')
        cleanup=snapshot['cleanup_before_release'];rows={x['pid']:x for x in cleanup['owned_processes']}
        pub=next(n for n,x in enumerate(fixture.protocol_rows) if x['tool']=='original_publish_entry')
        prefix=rf'^\++ B01_CLI pid={fixture.process.pid} sub=0 line=[0-9]+: '
        original=[(n,x) for n,x in enumerate(fixture.protocol_rows) if x['tool']=='original_wait_entry']
        trapped=[(n,x) for n,x in enumerate(fixture.protocol_rows) if x['tool']=='native_TERM_trap_entry']
        ignored=[(n,x) for n,x in enumerate(fixture.protocol_rows) if x['tool']=='native_trap_ignore_applied']
        self.assertEqual(len(original),1,marker);self.assertEqual(len(trapped),1,marker)
        self.assertEqual(len(ignored),1,marker)
        self.assertLess(original[0][0],trapped[0][0],marker)
        self.assertLess(trapped[0][0],ignored[0][0],marker)
        self.assertEqual(trapped[0][1]['incoming_status'],143,marker)
        self.assertEqual(ignored[0][1]['incoming_status'],0,marker)
        self.assertEqual(ignored[0][1]['pid'],fixture.process.pid,marker)
        self.assertEqual(ignored[0][1]['sub'],0,marker)
        ignored_trace=list(re.finditer(prefix+r"trap '' INT TERM$",fixture.stderr,re.MULTILINE))
        term_trace=list(re.finditer(prefix+r'round_handle_signal 143 terminated$',fixture.stderr,re.MULTILINE))
        self.assertEqual(len(ignored_trace),1,marker);self.assertEqual(len(term_trace),1,marker)
        self.assertLess(term_trace[0].start(),ignored_trace[0].start(),marker)
        for side in ('a','b'):
            pid=fixture.wait_entry['wait_pid' if side=='a' else 'other_pid']
            self.assertIn(pid,rows,marker+': actual original HTTP owner registered')
            row=rows[pid];self.assertTrue(row['wait_completed'],marker)
            self.assertNotIn(row['wait_status'],(None,127),marker)
            self.assertFalse(row['forced_termination'],marker)
            self.assertNotIn(row['role'],fixture.roles|{'owned','unknown'},marker)
            ledger=re.findall(prefix+rf'round_record_wait {pid} ([0-9]+)$',fixture.stderr,re.MULTILINE)
            self.assertEqual(ledger,[str(row['wait_status'])],marker)
            entries=[(n,x) for n,x in enumerate(fixture.protocol_rows)
                     if x['tool']=='closing_wait_entry' and x['wait_pid']==pid]
            returns=[(n,x) for n,x in enumerate(fixture.protocol_rows)
                     if x['tool']=='closing_wait_return' and x['wait_pid']==pid]
            ledgers=[(n,x) for n,x in enumerate(fixture.protocol_rows)
                     if x['tool']=='closing_wait_ledger' and x['wait_pid']==pid]
            self.assertEqual(len(entries),1,marker+': one later native closing wait')
            self.assertEqual(len(returns),1,marker+': observe its actual return')
            self.assertEqual(len(ledgers),1,marker+': one closing wait ledger')
            for _,event in entries+returns+ledgers:
                self.assertEqual(event['pid'],fixture.process.pid,marker)
                self.assertEqual(event['sub'],0,marker)
            self.assertLess(ignored[0][0],entries[0][0],marker)
            self.assertLess(entries[0][0],returns[0][0],marker)
            self.assertLess(returns[0][0],ledgers[0][0],marker)
            self.assertLess(ledgers[0][0],pub,marker)
            native_status=returns[0][1]['native_status']
            self.assertIs(type(native_status),int,marker)
            self.assertTrue(0<=native_status<=255 and native_status!=127,marker)
            self.assertEqual(native_status,row['wait_status'],marker)
            self.assertEqual(ledgers[0][1]['recorded_status'],str(native_status),marker)
            waits=list(re.finditer(prefix+rf'wait {pid}$',fixture.stderr,re.MULTILINE))
            ledger_trace=list(re.finditer(prefix+rf'round_record_wait {pid} {native_status}$',fixture.stderr,re.MULTILINE))
            self.assertGreaterEqual(len(waits),2 if side=='a' else 1,marker)
            self.assertEqual(len(ledger_trace),1,marker)
            closing=[x for x in waits if ignored_trace[0].start()<x.start()<ledger_trace[0].start()]
            self.assertEqual(len(closing),1,marker+': actual closing wait after trap-ignore')
            assignments=[x for x in re.finditer(prefix+rf'status={native_status}$',fixture.stderr,re.MULTILINE)
                         if closing[0].start()<x.start()<ledger_trace[0].start()]
            self.assertEqual(len(assignments),1,marker+': original native wait result stored before ledger')
            if side=='a':
                self.assertEqual(original[0][1]['wait_pid'],pid,marker)
                self.assertTrue(any(x.start()<term_trace[0].start() for x in waits),marker)
                self.assertLess(trapped[0][0],entries[0][0],marker+': interrupted A wait is not closing completion')
            end=[n for n,x in enumerate(fixture.protocol_rows) if x['tool']=='http_ended' and x['side']==side]
            self.assertEqual(len(end),1,marker);self.assertLess(end[0],pub,marker+': native curl end before actual publish entry')
            ended=fixture.protocol_rows[end[0]]
            self.assertLessEqual(ended['monotonic_ns']//1_000_000,
                                 cleanup['resource_grace_deadline_monotonic_ms'],marker)
            publish_trace=re.search(rf'^\++ B01_CLI pid={fixture.process.pid} sub=[0-9]+ line=[0-9]+: _round_tool publish(?: |$)',
                                    fixture.stderr,re.MULTILINE)
            ledger_trace=re.search(prefix+rf'round_record_wait {pid} {row["wait_status"]}$',fixture.stderr,re.MULTILINE)
            self.assertIsNotNone(publish_trace,marker);self.assertIsNotNone(ledger_trace,marker)
            self.assertLess(ledger_trace.start(),publish_trace.start(),marker+': native wait ledger before publication')
        self.assertEqual(cleanup['started_process_count'],7,marker)
        self.assertEqual(cleanup['wait_completed_count'],7,marker)
        self.assertEqual(len(rows),7,marker)
        self.assertTrue(cleanup['all_reaped'],marker);self.assertEqual(cleanup['pending_process_count'],0,marker)


    def assert_finalization(self, fixture, expected, marker):
        directory = fixture.artifacts / "round-1"
        path = directory / "round-finalization.json"
        self.assertTrue(path.is_file(), marker + ": outer caller must publish its round")
        value = fixture.bounded_json(path)
        self.assertEqual(value["terminal_reason_code"], expected,
                         marker + ": preserve the original Direct caller cause")
        self.assertEqual(value["original_exit_code"], 143, marker)
        self.assertEqual(value["round_result"], "invalid", marker)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600, marker)
        publish_prefix = rf"^\++ B01_CLI pid={fixture.process.pid} sub=[0-9]+ line=[0-9]+: "
        actual_publish = re.findall(publish_prefix + r"_round_tool publish --round-dir "
                                    + re.escape(str(directory)) + r"(?: |$)", fixture.stderr, re.MULTILINE)
        self.assertEqual(len(actual_publish), 1, marker + ": one actual publication transaction")
        cleanup = fixture.bounded_json(directory / "cleanup.json")
        self.assertTrue(cleanup["all_reaped"], marker)
        self.assertFalse(cleanup["forced_termination"], marker)
        self.assertEqual(cleanup["started_process_count"], 7, marker)
        self.assertEqual(cleanup["wait_completed_count"], 7, marker)
        self.assertEqual(cleanup["pending_process_count"], 0, marker)
        self.assertEqual(cleanup["worker_unknown_count"], 0, marker)
        self.assertTrue(fixture.roles.issubset({row["role"] for row in cleanup["owned_processes"]}), marker)
        self.assertEqual(len(cleanup["owned_processes"]), 7, marker)
        for row in cleanup["owned_processes"]:
            if row["role"] not in fixture.roles: continue
            self.assertTrue(row["wait_completed"], marker)
            self.assertEqual(row["wait_status"], 0, marker)
            self.assertEqual(row["pid"], fixture.child_records[row["role"]]["pid"], marker)
            self.assertFalse(row["forced_termination"], marker)
        for side in ("a", "b"):
            role = "node-" + side
            captured = fixture.bounded_json(directory / (".final-status-" + side + ".json"))
            self.assertEqual(value["statuses"][side], captured, marker)
            self.assertEqual(captured["pid"], fixture.child_records[role]["pid"], marker)
            self.assertEqual(captured["owner_role"], role, marker)
            self.assertIn(captured["result"], ("available", "unknown"), marker)
            canonical_calls = [row for row in fixture.events if row["tool"] == "curl"
                               and row.get("output") == str(directory / (role + ".status.json.capture"))]
            self.assertLessEqual(len(canonical_calls), 1, marker)
            worker = captured["worker"]
            self.assertIs(type(worker["started"]), bool, marker)
            if worker["started"]:
                self.assertTrue(worker["wait_completed"], marker)
                self.assertTrue(worker["command_wait_completed"], marker)
                self.assertTrue(worker["owned_group_shutdown_requested_before_wait"], marker)
                self.assertFalse(worker["forced_termination"], marker)
            raw = directory / (role + ".status.json")
            if captured["result"] == "available":
                self.assertIsNone(captured["reason_code"], marker)
                self.assertEqual(captured["process_observation"], "live_job", marker)
                self.assertTrue(worker["started"], marker)
                self.assertEqual(worker["result"], "completed", marker)
                self.assertEqual(worker["command_wait_status"], 0, marker)
                self.assertEqual(len(canonical_calls), 1, marker)
                self.assertTrue(raw.is_file(), marker)
                self.assertEqual(captured["sha256"], digest(raw), marker)
                self.assertEqual(canonical_calls[0]["response_sha256"], digest(raw), marker)
                for field in ("is_baseline", "is_barrier", "barrier_unhealthy_input"):
                    self.assertIs(canonical_calls[0][field], False, marker)
                status = fixture.bounded_json(raw, 1024 * 1024)
                self.assertEqual(status["process_id"], fixture.child_records[role]["pid"], marker)
                self.assertEqual(status["node_id"], role, marker)
                tasks = status["health"]["critical_tasks"]
                self.assertEqual(len(tasks), 1, marker)
                self.assertIs(tasks[0]["critical"], True, marker)
                self.assertIs(tasks[0]["running"], True, marker)
                self.assertIs(tasks[0]["finished"], False, marker)
                self.assertIsNone(tasks[0]["error"], marker)
                self.assertEqual(status["connection_timeline"]["events"], [], marker)
                self.assertEqual(status["connection_timeline"]["first_usable_summaries"], [], marker)
            else:
                self.assertIn(captured["reason_code"], ("deadline_exhausted", "resource_grace_exhausted",
                    "process_gone", "process_ownership_unknown", "status_unavailable", "status_auth_token_missing",
                    "status_schema_invalid", "status_schema_or_capture_failure"), marker)
                self.assertIsNone(captured["sha256"], marker)
                self.assertFalse(raw.exists(), marker)
                if captured["reason_code"] == "process_gone":
                    self.assertEqual(captured["process_observation"], "wait_complete", marker)
                    self.assertEqual(captured["identity_scope"], "round_original_owned_pid_after_actual_wait", marker)
                    self.assertFalse(worker["started"], marker)
        identity = fixture.bounded_json(directory / ".round-source-identity.json")
        self.assertEqual(value["source_identity"], identity, marker)
        self.assertIn(identity["result"], ("captured", "unknown"), marker)
        if identity["result"] == "captured":
            self.assertIsNone(identity["reason_code"], marker)
            source = fixture.bounded_json(fixture.artifacts / "source-at-build.json")
            self.assertEqual(identity["source"], source, marker)
            self.assertEqual(identity["source_at_build_sha256"], digest(fixture.artifacts / "source-at-build.json"), marker)
            self.assertEqual(identity["artifact_set_sha256"], digest(fixture.artifacts / "artifact-set.json"), marker)
            records = identity["launch_records"]
            self.assertEqual({row["role"] for row in records}, fixture.roles - {"nat"}, marker)
            self.assertEqual(len(records), 4, marker)
            for row in records:
                self.assertEqual(row["pid"], fixture.child_records[row["role"]]["pid"], marker)
                self.assertEqual(row["sha256"], digest(directory / "launches" / (row["role"] + ".json")), marker)
                self.assertEqual(row["state"], "exec_requested", marker)
        else:
            self.assertIn(identity["reason_code"], ("deadline_exhausted", "launch_capacity_or_deadline_exhausted"), marker)
        evidence = fixture.bounded_json(directory / "nat-evidence.json")
        self.assertEqual(evidence["result"], "fail", marker)
        self.assertFalse(evidence["executed"], marker)
        self.assertIsNone(evidence["nat_terminal"], marker)
        self.assertEqual(evidence["decision"]["reason_code"], "harness:" + expected, marker)
        self.invalid_denominator(fixture, marker)


    def test_actual_barrier_pair_term_preserves_owned_http_wait_and_descendants(self):
        fixture = self.fixture("barrier-pair-term")
        self.prerequisites(fixture)
        marker = "B01_ACTUAL_BARRIER_PAIR_TERM_OWNERSHIP"
        self.assert_HTTP_target(fixture, marker)
        self.assert_finalization(fixture, "terminated", marker)
