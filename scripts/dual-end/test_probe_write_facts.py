"""Owned pipe/socket controls; socket observations confer no TUN authority."""
from dataclasses import replace
import errno
import hashlib
import json
import os
from pathlib import Path
import select
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import probe_process_identity as identity
import probe_request_plan as plans
import probe_write_facts as facts
import tcp_business_probe as tcp
import udp_business_probe as udp
import udp_business_summary as udp_summary


class PlatformControls(unittest.TestCase):
    def test_missing_plan_is_rejected_before_socket_or_original_clock(self):
        config = udp.Config(("127.0.0.1", 41001), ("127.0.0.1", 41002), "1" * 32, "2" * 32)
        for tool, boundary in [(udp, "open_socket"), (tcp, "bound_socket")]:
            with self.subTest(tool=tool.SCOPE), patch.object(tool, boundary) as open_socket:
                with self.assertRaises(ValueError):
                    tool.run_probe(config, write_facts_fd=1)
                open_socket.assert_not_called()

    def test_non_posix_explicit_option_fails_without_duplicating_descriptor(self):
        with patch.object(facts.os, "name", "nt"), patch.object(facts.os, "dup") as duplicate:
            with self.assertRaisesRegex(ValueError, "POSIX"):
                facts.WriteFacts(1, object(), None, "udp", "0" * 64)
            duplicate.assert_not_called()


@unittest.skipUnless(os.name == "posix", "write facts require POSIX nonblocking pipes")
class PipeControls(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.reader, self.writer = os.pipe()
        self.addCleanup(self.close_pipe)
        os.set_blocking(self.writer, False)
        self.config = udp.Config(("127.0.0.1", 41001), ("127.0.0.1", 41002), "1" * 32, "2" * 32)

    def close_pipe(self):
        for name in ("reader", "writer"):
            descriptor = getattr(self, name)
            if descriptor is not None:
                os.close(descriptor)
                setattr(self, name, None)

    def prepared(self, config=None, transport="udp"):
        config = config or self.config
        value = plans.make_plan(config, transport, "a" * 32, "b" * 32)
        path = self.root / (transport + ".json")
        path.write_text(json.dumps(value), encoding="utf-8")
        tool_sha = value["tool_sha256"]
        return plans.load_plan(path, config, transport, tool_sha, value["shared_config_tool_sha256"]), path, tool_sha

    def observer(self):
        prepared, _, tool_sha = self.prepared()
        value = facts.WriteFacts(self.writer, prepared, self.config, "udp", tool_sha)
        self.addCleanup(lambda: value.finish("test_cleanup"))
        return value

    def read_events(self):
        os.close(self.writer)
        self.writer = None
        raw = bytearray()
        while True:
            block = os.read(self.reader, 65536)
            if not block:
                break
            raw.extend(block)
            self.assertLess(len(raw), facts.MAX_BYTES)
        rows = [json.loads(line) for line in raw.splitlines()]
        self.assertEqual([r["n"] for r in rows], list(range(len(rows))))
        self.assertTrue(all(len(line) + 1 <= facts.MAX_RECORD_BYTES for line in raw.splitlines()))
        return rows, bytes(raw)

    def test_pipe_flags_and_original_descriptor_survive_owned_copy_cleanup(self):
        import fcntl
        # Establish the kernel's post-write flags through this same owned
        # pipe before comparing; macOS marks its first pipe write in GETFL.
        os.write(self.writer, b".")
        self.assertEqual(os.read(self.reader, 1), b".")
        before = fcntl.fcntl(self.writer, fcntl.F_GETFL)
        observer = self.observer()
        owned = observer.fd
        self.assertNotEqual(owned, self.writer)
        self.assertFalse(os.get_inheritable(owned))
        result = observer.finish("completed")
        with self.assertRaises(OSError):
            os.fstat(owned)
        self.assertEqual(fcntl.fcntl(self.writer, fcntl.F_GETFL), before)
        self.assertIsNone(result["emission_gap_reason"])
        rows, raw = self.read_events()
        self.assertEqual(result["records_emitted"], len(rows))
        self.assertEqual(result["bytes_emitted"], len(raw))
        self.assertEqual(rows[-1]["kind"], "finish")

    def test_blocking_read_only_and_regular_descriptors_fail_and_close_only_copy(self):
        import fcntl
        prepared, _, tool_sha = self.prepared()
        original_dup = os.dup
        descriptors = []

        def duplicate(descriptor):
            owned = original_dup(descriptor)
            descriptors.append(owned)
            return owned

        with (self.root / "ordinary-file").open("wb") as file:
            for descriptor in [self.reader, file.fileno(), self.writer]:
                if descriptor == self.writer:
                    os.set_blocking(descriptor, True)
                before = fcntl.fcntl(descriptor, fcntl.F_GETFL)
                with self.subTest(descriptor=descriptor), patch.object(facts.os, "dup", side_effect=duplicate):
                    with self.assertRaises(ValueError):
                        facts.WriteFacts(descriptor, prepared, self.config, "udp", tool_sha)
                self.assertEqual(fcntl.fcntl(descriptor, fcntl.F_GETFL), before)
                with self.assertRaises(OSError):
                    os.fstat(descriptors[-1])
        os.set_blocking(self.writer, False)

    def test_owner_and_clock_are_actual_current_process_or_explicitly_unavailable(self):
        observer = self.observer()
        observer.finish("completed")
        rows, _ = self.read_events()
        owner = next(r for r in rows if r["kind"] == "owner")
        clock = next(r for r in rows if r["kind"] == "clock")
        self.assertEqual((owner["pid"], owner["parent_pid"], owner["uid"]),
                         (os.getpid(), os.getppid(), os.getuid()))
        if sys.platform == "linux":
            self.assertTrue(owner["linux_birth_available"])
            self.assertEqual(owner["boot_id"], identity.bounded_text("/proc/sys/kernel/random/boot_id"))
            self.assertEqual(owner["pid_namespace"], os.readlink("/proc/self/ns/pid"))
            self.assertEqual(owner["net_namespace"], os.readlink("/proc/self/ns/net"))
            self.assertIs(type(owner["start_ticks"]), int)
            self.assertTrue(clock["same_boot_clock_available"])
            self.assertEqual(clock["boot_id"], owner["boot_id"])
        else:
            self.assertFalse(owner["linux_birth_available"])
            self.assertFalse(clock["same_boot_clock_available"])
            self.assertNotIn("boot_id", owner)
            self.assertNotIn("start_ticks", owner)

    def loopback(self, transport, blocked=False, cli=False):
        tool = udp if transport == "udp" else tcp
        socket_type = socket.SOCK_DGRAM if transport == "udp" else socket.SOCK_STREAM
        with socket.socket(socket.AF_INET, socket_type) as client, socket.socket(socket.AF_INET, socket_type) as peer:
            client.bind(("127.0.0.1", 0))
            peer.bind(("127.0.0.1", 0))
            config = replace(self.config, bind=client.getsockname(), target=peer.getsockname())
            echo = replace(config, bind=config.target, target=config.bind)
            prepared, plan_path, _ = self.prepared(config, transport)
            if blocked:
                # Fill only this test's pipe; no observer reader is created.
                for _ in range(16384):
                    try:
                        os.write(self.writer, b"x" * 4096)
                    except BlockingIOError:
                        break
                else:
                    self.fail("owned pipe did not reach bounded backpressure")
            chunks, reader_errors, result = [], [], {}

            def collect():
                end = time.monotonic() + 5
                while time.monotonic() < end:
                    if not select.select([self.reader], [], [], .05)[0]:
                        continue
                    raw = os.read(self.reader, 65536)
                    if not raw:
                        return
                    chunks.append(raw)
                    if sum(map(len, chunks)) > 65536:
                        reader_errors.append("test capture capacity")
                        return
                reader_errors.append("test capture deadline")

            reader = None if blocked else threading.Thread(target=collect)
            ready = threading.Event()
            worker = threading.Thread(target=lambda: result.update(echo=tool.run_echo(echo, peer, ready.set)))
            if reader:
                reader.start()
            worker.start()
            try:
                self.assertTrue(ready.wait(1))
                if cli:
                    # Release only this test's reserved client port before the
                    # actual CLI binds it; the echo peer is already ready.
                    client.close()
                    output = self.root / "CLI-report.json"
                    command = [sys.executable, "-B", str(Path(__file__).parent / (transport + "_business_probe.py")),
                               "probe", "--bind-ip", config.bind[0], "--bind-port", str(config.bind[1]),
                               "--target-ip", config.target[0], "--target-port", str(config.target[1]),
                               "--run-nonce", config.run_nonce, "--round-nonce", config.round_nonce,
                               "--request-plan", str(plan_path), "--write-facts-fd", str(self.writer),
                               "--output", str(output)]
                    child = subprocess.Popen(command, pass_fds=(self.writer,), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    try:
                        _, stderr = child.communicate(timeout=3)
                    except BaseException:
                        child.kill()
                        child.wait()
                        raise
                    self.assertEqual(child.returncode, 0, stderr.decode("utf-8", "replace"))
                    report = json.loads(output.read_text())
                else:
                    report = tool.run_probe(config, client, plan_path, self.writer)
            finally:
                os.close(self.writer)
                self.writer = None
                worker.join(3)
                if reader:
                    reader.join(1)
            self.assertFalse(worker.is_alive())
            self.assertFalse(reader_errors)
            if reader:
                self.assertFalse(reader.is_alive())
            if transport == "udp":
                udp_summary.validate_report(report)
                records = report["requests"]
            else:
                records = tool.validate_probe(report)
            self.assertEqual(len(records), 8)
            self.assertEqual([r["status"] for r in records], ["success"] * 8)
            self.assertEqual(report["configuration"], config.as_dict())
            self.assertEqual(report["evidence"], udp.UNVERIFIED)
            self.assertEqual(result["echo"]["responses_sent"], 8)
            if transport == "tcp":
                self.assertEqual(report["connection_attempts"], 1)
                self.assertEqual(result["echo"]["accepted_connections"], 1)
            summary = report["write_facts"]
            self.assertFalse(summary["daemon_registration_verified"])
            self.assertFalse(summary["kernel_tun_verified"])
            if blocked:
                self.assertEqual(summary["emission_gap_reason"], "observation_pipe_full")
                self.assertEqual(summary["records_emitted"], 0)
                return
            self.assertIsNone(summary["emission_gap_reason"])
            raw = b"".join(chunks)
            rows = [json.loads(line) for line in raw.splitlines()]
            self.assertEqual([r["n"] for r in rows], list(range(len(rows))))
            self.assertTrue(all(len(line) + 1 <= 512 for line in raw.splitlines()))
            source = rows[0]
            owner = next(r for r in rows if r["kind"] == "owner")
            self.assertEqual(owner["pid"], child.pid if cli else os.getpid())
            if cli:
                self.assertEqual(owner["parent_pid"], os.getpid())
            self.assertEqual(source["plan_sha256"], prepared.sha256)
            self.assertEqual(source["capture_id"], prepared.capture_id)
            self.assertEqual(source["producer_scope"], prepared.producer_scope)
            helpers = next(r for r in rows if r["kind"] == "helpers")
            for key, file in [("observer_sha256", "probe_write_facts.py"),
                              ("identity_sha256", "probe_process_identity.py")]:
                self.assertEqual(helpers[key], hashlib.sha256((Path(__file__).parent / file).read_bytes()).hexdigest())
            started = next(r for r in rows if r["kind"] == "start")
            self.assertEqual(started["original_started_ns"], summary["original_started_ns"])
            self.assertEqual(started["original_end_ns"], started["original_started_ns"] + 10_000_000_000)
            socket_row = next(r for r in rows if r["kind"] == "socket")
            self.assertEqual(socket_row["local"], list(config.bind))
            self.assertEqual(socket_row["target"], list(config.target))
            writes = [r for r in rows if r["kind"] == "write"]
            self.assertEqual(len(writes), 8)
            for sequence, (record, write) in enumerate(zip(records, writes)):
                wire = tool.encode(config, sequence, prepared.nonces[sequence], tool.REQUEST)
                if transport == "tcp":
                    wire = struct.pack("!I", len(wire)) + wire
                sent = summary["original_started_ns"] + record["sent_offset_ns"]
                self.assertEqual(write["sequence"], sequence)
                self.assertEqual(write["frame_sha256"], hashlib.sha256(wire).hexdigest())
                self.assertEqual(write["original_sent_ns"], sent)
                self.assertEqual(write["original_deadline_ns"], min(started["original_end_ns"], sent + 1_000_000_000))
                self.assertLessEqual(sent, write["before_ns"])
                self.assertLessEqual(write["before_ns"], write["returned_ns"])
                self.assertEqual((write["offset"], write["requested"], write["accepted"], write["errno"]),
                                 (0, len(wire), len(wire), None))
            self.assertEqual(rows[-1]["kind"], "finish")
            self.assertEqual((summary["records_emitted"], summary["bytes_emitted"]), (len(rows), len(raw)))

    def test_actual_udp_original_eight_requests_and_absolute_deadlines(self):
        self.loopback("udp")

    def test_actual_tcp_original_eight_requests_on_one_connection(self):
        self.loopback("tcp")

    def test_actual_udp_cli_inherits_only_owned_pipe_and_emits_child_identity(self):
        self.loopback("udp", cli=True)

    def test_actual_udp_full_pipe_keeps_all_eight_business_results(self):
        self.loopback("udp", True)

    def test_actual_tcp_full_pipe_keeps_all_eight_business_results(self):
        self.loopback("tcp", True)

    def test_partial_tcp_syscalls_keep_offsets_bytes_and_one_original_deadline(self):
        observer = self.observer()
        calls = []

        class PartialSocket:
            def settimeout(self, timeout):
                calls.append(("timeout", timeout))

            def send(self, data):
                calls.append(("send", data))
                return min(3, len(data))

        data = b"abcdef"
        deadline = time.monotonic_ns() + 1_000_000_000
        sent = deadline - 1_000_000_000
        self.assertEqual(tcp.write_frame(PartialSocket(), data, deadline, facts=observer, sequence=7, sent=sent), 10)
        observer.finish("completed")
        rows, _ = self.read_events()
        writes = [r for r in rows if r["kind"] == "write"]
        wire = struct.pack("!I", len(data)) + data
        self.assertEqual([r["offset"] for r in writes], [0, 3, 6, 9])
        self.assertEqual([r["accepted"] for r in writes], [3, 3, 3, 1])
        self.assertEqual([r["requested"] for r in writes], [10, 7, 4, 1])
        self.assertEqual([value for kind, value in calls if kind == "send"], [wire[n:] for n in [0, 3, 6, 9]])
        self.assertTrue(all(r["original_deadline_ns"] == deadline and r["original_sent_ns"] == sent for r in writes))
        self.assertTrue(all(r["frame_sha256"] == hashlib.sha256(wire).hexdigest() for r in writes))

    def test_original_send_exception_and_numeric_errno_are_retained_once(self):
        observer = self.observer()
        original = OSError(errno.ENOBUFS, "test send pressure")
        with patch.object(socket.socket, "sendto", side_effect=original) as send:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                with self.assertRaises(OSError) as caught:
                    observer.send(sock, b"frame", sequence=0, sent=1, deadline=2, frame=b"frame", target=self.config.target)
        self.assertIs(caught.exception, original)
        send.assert_called_once_with(b"frame", self.config.target)
        observer.finish("send_error")
        rows, _ = self.read_events()
        write = next(r for r in rows if r["kind"] == "write")
        self.assertIsNone(write["accepted"])
        self.assertEqual(write["errno"], errno.ENOBUFS)

    def test_zero_tcp_return_does_not_become_a_full_write_or_retry(self):
        observer = self.observer()
        with patch.object(socket.socket, "settimeout"), patch.object(socket.socket, "send", return_value=0) as send:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                with self.assertRaisesRegex(OSError, "zero TCP write"):
                    tcp.write_frame(sock, b"frame", time.monotonic_ns() + 1_000_000_000, facts=observer)
        self.assertEqual(send.call_count, 1)
        observer.finish("send_error")
        rows, _ = self.read_events()
        self.assertEqual([r["accepted"] for r in rows if r["kind"] == "write"], [0])

    def test_deadline_expiry_before_original_send_emits_no_write(self):
        observer = self.observer()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock, patch.object(socket.socket, "send") as send:
            with self.assertRaises(TimeoutError):
                tcp.write_frame(sock, b"frame", time.monotonic_ns() - 1, facts=observer)
            send.assert_not_called()
        observer.finish("deadline")
        rows, _ = self.read_events()
        self.assertFalse(any(r["kind"] == "write" for r in rows))

    def test_broken_pipe_short_pipe_write_and_capacity_disable_without_retry(self):
        for kind, effect, reason in [
            ("broken", BrokenPipeError(errno.EPIPE, "closed"), "observation_pipe_failed"),
            ("short", 1, "observation_short_write"),
        ]:
            observer = self.observer()
            with self.subTest(kind=kind), patch.object(facts.os, "write", side_effect=effect if isinstance(effect, Exception) else None,
                                                      return_value=effect if type(effect) is int else None) as write:
                observer.emit("test")
                observer.emit("no_retry")
                self.assertEqual(write.call_count, 1)
            self.assertEqual(observer.finish("completed")["emission_gap_reason"], reason)
        observer = self.observer()
        with patch.object(facts, "MAX_EVENTS", observer.events), patch.object(facts.os, "write") as write:
            observer.emit("capacity")
            write.assert_not_called()
        self.assertEqual(observer.finish("completed")["emission_gap_reason"], "observation_capacity")

    def test_changed_process_or_oversize_record_cannot_continue_original_stream(self):
        for changed_pid in [False, True]:
            observer = self.observer()
            with self.subTest(changed_pid=changed_pid), patch.object(facts.os, "write") as write:
                if changed_pid:
                    with patch.object(facts.os, "getpid", return_value=observer.pid + 1):
                        observer.emit("forked")
                else:
                    observer.emit("oversize", data="x" * 513)
                observer.emit("no_retry")
                write.assert_not_called()
            self.assertEqual(observer.finish("completed")["emission_gap_reason"],
                             "producer_process_changed" if changed_pid else "observation_capacity")


if __name__ == "__main__":
    unittest.main()
