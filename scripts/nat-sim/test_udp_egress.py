"""Exercise real libc interception and strict NAT routing without a daemon build."""

import asyncio
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import unittest

import nat_sim
import udp_egress
from mapping_evidence import summarize_mapping_evidence


NATIVE_SENDER = r'''
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>
int main(int argc, char **argv) {
    if (argc != 4) return 2;
    if (getenv("P2WLAN_TEST_CAPTURE_CHILD_FIRST")) {
        pid_t child = fork();
        if (child < 0) return 10;
        if (!child) {
            int local[2];
            if (socketpair(AF_UNIX, SOCK_DGRAM, 0, local)) _exit(1);
            _exit(sendto(local[0], "x", 1, 0, NULL, 0) == 1 ? 0 : 2);
        }
        int status;
        if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status)) return 11;
    }
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in address = {0};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(fd, (struct sockaddr *)&address, sizeof(address))) return 3;
    struct timeval timeout = {1, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    unsigned char request[20] = {0, 1, 0, 0, 0x21, 0x12, 0xa4, 0x42};
    char response[128];
    address.sin_port = htons(atoi(argv[1]));
    if (sendto(fd, request, sizeof(request), 0, (struct sockaddr *)&address, sizeof(address)) != 20) return 4;
    if (recv(fd, response, sizeof(response), 0) < 20) return 5;
    address.sin_port = htons(atoi(argv[2]));
    if (sendto(fd, "first", 5, 0, (struct sockaddr *)&address, sizeof(address)) != 5) return 6;
    struct iovec vectors[] = {{"second", 6}, {"-iov", 4}};
    struct msghdr message = {0};
    address.sin_port = htons(atoi(argv[3]));
    message.msg_name = &address;
    message.msg_namelen = sizeof(address);
    message.msg_iov = vectors;
    message.msg_iovlen = 2;
    if (sendmsg(fd, &message, 0) != 10) return 7;
    /* Repeated destination must retain its mapping and consume no new noise. */
    if (sendmsg(fd, &message, 0) != 10) return 8;
    char large[65492] = {0};
    if (sendto(fd, large, sizeof(large), 0, (struct sockaddr *)&address, sizeof(address)) != -1 || errno != EMSGSIZE) return 9;
    socklen_t length = sizeof(address);
    getsockname(fd, (struct sockaddr *)&address, &length);
    printf("%u\n", ntohs(address.sin_port));
    close(fd);
    return 0;
}
'''


class Capture(asyncio.DatagramProtocol):
    def __init__(self):
        self.queue = asyncio.Queue()

    def datagram_received(self, data, source):
        self.queue.put_nowait((data, source))


def envelope(destination, data):
    return (b"P2NAT001" + socket.inet_aton(destination[0]) +
            struct.pack("!HH", destination[1], len(data)) + data)


def unused_port():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as stream:
        stream.bind(("127.0.0.1", 0))
        return stream.getsockname()[1]


class UdpEgressTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp.name)
        cls.library = cls.root / "shim.so"
        cls.sender = cls.root / "sender"
        source = cls.root / "sender.c"
        source.write_text(NATIVE_SENDER)
        udp_egress.build(cls.library)
        subprocess.run([os.environ.get("CC", "cc"), "-Wall", "-Wextra", "-Werror",
                        str(source), "-o", str(cls.sender)], check=True)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    async def test_recorder_cli_keeps_intent_without_injecting_intermediate_python(self):
        port = unused_port()
        stats = self.root / "recorder.stats"
        keys = ("DYLD_INSERT_LIBRARIES", "LD_PRELOAD",
                "P2WLAN_NAT_SIM_GATEWAY_PORT", "P2WLAN_NAT_SIM_EGRESS_STATS")
        code = "import json,os;print(json.dumps({'pid':os.getpid(),'env':{k:os.environ.get(k) for k in " + repr(keys) + "}}))"
        child = await asyncio.create_subprocess_exec(
            sys.executable, str(Path(udp_egress.__file__)), "--recorder",
            "--library", str(self.library), "--port", str(port), "--stats", str(stats),
            "--", sys.executable, "-c", code,
            env=udp_egress.recorder_environment(os.environ),
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        try:
            stdout, stderr = await asyncio.wait_for(child.communicate(), 15)
            self.assertEqual(child.returncode, 0, stderr.decode())
            observed = json.loads(stdout)
            self.assertEqual(observed["pid"], child.pid)
            self.assertEqual(observed["env"], dict(zip(keys, (None, None, str(port), str(stats.resolve())))))
        finally:
            if child.returncode is None:
                child.kill()
                await child.wait()

    async def asyncSetUp(self):
        self.nats = []
        self.transports = []
        self.trace_path = self.root / f"{self._testMethodName}.jsonl"
        self.trace = nat_sim.NatTrace(str(self.trace_path))
        self.fabric = nat_sim.NatFabric(self.trace)

    async def asyncTearDown(self):
        for nat in self.nats:
            await nat.close()
        for transport in self.transports:
            transport.close()
        self.trace.close()

    async def nat(self, name, **options):
        nat = nat_sim.Nat(name, "127.0.0.1", options.pop("step", 1),
                          7 if name == "A" else 8, options.pop("base_port", unused_port()),
                          strict_filtering=True, **options)
        await nat.start(self.fabric)
        gateway = await nat.add_egress_gateway()
        self.nats.append(nat)
        return nat, gateway

    async def endpoint(self):
        capture = Capture()
        transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
            lambda: capture, local_addr=("127.0.0.1", 0))
        self.transports.append(transport)
        return transport, capture, transport.get_extra_info("sockname")

    async def test_native_sendto_sendmsg_capture_unbound_destinations_and_source_socket(self):
        nat, gateway = await self.nat("A", consume_before_punch=2,
                                      sweep_noise_every=1, sweep_noise_count=3, sweep_noise_limit=2)
        observer = await nat.add_observer()
        # These host sockets are deliberately outside the NAT topology. A
        # guessed port must create a source mapping but must never bypass NAT.
        _, private_capture, destination_a = await self.endpoint()
        _, other_capture, destination_b = await self.endpoint()
        process = await asyncio.create_subprocess_exec(
            str(self.sender), str(observer[1]), str(destination_a[1]), str(destination_b[1]),
            env=udp_egress.environment(self.library, gateway[1], self.root / "native.egress-stats"),
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), 15)
        finally:
            if process.returncode is None:
                process.kill()
                await process.wait()
        self.assertEqual(process.returncode, 0, stderr.decode())
        source = ("127.0.0.1", int(stdout))
        for _ in range(100):
            if (source, destination_b) in nat.mappings and not nat.mappings[(source, destination_b)].pending:
                break
            await asyncio.sleep(0.001)
        self.assertIn((source, observer), nat.mappings)
        self.assertIn((source, destination_a), nat.mappings)
        self.assertIn((source, destination_b), nat.mappings)
        self.assertEqual(len(nat.mappings), 3)
        self.assertEqual(len(nat.noise_ports), 4)
        self.assertEqual(nat.sweep_noise_remaining, 0)
        self.assertTrue(private_capture.queue.empty())
        self.assertTrue(other_capture.queue.empty())
        rows = [json.loads(line) for line in self.trace_path.read_text().splitlines()]
        events = [row["event"] for row in rows]
        self.assertEqual(events.count("egress_captured"), 4)
        counters = struct.unpack("=8sQQQQ", (self.root / "native.egress-stats").read_bytes())
        self.assertEqual(counters, (b"P2CNT001", 4, 45, 0, gateway[1]))
        self.assertEqual(events.count("outbound_destination_unmapped"), 3)
        observed = next(row["sequence"] for row in rows if row["event"] == "stun_mapping_observed")
        initial = [row["sequence"] for row in rows if row["event"] == "mapping_consumed"
                   and row["stage"] == "post_measurement_before_first_peer"]
        first_peer = next(row["sequence"] for row in rows if row["event"] == "peer_mapping_started")
        self.assertEqual(len(initial), 2)
        self.assertTrue(all(observed < value < first_peer for value in initial))

    async def test_strict_bilateral_reciprocal_mapping_and_real_public_source(self):
        a, gateway_a = await self.nat("A")
        b, gateway_b = await self.nat("B")
        client_a, received_a, source_a = await self.endpoint()
        client_b, received_b, source_b = await self.endpoint()
        expected_a = ("127.0.0.1", a.next_port)
        expected_b = ("127.0.0.1", b.next_port)
        client_a.sendto(envelope(expected_b, b"a-to-b"), gateway_a)
        for _ in range(100):
            if expected_a[1] in a.forwarders:
                break
            await asyncio.sleep(0.001)
        client_b.sendto(envelope(expected_a, b"b-to-a"), gateway_b)
        self.assertEqual(await asyncio.wait_for(received_a.queue.get(), 1), (b"b-to-a", expected_b))
        client_a.sendto(envelope(expected_b, b"a-again"), gateway_a)
        self.assertEqual(await asyncio.wait_for(received_b.queue.get(), 1), (b"a-again", expected_a))
        self.assertEqual(len(self.fabric.reciprocal_pairs), 1)
        # The same remote daemon's unrelated mapping must still be rejected.
        alien = b.mapping_for(source_b, ("127.0.0.1", unused_port()))
        await b.ensure_bound(alien)
        self.fabric.route_translated(b, alien, b"reject", expected_a)
        self.assertTrue(received_a.queue.empty())
        self.assertEqual(len(a.mappings), 1)
        self.assertEqual(a.mappings[(source_a, expected_b)].port, expected_a[1])

    async def test_unmeasured_socket_and_retransmissions_do_not_spend_phase_noise(self):
        a, gateway = await self.nat("A", consume_before_punch=3,
                                    sweep_noise_every=1, sweep_noise_count=1, sweep_noise_limit=2)
        client, _, source = await self.endpoint()
        destination = ("127.0.0.1", unused_port())
        for _ in range(3):
            client.sendto(envelope(destination, b"probe"), gateway)
        for _ in range(100):
            if a.peer_mapping_counts.get(source) == 1:
                break
            await asyncio.sleep(0.001)
        self.assertEqual(len(a.noise_ports), 0)
        self.assertEqual(a.peer_mapping_counts[source], 1)

    async def test_invalid_gateway_payload_cannot_create_mapping(self):
        a, gateway = await self.nat("A")
        client, _, _ = await self.endpoint()
        client.sendto(b"not an envelope", gateway)
        client.sendto(envelope(("192.0.2.1", 9000), b"outside"), gateway)
        await asyncio.sleep(0.01)
        self.assertEqual(a.mappings, {})
        self.assertEqual(a.client_sockets, set())

    async def test_closed_gate_and_blackhole_allocate_source_mapping_before_dropping(self):
        for blocked in (False, True):
            with self.subTest(block_direct=blocked):
                gate = self.root / f"closed-{blocked}.gate"
                a, gateway = await self.nat("A", block_direct=blocked,
                                            direct_gate_file=str(gate), consume_before_punch=2)
                observer = await a.add_observer()
                client, replies, source = await self.endpoint()
                request = struct.pack("!HHI", 1, 0, nat_sim.MAGIC_COOKIE) + bytes(12)
                client.sendto(envelope(observer, request), gateway)
                await asyncio.wait_for(replies.queue.get(), 1)
                _, target_capture, destination = await self.endpoint()
                client.sendto(envelope(destination, b"blocked"), gateway)
                for _ in range(100):
                    mapping = a.mappings.get((source, destination))
                    if mapping is not None and mapping.bound_reported:
                        break
                    await asyncio.sleep(0.001)
                self.assertIn((source, destination), a.mappings)
                self.assertEqual(len(a.noise_ports), 2)
                self.assertTrue(target_capture.queue.empty())
                rows = [json.loads(line) for line in self.trace_path.read_text().splitlines()]
                self.assertTrue(any(row.get("event") == "direct_blocked" for row in rows))


class MappingEvidenceTests(unittest.TestCase):
    def write_evidence(self, root, rows, *, packets_b=1):
        features = {
            "egress_capture": "shim", "unassigned_egress_listeners": 0,
            "direct_gate_preserves_source_allocations": True,
            "strict_filtering_a": True, "strict_filtering_b": True,
            "consume_a": 1, "consume_b": 1,
            "sweep_noise_every": 0, "sweep_noise_count": 0, "sweep_noise_limit": 64,
        }
        (root / "nat-sim.out").write_text("NAT_FEATURES=" + json.dumps(features) + "\n")
        (root / "nat-trace.jsonl").write_text("".join(
            json.dumps({"sequence": index + 1, **row}) + "\n" for index, row in enumerate(rows)))
        for side, port, packets in (("a", 45000, 1), ("b", 45001, packets_b)):
            (root / f"node-{side}.egress-stats").write_bytes(
                struct.pack("=8sQQQQ", b"P2CNT001", packets, 20, 0, port))
        return summarize_mapping_evidence(root, {
            "STRICT_FILTERING_A": "1", "STRICT_FILTERING_B": "1", "CONSUME_A": "1", "CONSUME_B": "1"})

    def valid_rows(self):
        rows = []
        for side, port, own, peer in (("A", 45000, "127.0.0.1:16000", "127.0.0.1:26000"),
                                      ("B", 45001, "127.0.0.1:26000", "127.0.0.1:16000")):
            common = {"nat": side, "client": side + "-socket"}
            rows.extend([
                {**common, "event": "egress_gateway_ready", "gateway_port": port},
                {**common, "event": "egress_captured", "bytes": 20},
                {**common, "event": "stun_mapping_observed"},
                {**common, "event": "mapping_consumed", "stage": "post_measurement_before_first_peer"},
                {**common, "event": "peer_mapping_started", "prior_peer_mappings": 0},
                {**common, "event": "mapping_bound", "public_endpoint": own, "destination": peer},
            ])
        return rows

    def test_reciprocal_pairs_are_derived_and_not_promoted_to_business_success(self):
        with tempfile.TemporaryDirectory() as directory:
            rows = self.valid_rows()
            rows.append({"event": "reciprocal_mapping_pair", "pair_count": 99})
            evidence = self.write_evidence(Path(directory), rows)
            self.assertTrue(evidence["valid"], evidence["errors"])
            self.assertEqual(evidence["reciprocal_mapping_pairs"], 1)
            self.assertIn("not_attempt_or_business_success", evidence["scope"])
            rows[-2]["destination"] = "127.0.0.1:16001"
            evidence = self.write_evidence(Path(directory), rows)
            self.assertTrue(evidence["valid"], evidence["errors"])
            self.assertEqual(evidence["reciprocal_mapping_pairs"], 0)

    def test_gateway_packet_loss_invalidates_fidelity_without_hiding_attempt_cost(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence = self.write_evidence(Path(directory), self.valid_rows(), packets_b=2)
            self.assertFalse(evidence["valid"])
            self.assertIn("b_egress_capture_loss_or_duplicate", evidence["errors"])
            self.assertEqual(evidence["shim_send_counters"]["B"]["datagrams"], 2)
            self.assertEqual(evidence["egress_datagrams"]["B"], 1)

    def test_consumption_before_measurement_or_after_first_peer_is_invalid(self):
        for swap in (2, 4):
            with self.subTest(swap=swap), tempfile.TemporaryDirectory() as directory:
                rows = self.valid_rows()
                rows[3], rows[swap] = rows[swap], rows[3]
                evidence = self.write_evidence(Path(directory), rows)
                self.assertFalse(evidence["valid"])
                self.assertIn("mapping_noise_outside_measurement_peer_window", evidence["errors"])

    def test_missing_capture_and_fake_feature_labels_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "nat-sim.out").write_text('NAT_FEATURES={"egress_capture":"shim"}\n')
            (root / "nat-trace.jsonl").write_text('{"sequence":1,"event":"mapped"}\n')
            evidence = summarize_mapping_evidence(root, {})
            self.assertFalse(evidence["valid"])
            self.assertIn("a_complete_egress_capture_missing", evidence["errors"])
            self.assertIn("b_complete_egress_capture_missing", evidence["errors"])

    def test_noise_budget_arguments_reject_unbounded_values(self):
        for options in ({"consume_before_punch": 65}, {"sweep_noise_limit": 4097},
                        {"sweep_noise_count": -1}, {"sweep_noise_every": 1025}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                nat_sim.Nat("A", "127.0.0.1", 1, 1, 16000, **options)


if __name__ == "__main__":
    unittest.main()
