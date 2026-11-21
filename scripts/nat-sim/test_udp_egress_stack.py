"""Run the actual UDP interceptor on a bounded native worker stack."""

import asyncio
import errno
import os
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
import unittest

import udp_egress
from test_udp_egress import Capture, envelope


SENDER = r'''
#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

struct input {
    int fd;
    struct sockaddr_in destination;
    long vector_count;
    ssize_t maximum_sent;
    int maximum_errno;
};

static void *send_packets(void *opaque) {
    struct input *input = opaque;
    struct sockaddr *destination = (struct sockaddr *)&input->destination;
    socklen_t size = sizeof(input->destination);
    fprintf(stderr, "bounded worker entered original libc sends\n");
    if (sendto(input->fd, "small", 5, MSG_DONTWAIT, destination, size) != 5)
        return (void *)(uintptr_t)11;
    if (sendto(input->fd, NULL, 0, MSG_DONTWAIT, destination, size) != 0)
        return (void *)(uintptr_t)12;
    struct iovec parts[] = {{"scatter", 7}, {NULL, 0}, {"-gather", 7}};
    struct msghdr message = {0};
    message.msg_name = destination;
    message.msg_namelen = size;
    message.msg_iov = parts;
    message.msg_iovlen = 3;
    if (sendmsg(input->fd, &message, MSG_DONTWAIT) != 14)
        return (void *)(uintptr_t)13;
    message.msg_iovlen = 0;
    if (sendmsg(input->fd, &message, MSG_DONTWAIT) != 0)
        return (void *)(uintptr_t)14;
    if (sendto(input->fd, NULL, 1, 0, destination, size) != -1 || errno != EFAULT)
        return (void *)(uintptr_t)15;
    if (sendto(input->fd, NULL, 65492, 0, destination, size) != -1 || errno != EMSGSIZE)
        return (void *)(uintptr_t)16;
    parts[0].iov_base = NULL;
    message.msg_iovlen = 1;
    if (sendmsg(input->fd, &message, 0) != -1 || errno != EFAULT)
        return (void *)(uintptr_t)17;
    char control = 0;
    message.msg_control = &control;
    message.msg_controllen = 1;
    if (sendmsg(input->fd, &message, 0) != -1 || errno != EOPNOTSUPP)
        return (void *)(uintptr_t)18;
    message.msg_control = NULL;
    message.msg_controllen = 0;
    message.msg_iov = NULL;
    if (sendmsg(input->fd, &message, 0) != -1 || errno != EFAULT)
        return (void *)(uintptr_t)24;
    input->vector_count = sysconf(_SC_IOV_MAX);
    if (input->vector_count < 1 || input->vector_count > 65491)
        return (void *)(uintptr_t)19;
    struct iovec *many = calloc((size_t)input->vector_count, sizeof(*many));
    if (!many) return (void *)(uintptr_t)20;
    char value = 'v';
    for (long index = 0; index < input->vector_count; index++) {
        many[index].iov_base = &value;
        many[index].iov_len = 1;
    }
    message.msg_iov = many;
    message.msg_iovlen = input->vector_count;
    ssize_t sent = sendmsg(input->fd, &message, MSG_DONTWAIT);
    free(many);
    if (sent != input->vector_count) return (void *)(uintptr_t)21;
    char *maximum = malloc(65491);
    if (!maximum) return (void *)(uintptr_t)22;
    memset(maximum, 'z', 65491);
    input->maximum_sent = sendto(input->fd, maximum, 65491, MSG_DONTWAIT, destination, size);
    input->maximum_errno = errno;
    free(maximum);
    /* macOS may impose a smaller kernel UDP limit. That is an actual failed
     * handoff, preserved in error counters rather than an invented success. */
    if (input->maximum_sent != 65491 &&
        !(input->maximum_sent == -1 && input->maximum_errno == EMSGSIZE))
        return (void *)(uintptr_t)23;
    return NULL;
}

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    struct input input = {0};
    input.fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (input.fd < 0) return 3;
    struct sockaddr_in local = {0};
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(input.fd, (struct sockaddr *)&local, sizeof(local))) {
        close(input.fd); return 4;
    }
    socklen_t length = sizeof(local);
    if (getsockname(input.fd, (struct sockaddr *)&local, &length)) {
        close(input.fd); return 5;
    }
    input.destination = local;
    input.destination.sin_port = htons((uint16_t)atoi(argv[1]));
    pthread_attr_t attr;
    if (pthread_attr_init(&attr)) { close(input.fd); return 6; }
    if (pthread_attr_setstacksize(&attr, 64 * 1024)) {
        pthread_attr_destroy(&attr); close(input.fd); return 7;
    }
    pthread_t worker;
    int created = pthread_create(&worker, &attr, send_packets, &input);
    pthread_attr_destroy(&attr);
    if (created) { close(input.fd); return 8; }
    void *result = NULL;
    int joined = pthread_join(worker, &result);
    close(input.fd);
    if (joined) return 9;
    fprintf(stderr, "bounded worker joined; original socket closed\n");
    if (result) return (int)(uintptr_t)result;
    printf("%u %ld %zd %d\n", ntohs(local.sin_port), input.vector_count,
           input.maximum_sent, input.maximum_errno);
    return 0;
}
'''


class UdpEgressStackTests(unittest.IsolatedAsyncioTestCase):
    async def test_real_sendto_and_sendmsg_on_bounded_native_stack(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            library, sender = root / "shim.so", root / "sender"
            source = root / "sender.c"
            source.write_text(SENDER)
            udp_egress.build(library)
            subprocess.run([os.environ.get("CC", "cc"), "-Wall", "-Wextra", "-Werror",
                            "-pthread", str(source), "-o", str(sender)], check=True)
            capture = Capture()
            transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
                lambda: capture, local_addr=("127.0.0.1", 0))
            gateway = transport.get_extra_info("sockname")
            process = None
            try:
                process = await asyncio.create_subprocess_exec(
                    str(sender), "32001",
                    env=udp_egress.environment(library, gateway[1], root / "egress-stats"),
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                stdout, stderr = await asyncio.wait_for(process.communicate(), 15)
                # The child is reaped before any assertion, including the old
                # shim's native stack failure. A crash does not imply thread join.
                self.assertEqual(process.returncode, 0, (process.returncode, stderr.decode()))
                self.assertIn(b"bounded worker joined; original socket closed", stderr)
                port, vectors, maximum_sent, maximum_errno = map(int, stdout.split())
                original = ("127.0.0.1", port)
                payloads = [b"small", b"", b"scatter-gather", b"", b"v" * vectors]
                if maximum_sent == 65491:
                    payloads.append(b"z" * 65491)
                else:
                    self.assertEqual((maximum_sent, maximum_errno), (-1, errno.EMSGSIZE))
                for payload in payloads:
                    received = await asyncio.wait_for(capture.queue.get(), 1)
                    self.assertEqual(received, (envelope(("127.0.0.1", 32001), payload), original))
                counters = struct.unpack("=8sQQQQ", (root / "egress-stats").read_bytes())
                self.assertEqual(counters, (b"P2CNT001", len(payloads),
                                           sum(map(len, payloads)), int(maximum_sent == -1), gateway[1]))
            finally:
                if process is not None and process.returncode is None:
                    process.kill()
                    await process.wait()
                transport.close()


if __name__ == "__main__":
    unittest.main()
