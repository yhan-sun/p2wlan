#!/usr/bin/env python3
"""Optional two-sample OS TCP counters; no per-request or P2WLAN attribution.

Only inspect the existing connected socket. Never send, reconnect, retry,
start background work, change socket settings or refresh a business deadline.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import socket
import struct
import sys
import time

LAYOUTS = {
    "linux": ("linux_TCP_INFO", 104, {"tcpi_total_retrans": (100, "I", "segments")},
              {"tcpi_rtt": (68, "I", "microseconds"), "tcpi_unacked": (24, "I", "segments")}),
    "darwin": ("darwin_TCP_CONNECTION_INFO", 112,
               {"tcpi_txretransmitbytes": (72, "Q", "bytes"),
                "tcpi_txretransmitpackets": (104, "Q", "packets")},
               {"tcpi_srtt": (44, "I", "milliseconds"), "tcpi_snd_sbbytes": (32, "I", "bytes")}),
    "win32": ("windows_SIO_TCP_INFO_v0", 88, {"BytesRetrans": (68, "I", "bytes")},
              {"RttUs": (20, "I", "microseconds"), "BytesInFlight": (28, "I", "bytes")}),
}


def decode(platform: str, raw: bytes) -> dict:
    if platform not in LAYOUTS:
        raise ValueError("unsupported_platform")
    api, minimum, counters, gauges = LAYOUTS[platform]
    if type(raw) is not bytes or len(raw) != minimum:
        raise ValueError("unexpected_TCP_information_length")
    def fields(layout):
        return {name: {"value": struct.unpack_from("=" + fmt, raw, offset)[0], "unit": unit}
                for name, (offset, fmt, unit) in layout.items()}
    return {"api": api, "returned_bytes": len(raw), "counters": fields(counters), "gauges": fields(gauges)}


def _windows_info(sock: socket.socket) -> bytes:
    import ctypes
    # DWORD remains 32-bit; SOCKET is UINT_PTR. No asynchronous operation.
    library = ctypes.WinDLL("Ws2_32.dll")
    ioctl = library.WSAIoctl
    ioctl.argtypes = [ctypes.c_size_t, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32,
                      ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32),
                      ctypes.c_void_p, ctypes.c_void_p]
    ioctl.restype = ctypes.c_int
    error = library.WSAGetLastError
    error.argtypes, error.restype = [], ctypes.c_int
    version, returned = ctypes.c_uint32(0), ctypes.c_uint32(0)
    output = ctypes.create_string_buffer(88)
    # _WSAIORW(IOC_VENDOR,39): IOC_INOUT | 0x18000000 | 39.
    result = ioctl(sock.fileno(), 0xD8000027, ctypes.byref(version), 4,
                   output, len(output), ctypes.byref(returned), None, None)
    if result != 0:
        raise OSError(error(), "SIO_TCP_INFO_failed")
    if returned.value != len(output):
        raise ValueError("unexpected_TCP_information_length")
    return output.raw


def _native(sock: socket.socket, platform: str) -> bytes:
    if platform == "win32":
        return _windows_info(sock)
    if platform == "linux":
        return sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_INFO, 104)
    if platform == "darwin":
        return sock.getsockopt(socket.IPPROTO_TCP, 0x106, 112)
    raise ValueError("unsupported_platform")


def sample(sock: socket.socket) -> dict:
    result = {"platform": sys.platform, "started_monotonic_ns": time.monotonic_ns(),
              "availability": "unavailable", "connection": None}
    try:
        if sock.family not in (socket.AF_INET, socket.AF_INET6) or sock.type != socket.SOCK_STREAM:
            raise ValueError("not_an_IP_TCP_stream")
        result["connection"] = {"descriptor": sock.fileno(), "family": int(sock.family),
                                "local": list(sock.getsockname()), "peer": list(sock.getpeername())}
        result.update(decode(sys.platform, _native(sock, sys.platform)), availability="available")
    except OSError as error:
        result.update(reason="socket_information_failed", errno=error.errno)
    except (ValueError, AttributeError, struct.error) as error:
        result.update(reason="unsupported_or_invalid_information", detail=type(error).__name__)
    result["finished_monotonic_ns"] = time.monotonic_ns()
    return result


def interval(first: dict, last: dict) -> dict:
    result = {"availability": "unavailable", "reason": "incomplete_samples", "counters": {}}
    if first["availability"] != "available" or last["availability"] != "available":
        return result
    if (first["connection"] != last["connection"] or first["api"] != last["api"]
            or first["platform"] != last["platform"]
            or first["finished_monotonic_ns"] > last["started_monotonic_ns"]):
        return dict(result, reason="connection_or_sample_order_changed")
    result.update(availability="available", reason="same_connection_interval")
    for name, before in first["counters"].items():
        after = last["counters"].get(name)
        if after is None or before["unit"] != after["unit"]:
            result["counters"][name] = {"availability": "unavailable", "reason": "counter_shape_changed"}
        elif after["value"] < before["value"]:
            result["counters"][name] = {"availability": "unavailable", "reason": "counter_decreased"}
        else:
            result["counters"][name] = {"availability": "available", "delta": after["value"] - before["value"],
                                        "unit": before["unit"]}
    return result


class SocketObservation:
    """Begin once after connect; finish once before handoff/close."""
    def __init__(self):
        self.source_sha256 = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        self._socket = None
        self._first = None
        self._finished = False

    def begin(self, sock: socket.socket) -> None:
        if self._first is not None or self._finished:
            raise ValueError("TCP observation already started or finished")
        self._socket, self._first = sock, sample(sock)

    def finish(self) -> dict:
        if self._finished:
            raise ValueError("TCP observation already finished")
        self._finished = True
        report = {"schema_version": 1, "scope": "same_OS_TCP_connection_interval_only",
                  "collector_sha256": self.source_sha256, "sample_budget": 2,
                  "clock": "local_tool_process_monotonic_ns", "request_attribution_verified": False,
                  "p2wlan_path_verified": False, "native_owner_credit_verified": False, "samples": []}
        if self._first is None:
            report.update(availability="unavailable", reason="no_connected_socket_observed", interval=None)
            return report
        last = sample(self._socket)
        report.update(samples=[self._first, last], interval=interval(self._first, last))
        report["availability"] = report["interval"]["availability"]
        self._socket = None
        return report
