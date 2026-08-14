#!/usr/bin/env python3
"""Regression tests for real-TUN first-business evidence parsing."""

from __future__ import print_function

import importlib.util
import pathlib
import tempfile
import unittest


PARSER_PATH = pathlib.Path(__file__).with_name("production-availability-parser.py")
SPEC = importlib.util.spec_from_file_location("production_availability", str(PARSER_PATH))
PARSER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PARSER)


def line(event, t_ms, peer="air", generation=7, path=None):
    path_text = "" if path is None else ' path=Some("%s")' % path
    return (
        '2026-08-14T00:00:00.000Z t_ms=%d event="%s" '
        'detail=Some("peer=%s generation=%d")%s\n'
        % (t_ms, event, peer, generation, path_text)
    )


class ProductionAvailabilityParserTest(unittest.TestCase):
    def parse(self, content, peer="air"):
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as stream:
            stream.write(content)
            stream.flush()
            return PARSER.first_business_info(stream.name, peer)

    def test_real_business_before_local_probe_ack_is_valid_relay_evidence(self):
        result = self.parse(
            line("relay_transport_ready_peer", 100)
            + line("first_real_business_ingress", 140, path="relay")
        )
        self.assertEqual(result, "relay|40|7|ok")

    def test_missing_ready_boundary_fails_closed(self):
        result = self.parse(line("first_real_business_ingress", 140, path="relay"))
        self.assertEqual(result, "|missing|7|relay_transport_ready_missing")

    def test_direct_first_business_is_not_relay_first(self):
        result = self.parse(
            line("relay_transport_ready_peer", 100)
            + line("first_real_business_ingress", 140, path="direct")
        )
        self.assertEqual(result, "|missing|7|first_business_not_relay")

    def test_stale_generation_does_not_supply_current_ready_boundary(self):
        result = self.parse(
            line("relay_transport_ready_peer", 100, generation=6)
            + line("first_real_business_ingress", 140, generation=7, path="relay")
        )
        self.assertEqual(result, "|missing|7|relay_transport_ready_missing")


if __name__ == "__main__":
    unittest.main()
