#!/usr/bin/env python3
"""Fixture driver isolation; original inline Python retains its own startup.

This exercises a real generated launcher and configuration rejection. It
does not start the topology CLI or establish a NAT or cleanup result.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import test_actual_http_pair_signal as legacy

PROTOCOL_SECONDS = 4


class FixtureDriverSiteContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        destination = os.environ.get("P2WLAN_B01_FIXTURE_ARTIFACTS")
        if destination:
            cls.root = Path(destination) / "fixture-driver-site-contracts"
            cls.root.mkdir(mode=0o700)
        else:
            temporary = tempfile.TemporaryDirectory(prefix="p2wlan-driver-site-")
            cls.addClassCleanup(temporary.cleanup)
            cls.root = Path(temporary.name)
        cls.fixture = legacy.HttpPairSignalCliFixture(cls.root / "prepared", legacy.source_repository(),
                                              "barrier-pair-term", 1)
        cls.addClassCleanup(cls.fixture.close)
        cls.original_config = (cls.fixture.root / "fixture-config.json").read_bytes()
        cls.hooks = cls.root / "startup-hooks"
        cls.hooks.mkdir(mode=0o700)
        payload = ("import json,os,sys\n"
                   "row={'pid':os.getpid(),'argv':sys.argv,'no_site':sys.flags.no_site}\n"
                   "fd=os.open(os.environ['B01_SITE_RECORD'],os.O_WRONLY|os.O_APPEND|os.O_CREAT,0o600)\n"
                   "os.write(fd,(json.dumps(row,sort_keys=True)+'\\n').encode());os.close(fd)\n")
        with (cls.hooks / "sitecustomize.py").open("x") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(payload)

    def run_inline(self, arguments, *, stdin=None, reject_config=False):
        stage = self.root / self._testMethodName
        stage.mkdir(mode=0o700)
        record = stage / "site-record.jsonl"
        environment = {**self.fixture.environment, "PYTHONPATH":str(self.hooks),
                       "B01_SITE_RECORD":str(record), "B01_INLINE_NONCE":"inline-transport-v1"}
        config = self.fixture.root / "fixture-config.json"
        if reject_config:
            value = json.loads(self.original_config)
            del value["real_python"]
            config.write_text(json.dumps(value, sort_keys=True) + "\n")
        timed_out = False
        try:
            process = subprocess.Popen([str(self.fixture.root / "fake-path/python3"), *arguments],
                cwd=self.fixture.repository, env=environment, stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                stdout, stderr = process.communicate(input=stdin, timeout=PROTOCOL_SECONDS)
            except subprocess.TimeoutExpired:
                timed_out = True
                process.kill()
                stdout, stderr = process.communicate(timeout=1)
        finally:
            config.write_bytes(self.original_config)
        for name, data in (("stdout.log",stdout),("stderr.log",stderr)):
            with (stage / name).open("xb") as stream:
                os.fchmod(stream.fileno(),0o600)
                stream.write(data)
        hooks = [json.loads(line) for line in record.read_text().splitlines()] if record.exists() else []
        receipt = {"generated_launcher_sha256":legacy.digest(self.fixture.root / "fake-path/python3"),
                   "original_driver_sha256":legacy.digest(self.fixture.root / "fixture-external-tools.py"),
                   "restored_configuration_sha256":hashlib.sha256(config.read_bytes()).hexdigest(),
                   "original_sources":self.fixture.original_sources,
                   "pid":process.pid,"returncode":process.returncode,"hooks":hooks,"timed_out":timed_out,
                   "CLI_started":False,"topology_or_NAT_accepted":False}
        with (stage / "receipt.json").open("x") as stream:
            os.fchmod(stream.fileno(),0o600)
            json.dump(receipt,stream,sort_keys=True)
            stream.write("\n")
        self.assertEqual(config.read_bytes(),self.original_config)
        self.assertFalse(timed_out,"inline fixture protocol timed out; not a product RED")
        return process,stdout,stderr,hooks

    def assert_original_inline(self, arguments, stdin=None):
        process,stdout,stderr,hooks = self.run_inline(arguments,stdin=stdin)
        self.assertEqual(process.returncode,17,stderr.decode(errors="replace"))
        value = json.loads(stdout)
        self.assertEqual(value["pid"],process.pid)
        self.assertEqual(value["no_site"],0)
        self.assertEqual(value["nonce"],"inline-transport-v1")
        self.assertEqual(value["cwd"],str(self.fixture.repository))
        self.assertEqual(value["argv"],[arguments[0],"transport-argument"])
        self.assertEqual(len(hooks),1,"only original inline startup may load the site hook")
        self.assertEqual(hooks[0]["pid"],process.pid)
        self.assertEqual(hooks[0]["no_site"],0)

    def test_inline_command_retains_fresh_site_argv_pid_env_and_status(self):
        code = ("import json,os,sys;print(json.dumps({'pid':os.getpid(),'no_site':sys.flags.no_site,"
                "'nonce':os.environ['B01_INLINE_NONCE'],'cwd':os.getcwd(),'argv':sys.argv}));sys.exit(17)")
        self.assert_original_inline(["-c",code,"transport-argument"])

    def test_inline_stdin_retains_fresh_site_argv_pid_env_and_status(self):
        code = ("import json,os,sys;print(json.dumps({'pid':os.getpid(),'no_site':sys.flags.no_site,"
                "'nonce':os.environ['B01_INLINE_NONCE'],'cwd':os.getcwd(),'argv':sys.argv}));sys.exit(17)\n")
        self.assert_original_inline(["-","transport-argument"],stdin=code.encode())

    def test_invalid_configuration_rejected_before_inline_or_site_hook(self):
        process,stdout,stderr,hooks = self.run_inline(["-c","raise SystemExit(17)"],reject_config=True)
        self.assertEqual(process.returncode,92)
        self.assertEqual(stdout,b"")
        self.assertIn(b"B01_FIXTURE_INFRA_FAILURE:",stderr)
        self.assertEqual(hooks,[],"fixture transport must reject configuration without site hooks")


if __name__ == "__main__":
    unittest.main()
