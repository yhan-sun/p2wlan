"""Verify retained account data across an actual control container restart."""
import json
import secrets
import subprocess
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
COMPOSE = ["docker", "compose", "--env-file", "deploy/selfhost/config/compose.env", "-f", "deploy/selfhost/compose.yml"]


def request(port, path, body):
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/api/v1/{path}",
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=5) as response:
        return json.load(response)


def main():
    values = dict(
        line.split("=", 1)
        for line in (ROOT / "deploy/selfhost/config/compose.env").read_text(encoding="utf-8").splitlines()
        if line and not line.startswith("#")
    )
    port = int(values["CONTROL_PORT"])
    account = {"email": f"persistence-{secrets.token_hex(8)}@example.test", "password": secrets.token_hex(24)}
    created = request(port, "register", account)
    if not created.get("token"):
        raise RuntimeError("account creation did not return authentication proof")
    subprocess.run(COMPOSE + ["restart", "control"], cwd=ROOT, check=True)
    subprocess.run(COMPOSE + ["up", "-d", "--wait", "--wait-timeout", "60"], cwd=ROOT, check=True)
    logged_in = request(port, "login", account)
    if not logged_in.get("token"):
        raise RuntimeError("persisted account was not usable after container restart")
    print("PASS: real registered account retained and authenticated after control container restart")


if __name__ == "__main__":
    main()
