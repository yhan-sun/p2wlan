"""Verify private support logs and accounts across a real control restart."""
import datetime
import gzip
import json
import os
import re
import secrets
import selectors
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
COMPOSE = ["docker", "compose", "--env-file", "deploy/selfhost/config/compose.env", "-f", "deploy/selfhost/compose.yml"]
MAX_RESPONSE_BYTES = 16 * 1024
MAX_METADATA_BYTES = 4096


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def request(port, path, body=None, token=None, method="POST"):
    data = None if body is None else json.dumps(body).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
        if path == "support/logs":
            data = gzip.compress(data)
            headers["Content-Encoding"] = "gzip"
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/api/v1/{path}",
        data=data,
        headers=headers,
        method=method,
    )
    # Neither deployment proxies nor redirects may send this synthetic test
    # account or its token anywhere beyond the local Compose control endpoint.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        with opener.open(req, timeout=5) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
        if len(raw) > MAX_RESPONSE_BYTES:
            raise RuntimeError("Compose HTTP response exceeded its size limit")
        result = json.loads(raw)
        if not isinstance(result, dict):
            raise ValueError("expected a JSON object")
        return result
    except urllib.error.HTTPError as error:
        error.close()
        raise RuntimeError(f"Compose {path} request failed (HTTP {error.code})") from None
    except (OSError, urllib.error.URLError):
        raise RuntimeError(f"Compose {path} request failed or timed out") from None
    except (ValueError, UnicodeError):
        raise RuntimeError(f"Compose {path} response was not valid JSON") from None


def run_compose(args, timeout=15, capture=False):
    """Keep Docker error output private and metadata output strictly bounded."""
    process = subprocess.Popen(
        COMPOSE + args, cwd=ROOT, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    deadline = time.monotonic() + timeout
    output = bytearray()
    try:
        if capture:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0 or not selector.select(remaining):
                        raise subprocess.TimeoutExpired("Compose metadata", timeout)
                    chunk = os.read(process.stdout.fileno(), MAX_METADATA_BYTES + 1 - len(output))
                    if not chunk:
                        break
                    output.extend(chunk)
                    if len(output) > MAX_METADATA_BYTES:
                        raise RuntimeError("Compose metadata exceeded its size limit")
        if process.wait(timeout=max(0.001, deadline - time.monotonic())) != 0:
            raise RuntimeError("Compose persistence command failed")
        return output.decode("ascii")
    except subprocess.TimeoutExpired:
        raise RuntimeError("Compose persistence command timed out") from None
    except UnicodeError:
        raise RuntimeError("Compose metadata was not valid ASCII") from None
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        if process.stdout is not None:
            process.stdout.close()


def control_uid():
    metadata = run_compose([
        "exec", "-T", "control", "sh", "-c",
        'id -u; awk \'$1 == "Uid:" {print $2, $3, $4, $5; exit}\' /proc/1/status',
    ], capture=True).splitlines()
    if len(metadata) != 2 or not all(re.fullmatch(r"[0-9 ]+", line) for line in metadata):
        raise RuntimeError("could not verify the control process identity")
    uid = int(metadata[0])
    process_uids = metadata[1].split()
    if uid == 0 or len(process_uids) != 4 or any(int(value) != uid for value in process_uids):
        raise RuntimeError("Compose persistence requires an actual non-root control process")
    return uid


def assert_private_upload(path, uid):
    metadata = run_compose([
        "exec", "-T", "control", "sh", "-c",
        'test -d /data/log-uploads && test ! -L /data/log-uploads && '
        'test -f "$1" && test ! -L "$1" && '
        'stat -c "%u %a" /data/log-uploads "$1"',
        "check-private-upload", path,
    ], capture=True).splitlines()
    if metadata != [f"{uid} 700", f"{uid} 600"]:
        raise RuntimeError("uploaded support log or directory is not privately owned by control")


def upload_support_log(port, token):
    uploaded = request(port, "support/logs", {
        "schema_version": 2,
        "uploaded_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "device_name": "compose-persistence-check",
        "platform": "linux",
        "manifest": {"total_instances": 1, "has_room_logs": False},
        "files": [{"name": "p2wlan-daemon.log", "content": "synthetic Compose persistence check\n"}],
    }, token=token)
    upload_id = uploaded.get("upload_id")
    received_at = uploaded.get("received_at")
    if (uploaded.get("success") is not True or uploaded.get("instances") != 1
            or not isinstance(upload_id, str) or not re.fullmatch(r"[a-f0-9]{24}", upload_id)
            or not isinstance(received_at, str)):
        raise RuntimeError("support upload did not return a valid success receipt")
    timestamp = re.fullmatch(
        r"([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})"
        r"(?:\.([0-9]{1,9}))?Z",
        received_at,
    )
    if timestamp is None:
        raise RuntimeError("support upload receipt has an invalid UTC timestamp")
    # Go emits RFC3339Nano, but Python 3.10 only accepts 3 or 6 fractional
    # digits. Validate the complete wire value before reducing its precision.
    micros = (timestamp.group(2) or "")[:6].ljust(6, "0")
    try:
        datetime.datetime.fromisoformat(f"{timestamp.group(1)}.{micros}+00:00")
    except ValueError:
        raise RuntimeError("support upload receipt has an invalid timestamp") from None
    return f"/data/log-uploads/{timestamp.group(1)[:10]}-{upload_id}.json.gz"


def main():
    values = dict(
        line.split("=", 1)
        for line in (ROOT / "deploy/selfhost/config/compose.env").read_text(encoding="utf-8").splitlines()
        if line and not line.startswith("#")
    )
    port = int(values["CONTROL_PORT"])
    uid = control_uid()
    account = {"email": f"persistence-{secrets.token_hex(8)}@example.test", "password": secrets.token_hex(24)}
    created = request(port, "register", account)
    token = created.get("token")
    if not isinstance(token, str) or not token:
        raise RuntimeError("account creation did not return authentication proof")
    upload_path = upload_support_log(port, token)
    assert_private_upload(upload_path, uid)
    run_compose(["restart", "control"], timeout=30)
    run_compose(["up", "-d", "--no-deps", "--no-recreate", "--wait", "--wait-timeout", "60", "control"], timeout=75)
    if control_uid() != uid:
        raise RuntimeError("control process identity changed after restart")
    assert_private_upload(upload_path, uid)
    # Reusing the original token is the login-preservation contract. A new
    # password login alone would not detect an accidentally rotated JWT key.
    profile = request(port, "profile", token=token, method="GET")
    if profile.get("user", {}).get("email") != account["email"]:
        raise RuntimeError("existing login did not survive container restart")
    logged_in = request(port, "login", account)
    if not isinstance(logged_in.get("token"), str) or not logged_in["token"]:
        raise RuntimeError("persisted account was not usable after container restart")
    print("PASS: non-root control retained private support logs, accounts and the existing login after restart")


if __name__ == "__main__":
    main()
