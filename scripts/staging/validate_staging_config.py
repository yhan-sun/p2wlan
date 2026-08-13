#!/usr/bin/env python3
"""Read-only staging control/relay preflight validator.

The default mode performs only local parsing. Network checks require the
explicit ALLOW_STAGING_TEST=1 opt-in and never restart or mutate a service.
Secrets and ticket contents are intentionally never printed.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import shlex
import socket
import ssl
import sys
import time
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, build_opener, ProxyHandler, urlopen


class ValidationError(Exception):
    pass


def env_file(path: str | None) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path:
        return values
    for number, raw in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ValidationError(f"{path}:{number}: expected KEY=value")
        key, value = line.split("=", 1)
        key = key.strip()
        if not key:
            raise ValidationError(f"{path}:{number}: empty key")
        try:
            parsed = shlex.split(value, comments=False, posix=True)
        except ValueError as exc:
            raise ValidationError(f"{path}:{number}: invalid shell quoting: {exc}") from exc
        values[key] = parsed[0] if parsed else ""
    return values


def value(values: dict[str, str], key: str) -> str:
    return values.get(key, os.environ.get(key, "")).strip()


def require(values: dict[str, str], key: str) -> str:
    result = value(values, key)
    if not result:
        raise ValidationError(f"missing {key}")
    return result


def reject_placeholder(text: str, key: str, strict: bool) -> None:
    if strict and ("<" in text or ">" in text):
        raise ValidationError(f"{key} still contains a placeholder")


def parse_catalog(raw: str, strict: bool) -> list[dict[str, str]]:
    try:
        catalog = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValidationError(f"RELAY_CATALOG_JSON is invalid JSON: {exc}") from exc
    if not isinstance(catalog, list) or not catalog:
        raise ValidationError("RELAY_CATALOG_JSON must be a non-empty array")
    result = []
    audiences: set[str] = set()
    regions: set[str] = set()
    for index, item in enumerate(catalog):
        if not isinstance(item, dict):
            raise ValidationError(f"catalog entry {index} is not an object")
        for key in ("region", "audience", "endpoint"):
            if not isinstance(item.get(key), str) or not item[key].strip():
                raise ValidationError(f"catalog entry {index} missing {key}")
            reject_placeholder(item[key], f"catalog[{index}].{key}", strict)
        region = item["region"].strip()
        audience = item["audience"].strip()
        endpoint = item["endpoint"].strip()
        parsed = urlparse(endpoint)
        if parsed.scheme != "tls":
            raise ValidationError(
                f"catalog entry {index} endpoint must use tls:// (got {endpoint!r})"
            )
        if not parsed.hostname or parsed.port is None:
            raise ValidationError(f"catalog entry {index} endpoint must be tls://host:port")
        if audience in audiences:
            raise ValidationError(f"duplicate relay audience {audience!r}")
        if region in regions:
            raise ValidationError(f"duplicate relay region {region!r}")
        observer = item.get("udp_observer_endpoint", "")
        if observer:
            observer_text = str(observer)
            observer_host, separator, observer_port = observer_text.rpartition(":")
            if not separator or not observer_host or not observer_port.isdigit():
                raise ValidationError(f"catalog entry {index} has invalid UDP observer endpoint")
        audiences.add(audience)
        regions.add(region)
        result.append({"region": region, "audience": audience, "endpoint": endpoint})
    return result


def parse_keyring(raw: str, expected_kid: str, strict: bool) -> dict[str, str]:
    try:
        keyring = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValidationError(f"RELAY_TICKET_KEYRING_JSON is invalid JSON: {exc}") from exc
    if not isinstance(keyring, dict) or not keyring:
        raise ValidationError("RELAY_TICKET_KEYRING_JSON must be a non-empty object")
    if expected_kid not in keyring:
        raise ValidationError("relay keyring does not contain RELAY_TICKET_SIGNER_KID")
    for kid, public_key in keyring.items():
        if not isinstance(kid, str) or not isinstance(public_key, str):
            raise ValidationError("relay keyring must map key IDs to hex public keys")
        reject_placeholder(kid, "relay keyring kid", strict)
        reject_placeholder(public_key, f"relay keyring public key {kid}", strict)
        if strict:
            try:
                decoded = bytes.fromhex(public_key)
            except ValueError as exc:
                raise ValidationError(f"relay keyring public key {kid} is not hex") from exc
            if len(decoded) != 32:
                raise ValidationError(f"relay keyring public key {kid} must be 32 bytes")
    return keyring


def check_static(control: dict[str, str], relay: dict[str, str], catalog: list[dict[str, str]], strict: bool) -> None:
    control_url = require(control, "CONTROL_PUBLIC_URL")
    if not control_url.startswith("https://"):
        raise ValidationError("CONTROL_PUBLIC_URL must use https://")
    signer_kid = require(control, "RELAY_TICKET_SIGNER_KID")
    require(control, "RELAY_TICKET_SIGNER_KEY_FILE")
    require(control, "RELAY_REVOCATION_FEED_TOKEN")
    reject_placeholder(signer_kid, "RELAY_TICKET_SIGNER_KID", strict)

    audience = require(relay, "RELAY_AUDIENCE")
    region = require(relay, "RELAY_REGION")
    require(relay, "RELAY_TLS_CERT")
    require(relay, "RELAY_TLS_KEY")
    if value(relay, "RELAY_REQUIRE_AUTH").lower() != "true":
        raise ValidationError("RELAY_REQUIRE_AUTH must be true")
    if value(relay, "RELAY_ALLOW_LEGACY_UNAUTH").lower() == "true":
        raise ValidationError("RELAY_ALLOW_LEGACY_UNAUTH must be false")
    if value(relay, "RELAY_ALLOW_INSECURE_PLAINTEXT").lower() == "true":
        raise ValidationError("RELAY_ALLOW_INSECURE_PLAINTEXT is forbidden")
    feed_url = require(relay, "RELAY_REVOCATION_FEED_URL")
    if not feed_url.startswith("https://"):
        raise ValidationError("RELAY_REVOCATION_FEED_URL must use https://")
    require(relay, "RELAY_REVOCATION_FEED_TOKEN")
    metrics_bind = require(relay, "RELAY_METRICS_BIND")
    metrics_host, separator, _ = metrics_bind.rpartition(":")
    if not separator or metrics_host not in ("127.0.0.1", "::1", "[::1]"):
        raise ValidationError("RELAY_METRICS_BIND must bind loopback")
    if value(relay, "RELAY_METRICS_ALLOW_PUBLIC").lower() == "true":
        raise ValidationError("RELAY_METRICS_ALLOW_PUBLIC must be false")
    keyring = parse_keyring(require(relay, "RELAY_TICKET_KEYRING_JSON"), signer_kid, strict)

    matches = [entry for entry in catalog if entry["audience"] == audience and entry["region"] == region]
    if len(matches) != 1:
        raise ValidationError("RELAY_AUDIENCE/RELAY_REGION do not match exactly one catalog entry")
    print(f"catalog: {len(catalog)} relay(s), selected audience={audience} region={region}")
    print(f"ticket keyring: {len(keyring)} key(s), active kid verified by ID")
    print("metrics bind: loopback-only")


def b64_json(part: str) -> dict:
    padding = "=" * (-len(part) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode((part + padding).encode("ascii")))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValidationError(f"ticket contains invalid JWT JSON: {exc}") from exc


def verify_ticket(path: str, keyring: dict[str, str], audience: str, region: str) -> None:
    token = Path(path).read_text(encoding="utf-8").strip()
    parts = token.split(".")
    if len(parts) != 3:
        raise ValidationError("ticket file is not a compact JWT")
    header = b64_json(parts[0])
    claims = b64_json(parts[1])
    if header.get("alg") != "EdDSA" or header.get("typ") != "p2wlan-relay+jwt":
        raise ValidationError("ticket algorithm/type is not the relay contract")
    kid = header.get("kid")
    if kid not in keyring:
        raise ValidationError("ticket kid is not in the relay keyring")
    try:
        signature = base64.urlsafe_b64decode((parts[2] + "=" * (-len(parts[2]) % 4)).encode("ascii"))
        public_key = bytes.fromhex(keyring[kid])
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        Ed25519PublicKey.from_public_bytes(public_key).verify(
            signature, f"{parts[0]}.{parts[1]}".encode("ascii")
        )
    except ImportError as exc:
        raise ValidationError("cryptography is required for --ticket-file signature verification") from exc
    except Exception as exc:  # cryptography raises InvalidSignature without a stable stdlib type
        raise ValidationError(f"ticket signature verification failed: {type(exc).__name__}") from exc
    now = int(time.time())
    if claims.get("iss") != "p2wlan-control" or claims.get("aud") != audience:
        raise ValidationError("ticket issuer or audience mismatch")
    if claims.get("relay_region") != region or claims.get("relay_protocol") != 1:
        raise ValidationError("ticket relay region/protocol mismatch")
    if not claims.get("device_id") or not claims.get("network_id") or not claims.get("node_id"):
        raise ValidationError("ticket is missing a required identity claim")
    if not isinstance(claims.get("exp"), int) or claims["exp"] <= now:
        raise ValidationError("ticket is expired or has no integer exp")
    print("ticket: signature and required audience/region/identity/expiry claims verified")


def network_get(url: str, timeout: float) -> tuple[int, bytes]:
    request = Request(url, headers={"Accept": "application/json"}, method="GET")
    # Preflight must not silently inherit Clash/http_proxy and report a proxy
    # endpoint as the UDP/control origin.
    opener = build_opener(ProxyHandler({}))
    with opener.open(request, timeout=timeout) as response:
        return response.status, response.read(64 * 1024)


def check_network(control: dict[str, str], catalog: list[dict[str, str]], metrics_url: str | None) -> None:
    if os.environ.get("ALLOW_STAGING_TEST") != "1":
        raise ValidationError("network checks require ALLOW_STAGING_TEST=1")
    control_url = require(control, "CONTROL_PUBLIC_URL").rstrip("/")
    parsed_control = urlparse(control_url)
    socket.getaddrinfo(parsed_control.hostname, parsed_control.port or 443, type=socket.SOCK_STREAM)
    status, body = network_get(control_url + "/health", 5.0)
    if status != 200 or body.strip() != b"ok":
        raise ValidationError(f"control /health failed with HTTP {status}")
    print("control: DNS and /health passed (direct, proxy bypassed)")

    for entry in catalog:
        parsed = urlparse(entry["endpoint"])
        socket.getaddrinfo(parsed.hostname, parsed.port, type=socket.SOCK_STREAM)
        context = ssl.create_default_context()
        with socket.create_connection((parsed.hostname, parsed.port), timeout=5.0) as raw:
            with context.wrap_socket(raw, server_hostname=parsed.hostname):
                pass
        print(f"relay TLS: hostname and certificate passed for audience={entry['audience']}")
    if not metrics_url:
        print("relay metrics: NOT CHECKED (provide --metrics-url for the SSH-tunnel URL)")
        return
    for suffix in ("/healthz", "/metrics"):
        status, _ = network_get(metrics_url.rstrip("/") + suffix, 5.0)
        if status != 200:
            raise ValidationError(f"relay metrics {suffix} failed with HTTP {status}")
    print("relay metrics: healthz and metrics passed through the supplied loopback tunnel")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--control-env")
    parser.add_argument("--relay-env")
    parser.add_argument("--catalog-file")
    parser.add_argument("--ticket-file", help="optional short-lived ticket; never printed")
    parser.add_argument("--metrics-url", help="optional local URL reached through an SSH tunnel")
    parser.add_argument("--check-network", action="store_true")
    parser.add_argument("--strict-values", action="store_true", help="reject template placeholders")
    args = parser.parse_args()
    try:
        control = env_file(args.control_env)
        relay = env_file(args.relay_env)
        catalog_raw = value(control, "RELAY_CATALOG_JSON")
        if args.catalog_file:
            catalog_raw = Path(args.catalog_file).read_text(encoding="utf-8")
        catalog = parse_catalog(require({"RELAY_CATALOG_JSON": catalog_raw}, "RELAY_CATALOG_JSON"), args.strict_values)
        check_static(control, relay, catalog, args.strict_values)
        keyring = parse_keyring(require(relay, "RELAY_TICKET_KEYRING_JSON"), require(control, "RELAY_TICKET_SIGNER_KID"), args.strict_values)
        if args.ticket_file:
            verify_ticket(args.ticket_file, keyring, require(relay, "RELAY_AUDIENCE"), require(relay, "RELAY_REGION"))
        if args.check_network:
            check_network(control, catalog, args.metrics_url)
        else:
            print("network: NOT CHECKED (local read-only validation only)")
    except (OSError, ValidationError, ValueError) as exc:
        print(f"FAIL reason_code=staging_preflight_failed detail={exc}", file=sys.stderr)
        return 1
    print("PASS staging configuration preflight")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
