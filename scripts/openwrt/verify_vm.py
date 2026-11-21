#!/usr/bin/env python3
"""Install and exercise a native package on the matching OpenWrt kernel in QEMU."""

from __future__ import annotations

import argparse
from functools import partial
import gzip
from http.server import HTTPServer, SimpleHTTPRequestHandler
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import threading
import time

from build import download, sha256, target_config


class QuietHandler(SimpleHTTPRequestHandler):
    timeout = 15
    def log_message(self, *_args) -> None:
        pass


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def verify(args: argparse.Namespace) -> None:
    release, target, stem, base = target_config(args.series, args.arch)
    work = args.work_dir.resolve() / "vm"
    work.mkdir(parents=True, exist_ok=True)
    kernel = work / f"{stem}-generic-kernel.bin"
    rootfs = work / f"{stem}-generic-ext4-rootfs.img.gz"
    download(base + kernel.name, kernel, target["kernel_sha256"])
    download(base + rootfs.name, rootfs, target["rootfs_sha256"])
    image = work / "rootfs.img"
    with gzip.open(rootfs, "rb") as src, image.open("wb") as dst:
        shutil.copyfileobj(src, dst)
    subprocess.run(["truncate", "-s", "512M", str(image)], check=True)
    checked = subprocess.run(["e2fsck", "-pf", str(image)], check=False)
    # e2fsck's status 1 means errors were corrected, not a failed filesystem.
    if checked.returncode not in (0, 1):
        raise RuntimeError(f"OpenWrt rootfs check failed: {checked.returncode}")
    subprocess.run(["resize2fs", str(image)], check=True)
    package_arch = "aarch64_generic" if args.arch == "arm64" else "x86_64"
    package = args.directory.resolve() / f"p2wlan-openwrt-{args.series}-{package_arch}.{release['extension']}"
    if not package.is_file():
        raise ValueError(f"native package missing: {package}")
    metadata = json.loads(package.with_name(package.name + ".metadata.json").read_text())
    with tempfile.TemporaryDirectory(prefix="p2wlan-openwrt-") as tmp:
        shared = Path(tmp)
        key = shared / "id_ed25519"
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True)
        # Only the public key and package are served to the disposable VM.
        public = shared / "public"
        public.mkdir()
        shutil.copyfile(key.with_suffix(".pub"), public / "key.pub")
        shutil.copyfile(package, public / package.name)
        (public / "RELEASE-MANIFEST.json").write_text(json.dumps({
            "schema_version": 3, "tag": metadata["tag"], "source_sha": args.source_sha,
            "files": {package.name: {"sha256": sha256(package)}},
        }))
        shutil.copyfile(Path(__file__).resolve().parents[1] / "install-linux-cli.sh", public / "install-linux-cli.sh")
        shutil.copyfile(Path(__file__).resolve().parents[1] / "install-openwrt.sh", public / "install-openwrt.sh")
        server = HTTPServer(("0.0.0.0", 0), partial(QuietHandler, directory=str(public)))
        threading.Thread(target=server.serve_forever, daemon=True).start()
        ssh_port = free_port()
        if args.arch == "arm64":
            qemu = ["qemu-system-aarch64", "-machine", "virt", "-cpu", "cortex-a53"]
            console = "ttyAMA0"
        else:
            qemu = ["qemu-system-x86_64", "-machine", "q35", "-cpu", "max"]
            console = "ttyS0"
        qemu += ["-m", "1024", "-smp", "2", "-nographic", "-monitor", "none", "-no-reboot",
                 "-kernel", str(kernel), "-append", f"root=/dev/vda rootwait rw console={console}",
                 "-drive", f"file={image},format=raw,if=none,id=root", "-device", "virtio-blk-pci,drive=root",
                 "-netdev", f"user,id=net0,net=192.168.1.0/24,host=192.168.1.2,hostfwd=tcp:127.0.0.1:{ssh_port}-192.168.1.1:22",
                 "-device", "virtio-net-pci,netdev=net0"]
        tail = bytearray()
        lock = threading.Lock()
        process = subprocess.Popen(qemu, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

        def collect() -> None:
            with (work / "console.log").open("wb") as log:
                while chunk := os.read(process.stdout.fileno(), 4096):
                    log.write(chunk)
                    with lock:
                        tail.extend(chunk)
                        del tail[:-65536]

        reader = threading.Thread(target=collect, daemon=True)
        reader.start()
        ssh = ["ssh", "-i", str(key), "-p", str(ssh_port), "-o", "StrictHostKeyChecking=no",
               "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=5", "-o", "LogLevel=ERROR", "root@127.0.0.1"]

        def remote(command: str, timeout: int = 60, success: bool = True) -> str:
            result = subprocess.run([*ssh, command], text=True, capture_output=True, timeout=timeout)
            if success and result.returncode != 0:
                raise RuntimeError(f"OpenWrt command failed: {command}\n{result.stdout[-3000:]}\n{result.stderr[-3000:]}")
            if not success and result.returncode == 0:
                raise RuntimeError(f"OpenWrt command unexpectedly succeeded: {command}")
            return result.stdout

        try:
            deadline = time.monotonic() + 180
            while time.monotonic() < deadline:
                with lock:
                    ready = b"Please press Enter to activate this console" in tail
                if ready:
                    break
                if process.poll() is not None:
                    raise RuntimeError("QEMU exited before OpenWrt booted")
                time.sleep(1)
            else:
                raise RuntimeError("OpenWrt boot timed out")
            # askfirst consumes the activation line before it starts ash;
            # sending setup in the same write loses it during login startup.
            process.stdin.write(b"\n")
            process.stdin.flush()
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                with lock:
                    ready = b":~# " in tail
                if ready:
                    break
                if process.poll() is not None:
                    raise RuntimeError("QEMU exited before the console shell started")
                time.sleep(0.5)
            else:
                raise RuntimeError("OpenWrt console shell did not become ready")
            address = f"http://192.168.1.2:{server.server_port}"
            # This is a disposable VM network, independent of the package.
            # Persist it before restarting netifd so first-boot rcS cannot
            # overwrite a temporary route/address while the harness connects.
            setup = ("\n".join([
                "cat > /etc/config/network <<'P2WLAN_NETWORK'",
                "config interface 'loopback'",
                " option device 'lo'",
                " option proto 'static'",
                " option ipaddr '127.0.0.1'",
                " option netmask '255.0.0.0'",
                "config interface 'lan'",
                " option device 'eth0'",
                " option proto 'static'",
                " option ipaddr '192.168.1.1'",
                " option netmask '255.255.255.0'",
                " option gateway '192.168.1.2'",
                " list dns '192.168.1.3'",
                "P2WLAN_NETWORK",
                "/etc/init.d/network restart",
                "echo nameserver 192.168.1.3 > /etc/resolv.conf",
                f"date -s @{int(time.time())}",
                # These fixed service ports are inside the guest's ephemeral
                # range. Reserve them before downloads/CLI HTTP connections;
                # explicit binds and the service readiness checks stay intact.
                "vm_reserved_ports=$(cat /proc/sys/net/ipv4/ip_local_reserved_ports); "
                "printf '%s\\n' \"${vm_reserved_ports:+$vm_reserved_ports,}39277,39278\" "
                "> /proc/sys/net/ipv4/ip_local_reserved_ports",
                "mkdir -p /etc/dropbear",
                "for attempt in 1 2 3 4 5 6 7 8 9 10; do "
                f"wget -q -T 5 -O /etc/dropbear/authorized_keys {address}/key.pub && break; sleep 1; done",
                "chmod 600 /etc/dropbear/authorized_keys",
                "/etc/init.d/dropbear restart",
            ]) + "\n")
            process.stdin.write(setup.encode())
            process.stdin.flush()
            deadline = time.monotonic() + 90
            while time.monotonic() < deadline:
                try:
                    connected = subprocess.run([*ssh, "true"], capture_output=True, timeout=8).returncode == 0
                except subprocess.TimeoutExpired:
                    connected = False
                if connected:
                    break
                time.sleep(2)
            else:
                raise RuntimeError("OpenWrt SSH did not become ready")
            reserved_ports = remote("cat /proc/sys/net/ipv4/ip_local_reserved_ports").strip()
            reserved_ranges = [part.partition("-") for part in reserved_ports.split(",")]
            if not all(any(int(start) <= port <= int(end or start)
                           for start, _, end in reserved_ranges) for port in (39277, 39278)):
                raise ValueError("VM diagnostics ports are not reserved from automatic allocation")
            guest_package = "/tmp/" + package.name
            remote(f"wget -q -O {guest_package} {address}/{package.name}")
            downloaded = remote(f"sha256sum {guest_package}").split()[0]
            if downloaded != sha256(package):
                raise ValueError("package bytes changed before OpenWrt installation")
            manager = "apk" if args.series == "25.12" else "opkg"
            remote(f"for attempt in 1 2 3; do {manager} update && exit 0; "
                   '[ "$attempt" -lt 3 ] || exit 1; sleep 3; done', timeout=480)
            install = (f"apk add --allow-untrusted {guest_package}" if args.series == "25.12"
                       else f"opkg install {guest_package}")
            remote(install, timeout=240)
            remote("! pidof p2wlan-daemon")  # unconfigured install must stay idle
            remote("/etc/init.d/p2wlan enable && /etc/init.d/p2wlan enabled")
            info = json.loads(remote("p2wlan-daemon --build-info"))
            if info["git_commit"] != args.source_sha or info["dirty"]:
                raise ValueError("installed daemon source identity differs from checkout")
            version = metadata["tag"].removeprefix("v")
            if info["app_version"] != version or info["daemon_version"] != version:
                raise ValueError("installed binary version differs from package tag")
            if info["binary_sha256"] != remote("sha256sum /usr/bin/p2wlan-daemon").split()[0]:
                raise ValueError("installed daemon self-reported digest differs from package bytes")
            remote("p2wlan config set control https://control.example.com")
            remote("sed -i -e 's/\"manual\": false/\"manual\": true/' "
                   "-e 's/\"stun_servers\": \[\]/\"stun_servers\": [\"off\"]/' "
                   "-e 's/\"upnp_enabled\": true/\"upnp_enabled\": false/' "
                   "-e 's/\"udp_liveness_enabled\": true/\"udp_liveness_enabled\": false/' "
                   "/etc/p2wlan/p2wlan-config.json")
            remote("p2wlan up", timeout=90)
            remote("test \"$(ls -ld /etc/p2wlan/p2wlan-config.json | cut -c 1-10)\" = '-rw-------' && "
                   "test \"$(ls -ld /var/run/p2wlan | cut -c 1-10)\" = 'drwx------'")
            remote("sysupgrade -l | grep -Fxq '/etc/p2wlan/p2wlan-config.json'")
            snapshot = json.loads(remote("p2wlan status --json"))
            if snapshot.get("virtual_ip") != "10.20.0.1":
                raise ValueError(f"real TUN did not receive the configured address: {snapshot.get('virtual_ip')}")
            remote("ip -4 addr show | grep -q 10.20.0.1")
            # Exercise the optional firewall example on stock firewall4;
            # package installation itself must not alter firewall policy.
            remote("uci set firewall.p2wlan=zone; uci set firewall.p2wlan.name=p2wlan; "
                   "uci add_list firewall.p2wlan.device=p2wlan0; uci add_list firewall.p2wlan.device='p2r+'; "
                   "uci set firewall.p2wlan.input=REJECT; uci set firewall.p2wlan.output=ACCEPT; "
                   "uci set firewall.p2wlan.forward=REJECT; uci set firewall.p2wlan_ping=rule; "
                   "uci set firewall.p2wlan_ping.name=Allow-P2WLAN-Ping; uci set firewall.p2wlan_ping.src=p2wlan; "
                   "uci set firewall.p2wlan_ping.family=ipv4; uci set firewall.p2wlan_ping.proto=icmp; "
                   "uci add_list firewall.p2wlan_ping.icmp_type=echo-request; "
                   "uci set firewall.p2wlan_ping.target=ACCEPT; uci commit firewall; "
                   "fw4 check && /etc/init.d/firewall reload && fw4 zone p2wlan p2wlan0")
            pid = remote("pidof p2wlan-daemon").strip()
            remote("p2wlan up")
            if remote("pidof p2wlan-daemon").strip() != pid or len(pid.split()) != 1:
                raise ValueError("repeated up created/replaced the procd-owned daemon")
            remote("p2wlan down", timeout=60)
            time.sleep(7)  # exceed procd's 5-second respawn interval
            remote("! pidof p2wlan-daemon && ! ip -4 addr show | grep -q 10.20.0.1")
            remote("p2wlan update --dry-run", success=False)
            remote(f"wget -q -O /tmp/install-linux-cli.sh {address}/install-linux-cli.sh")
            remote("sh /tmp/install-linux-cli.sh --version v1.2.3 --dry-run", success=False)
            remote(f"wget -q -O /tmp/install-openwrt.sh {address}/install-openwrt.sh")
            selection = remote(f"sh /tmp/install-openwrt.sh --version v{version} --dry-run")
            if package.name not in selection:
                raise ValueError(f"installer selected the wrong native package: {selection}")
            remote(f"wget -q -O /tmp/release-manifest.json {address}/RELEASE-MANIFEST.json")
            parsed_checksum = remote("jsonfilter -i /tmp/release-manifest.json "
                                     f"-e '@.files[\"{package.name}\"].sha256'").strip()
            if parsed_checksum != sha256(package):
                raise ValueError("native installer manifest checksum expression failed")
            remote("sh /tmp/install-openwrt.sh --version v1.2.3/escape --dry-run", success=False)
            # Stop must still work when the JSON has become unreadable; a bad
            # config must never cause a new unmanaged process to be spawned.
            remote("p2wlan config set diagnostics 127.0.0.1:39278")
            remote("p2wlan up", timeout=90)
            json.loads(remote("p2wlan status --json"))
            remote("cp /etc/p2wlan/p2wlan-config.json /tmp/config.saved; echo broken > /etc/p2wlan/p2wlan-config.json")
            remote("p2wlan down", timeout=60)
            remote("/etc/init.d/p2wlan start", success=False)
            remote("! pidof p2wlan-daemon")
            remote("mv /tmp/config.saved /etc/p2wlan/p2wlan-config.json; chmod 600 /etc/p2wlan/p2wlan-config.json")
            remote("uci set p2wlan.main.enabled=0; uci commit p2wlan")
            remote("p2wlan up", success=False)
            remote("! pidof p2wlan-daemon")
            remote("uci set p2wlan.main.enabled=1; uci commit p2wlan")
            remote("sed -i 's/127.0.0.1:39278/0.0.0.0:39278/' /etc/p2wlan/p2wlan-config.json")
            remote("/etc/init.d/p2wlan start", success=False)
            remote("! pidof p2wlan-daemon")
            report = {"series": args.series, "arch": args.arch, "firmware": release["version"],
                      "source_sha": args.source_sha, "package": package.name, "sha256": sha256(package),
                      "vm_ip_local_reserved_ports": reserved_ports,
                      "checks": ["native-dependencies", "build-identity", "real-tun", "single-owner-up",
                                 "procd-down-no-respawn", "invalid-config-stop", "glibc-update-refused",
                                 "native-installer-selection", "private-runtime-permissions",
                                 "sysupgrade-config-backup", "disabled-service-refused", "firewall-example",
                                 "loopback-diagnostics", "native-installer-manifest",
                                 "diagnostics-port-reservation"]}
            (work / "verification.json").write_text(json.dumps(report, indent=2) + "\n")
            print("PASS OpenWrt VM", json.dumps(report), flush=True)
        except Exception as error:
            # Only synthetic VM state is collected; never copy config keys or
            # the diagnostics token into public build evidence.
            try:
                diagnostics = subprocess.run([*ssh,
                    "tail -c 12000 /var/run/p2wlan/p2wlan-daemon.log 2>/dev/null; "
                    "logread -e p2wlan | tail -c 12000; "
                    "ubus call service list '{\"name\":\"p2wlan\"}'; "
                    "cat /proc/sys/net/ipv4/ip_local_port_range /proc/sys/net/ipv4/ip_local_reserved_ports; "
                    "netstat -lntp 2>/dev/null; cat /proc/net/tcp /proc/net/tcp6; "
                    "ls -ld /etc/p2wlan /var/run/p2wlan"],
                    capture_output=True, text=True, timeout=10)
                (work / "service-diagnostics.log").write_text((diagnostics.stdout + diagnostics.stderr)[-26000:])
            except (subprocess.TimeoutExpired, OSError):
                pass
            (work / "failure.json").write_text(json.dumps({
                "series": args.series, "arch": args.arch, "source_sha": args.source_sha,
                "error": f"{type(error).__name__}: {error}"[-6000:],
            }, indent=2) + "\n")
            with lock:
                print(bytes(tail[-4000:]).decode(errors="replace"), flush=True)
            raise
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            reader.join(timeout=2)
            server.shutdown()
            server.server_close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--series", choices=("24.10", "25.12"), required=True)
    parser.add_argument("--arch", choices=("arm64", "x64"), required=True)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    verify(parser.parse_args())


if __name__ == "__main__":
    main()
