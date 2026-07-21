# p2wlan Release Packaging

## macOS

Use the packaging script instead of running `pnpm tauri build` directly:

```bash
pnpm run icons
pnpm run package:macos
```

The script builds `p2pnet-daemon` in release mode, copies it into the Tauri
resource directory, builds `p2wlan.app`, applies an ad-hoc deep code signature,
and creates a DMG containing:

- `p2wlan.app`
- an `Applications` shortcut
- `p2wlan.app/Contents/Resources/p2pnet-daemon`

Local Apple Silicon output:

```text
target/aarch64-apple-darwin/release/bundle/macos/p2wlan.app
target/aarch64-apple-darwin/release/bundle/dmg/p2wlan_<version>_aarch64.dmg
```

Universal release output is produced by GitHub Actions with:

```bash
scripts/package-macos.sh --target universal-apple-darwin
```

The release workflow uploads:

- `p2wlan-macos-universal.dmg`
- `p2wlan-macos-universal.app.zip`
- `p2wlan-windows-x64.zip`
- `p2wlan-linux-x64-cli.tar.gz`
- `p2wlan-linux-arm64-cli.tar.gz`

The app is ad-hoc signed but not notarized yet. If macOS Gatekeeper blocks a
downloaded build, use right-click > Open for internal testing. Public notarized
distribution will need a Developer ID certificate and Apple notarization secrets.

## Windows

The release workflow builds a portable zip containing:

- `p2wlan-desktop.exe`
- `p2pnet-daemon.exe`
- `wintun.dll`
- `README-WINDOWS.txt`

Keep these files in the same folder. The desktop app uses Windows UAC to launch
the daemon with administrator privileges when TUN mode starts.

## Linux CLI

The release workflow builds headless Linux x64 and arm64 CLI tarballs containing:

- `p2wlan`
- `p2pnet-daemon`
- `install.sh`
- `LICENSE`
- `README-LINUX-CLI.txt`

The CLI package is intended for servers, headless Linux hosts, and real TUN
smoke testing. Running real TUN mode requires root privileges or equivalent
`CAP_NET_ADMIN` capability:

Install the latest published Linux CLI directly from GitHub:

```bash
curl -fsSL https://raw.githubusercontent.com/yhan-sun/p2wlan/main/scripts/install-linux-cli.sh -o /tmp/p2wlan-install.sh
sudo sh /tmp/p2wlan-install.sh
p2wlan --version
p2wlan help
```

Install a specific release tag:

```bash
sudo sh /tmp/p2wlan-install.sh --version v0.1.28
```

Preview or install to a user-writable directory:

```bash
sh /tmp/p2wlan-install.sh --version v0.1.28 --dry-run
sh /tmp/p2wlan-install.sh --install-dir "$HOME/.local/bin"
```

Or install from an already downloaded release tarball:

```bash
tar -xzf p2wlan-linux-x64-cli.tar.gz
cd p2wlan-linux-x64-cli
sudo ./install.sh
```

After installation:

```bash
p2wlan login -u you@example.com
p2wlan up
p2wlan status
p2wlan doctor
p2wlan logs -f
p2wlan down
```

Persistent configuration is stored in `~/.config/p2wlan/p2pnet-config.json`.
Runtime logs and the PID record are stored under `~/.local/state/p2wlan`.
Only `up` requires elevated privileges; login and configuration remain owned by
the invoking user.

Cloud servers should use a fixed UDP port and advertise the public endpoint if
direct UDP is expected:

```bash
p2wlan config set udp-bind 0.0.0.0:60207
p2wlan config set udp-advertise <public-ip>:60207
p2wlan config set relay-policy auto
```

The same UDP port must be allowed by the cloud security group and host firewall.
Published Linux CLI builds can update themselves:

```bash
p2wlan update
p2wlan update --version v0.1.28
```

`p2wlan doctor` prints peer UDP candidate previews and flags peers that only
advertise private or loopback endpoints, which usually means the peer still
needs `udp-advertise <public-ip>:<port>` plus matching firewall rules.

## Icon Generation

Icons are deterministic and generated from `scripts/generate-icons.py`:

```bash
pnpm run icons
```

This updates all Tauri icon outputs under `src-tauri/icons`, including macOS
`.icns`, Windows `.ico`, and PNG sizes used by installers.
