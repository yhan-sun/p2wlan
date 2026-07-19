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

The release workflow builds a headless Linux x64 CLI tarball containing:

- `p2pnet-daemon`
- `LICENSE`
- `README-LINUX-CLI.txt`

The CLI package is intended for servers, headless Linux hosts, and real TUN
smoke testing. Running real TUN mode requires root privileges or equivalent
`CAP_NET_ADMIN` capability:

```bash
sudo ./p2pnet-daemon --init --control http://CONTROL_HOST:18080 --network default
sudo ./p2pnet-daemon --control http://CONTROL_HOST:18080 --network default
./p2pnet-daemon --status
```

## Icon Generation

Icons are deterministic and generated from `scripts/generate-icons.py`:

```bash
pnpm run icons
```

This updates all Tauri icon outputs under `src-tauri/icons`, including macOS
`.icns`, Windows `.ico`, and PNG sizes used by installers.
