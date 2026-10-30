#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
WORKSPACE_ROOT="$(cd "$REPO_ROOT/.." && pwd)"

OHOS_ABI="${P2WLAN_OHOS_ABI:-arm64-v8a}"
case "$OHOS_ABI" in
  arm64-v8a)
    RUST_TARGET="aarch64-unknown-linux-ohos"
    CLANG_WRAPPER="aarch64-unknown-linux-ohos-clang"
    LLVM_LIBDIR="aarch64-linux-ohos"
    ;;
  x86_64)
    RUST_TARGET="x86_64-unknown-linux-ohos"
    CLANG_WRAPPER="x86_64-unknown-linux-ohos-clang"
    LLVM_LIBDIR="x86_64-linux-ohos"
    ;;
  *)
    echo "Unsupported P2WLAN_OHOS_ABI: $OHOS_ABI (supported: arm64-v8a, x86_64)." >&2
    exit 2
    ;;
esac

RUST_TOOLCHAIN="${P2WLAN_RUST_TOOLCHAIN:-1.99.0}"
DEVECO_SDK_HOME="${DEVECO_SDK_HOME:-}"
if [[ -z "$DEVECO_SDK_HOME" ]]; then
  echo "Set DEVECO_SDK_HOME to the installed DevEco SDK root." >&2
  exit 2
fi
OHOS_NATIVE_ROOT="$DEVECO_SDK_HOME/default/openharmony/native"
OHOS_CLANG="$OHOS_NATIVE_ROOT/llvm/bin/$CLANG_WRAPPER"
OHOS_AR="$OHOS_NATIVE_ROOT/llvm/bin/llvm-ar"
OHOS_READOBJ="$OHOS_NATIVE_ROOT/llvm/bin/llvm-readobj"
OHOS_NM="$OHOS_NATIVE_ROOT/llvm/bin/llvm-nm"
OHOS_SYSROOT="$OHOS_NATIVE_ROOT/sysroot"
export OHOS_SDK_NATIVE="$OHOS_NATIVE_ROOT"
for tool in "$OHOS_CLANG" "$OHOS_AR" "$OHOS_READOBJ" "$OHOS_NM"; do
  if [[ ! -x "$tool" ]]; then
    echo "Required OHOS SDK tool is missing or not executable: ${tool##*/}" >&2
    exit 2
  fi
done
if [[ ! -d "$OHOS_SYSROOT/usr/lib/$LLVM_LIBDIR" ]]; then
  echo "The OHOS SDK sysroot lacks ABI library directory $LLVM_LIBDIR." >&2
  exit 2
fi

# Prefer the isolated workspace toolchain when this workspace provisioned it.
LOCAL_CARGO_HOME="$WORKSPACE_ROOT/toolchains/rustup-ohos-cargo"
LOCAL_RUSTUP_HOME="$WORKSPACE_ROOT/toolchains/rustup-ohos-home"
if [[ -x "$LOCAL_CARGO_HOME/bin/cargo" && -x "$LOCAL_CARGO_HOME/bin/rustup" ]]; then
  export RUSTUP_HOME="$LOCAL_RUSTUP_HOME"
  export PATH="$LOCAL_CARGO_HOME/bin:$PATH"
fi

CARGO_BIN="$(command -v cargo || true)"
RUSTC_BIN="$(command -v rustc || true)"
if [[ -z "$CARGO_BIN" || -z "$RUSTC_BIN" ]]; then
  echo "Rust cargo and rustc must be available on PATH." >&2
  exit 2
fi
if [[ "$("$RUSTC_BIN" --version | awk '{print $2}')" != "$RUST_TOOLCHAIN" ]]; then
  echo "Expected rustc $RUST_TOOLCHAIN; found: $("$RUSTC_BIN" --version)." >&2
  exit 2
fi

TARGET_LIBDIR="$("$RUSTC_BIN" --print target-libdir --target "$RUST_TARGET")"
if [[ ! -d "$TARGET_LIBDIR" ]]; then
  echo "Rust target standard library is missing for $RUST_TARGET; install it with rustup target add --toolchain $RUST_TOOLCHAIN $RUST_TARGET." >&2
  exit 2
fi

export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_OHOS_LINKER="$OHOS_CLANG"
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_OHOS_AR="$OHOS_AR"
export CC_aarch64_unknown_linux_ohos="$OHOS_CLANG"
export AR_aarch64_unknown_linux_ohos="$OHOS_AR"
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_OHOS_RUSTFLAGS="${CARGO_TARGET_AARCH64_UNKNOWN_LINUX_OHOS_RUSTFLAGS:-} -C link-arg=-Wl,-soname,libp2wlan_harmony_core.so"
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_OHOS_LINKER="$OHOS_CLANG"
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_OHOS_AR="$OHOS_AR"
export CC_x86_64_unknown_linux_ohos="$OHOS_CLANG"
export AR_x86_64_unknown_linux_ohos="$OHOS_AR"
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_OHOS_RUSTFLAGS="${CARGO_TARGET_X86_64_UNKNOWN_LINUX_OHOS_RUSTFLAGS:-} -C link-arg=-Wl,-soname,libp2wlan_harmony_core.so"

TOOLCHAIN_DIR="${P2WLAN_TOOLCHAIN_DIR:-$WORKSPACE_ROOT/toolchains}"
LOCAL_CMAKE="$TOOLCHAIN_DIR/cmake-3.31.12-macos-universal/CMake.app/Contents/bin/cmake"
if [[ -n "${P2WLAN_CMAKE_BIN:-}" ]]; then
  export CMAKE="$P2WLAN_CMAKE_BIN"
elif [[ -z "${CMAKE:-}" && -x "$LOCAL_CMAKE" ]]; then
  export CMAKE="$LOCAL_CMAKE"
fi
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$TOOLCHAIN_DIR/p2wlan-harmony-target}"
RUST_LIB_DIR="$TOOLCHAIN_DIR/p2wlan-harmony-native/$OHOS_ABI"
mkdir -p "$RUST_LIB_DIR"

RUSTUP_TOOLCHAIN="$RUST_TOOLCHAIN" "$CARGO_BIN" build \
  --locked \
  --manifest-path "$REPO_ROOT/Cargo.toml" \
  --package p2wlan-harmony-native \
  --target "$RUST_TARGET" \
  --release

BUILT_LIBRARY="$CARGO_TARGET_DIR/$RUST_TARGET/release/libp2wlan_harmony_core.so"
if [[ ! -f "$BUILT_LIBRARY" ]]; then
  echo "Cargo succeeded but the expected cdylib was not produced." >&2
  exit 1
fi
install -m 755 "$BUILT_LIBRARY" "$RUST_LIB_DIR/libp2wlan_harmony_core.so"

HEADERS="$("$OHOS_READOBJ" --file-headers "$RUST_LIB_DIR/libp2wlan_harmony_core.so")"
if ! grep -q 'Machine: EM_AARCH64' <<<"$HEADERS" && [[ "$RUST_TARGET" == "aarch64-unknown-linux-ohos" ]]; then
  echo "The cdylib machine type does not match the arm64 OHOS target." >&2
  exit 1
fi
if ! grep -q 'Machine: EM_X86_64' <<<"$HEADERS" && [[ "$RUST_TARGET" == "x86_64-unknown-linux-ohos" ]]; then
  echo "The cdylib machine type does not match the x86_64 OHOS target." >&2
  exit 1
fi
EXPORTED_SYMBOLS="$("$OHOS_NM" --dynamic --defined-only "$RUST_LIB_DIR/libp2wlan_harmony_core.so")"
for symbol in \
  p2wlan_harmony_get_build_info_v1 \
  p2wlan_harmony_prepare_vpn_engine_v1 \
  p2wlan_harmony_prepare_vpn_network_v1 \
  p2wlan_harmony_discard_vpn_network_v1 \
  p2wlan_harmony_activate_vpn_engine_v1 \
  p2wlan_harmony_abort_vpn_engine_v1 \
  p2wlan_harmony_stop_vpn_engine_v1 \
  p2wlan_harmony_stop_vpn_engine_bounded_v1 \
  p2wlan_harmony_get_vpn_engine_status_v1; do
  if ! grep -Eq "[[:space:]]${symbol}$" <<<"$EXPORTED_SYMBOLS"; then
    echo "The expected FFI symbol is missing from the cdylib: $symbol" >&2
    exit 1
  fi
done

printf 'Built toolchains/p2wlan-harmony-native/%s/libp2wlan_harmony_core.so for %s with rustc %s.\n' "$OHOS_ABI" "$RUST_TARGET" "$RUST_TOOLCHAIN"
