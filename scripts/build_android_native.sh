#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
app_root="$repo_root/apps/flutter_client"
ndk_root="${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}"

if [[ -z "$ndk_root" ]]; then
  sdk_root="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-}}"
  if [[ -z "$sdk_root" && -f "$app_root/android/local.properties" ]]; then
    sdk_root="$(sed -n 's/^sdk\.dir=//p' "$app_root/android/local.properties" | head -n 1)"
  fi
  if [[ -n "$sdk_root" && -d "$sdk_root/ndk" ]]; then
    ndk_root="$(find "$sdk_root/ndk" -mindepth 1 -maxdepth 1 -type d | sort | tail -n 1)"
  fi
fi

if [[ -z "$ndk_root" || ! -d "$ndk_root" ]]; then
  echo "Android NDK not found. Set ANDROID_NDK_HOME (or ANDROID_SDK_ROOT)." >&2
  exit 1
fi

case "$(uname -s)" in
  Darwin)
    if [[ -d "$ndk_root/toolchains/llvm/prebuilt/darwin-arm64" ]]; then
      host_tag="darwin-arm64"
    else
      host_tag="darwin-x86_64"
    fi
    ;;
  Linux) host_tag="linux-x86_64" ;;
  *) echo "Unsupported build host: $(uname -s)" >&2; exit 1 ;;
esac

llvm_bin="$ndk_root/toolchains/llvm/prebuilt/$host_tag/bin"
if [[ ! -x "$llvm_bin/llvm-ar" ]]; then
  echo "Android NDK LLVM toolchain not found at $llvm_bin" >&2
  exit 1
fi

build_native() {
  local target="$1"
  local abi="$2"
  local clang="$3"
  local required="${4:-false}"
  local target_key
  local cargo_target_key
  target_key="${target//-/_}"
  cargo_target_key="$(printf '%s' "$target_key" | tr '[:lower:]' '[:upper:]')"

  if ! rustup target list --installed | grep -Fxq "$target"; then
    if [[ "$required" == "true" ]]; then
      echo "Required Android Rust target is missing: $target (install it with: rustup target add $target)" >&2
      exit 1
    fi
    echo "Skipping Android Rust target $target (install it with: rustup target add $target)" >&2
    return 0
  fi
  if [[ ! -x "$llvm_bin/$clang" ]]; then
    if [[ "$required" != "true" ]]; then
      echo "Skipping Android ABI $abi (compiler missing: $llvm_bin/$clang)" >&2
      return 0
    fi
    echo "Android compiler missing: $llvm_bin/$clang" >&2
    exit 1
  fi

  local linker_var="CARGO_TARGET_${cargo_target_key}_LINKER"
  export "$linker_var=$llvm_bin/$clang"
  export "CC_${target_key}=$llvm_bin/$clang"
  export "CXX_${target_key}=$llvm_bin/${clang/clang/clang++}"
  export "AR_${target_key}=$llvm_bin/llvm-ar"
  cargo build --manifest-path "$repo_root/Cargo.toml" \
    -p p2wlan-android-native --release --target "$target"

  mkdir -p "$app_root/android/app/src/main/jniLibs/$abi"
  cp "$repo_root/target/$target/release/libp2wlan_android.so" \
    "$app_root/android/app/src/main/jniLibs/$abi/libp2wlan_android.so"
}

# Keep the app useful on the common 64-bit Android devices and emulators. ABI
# directories are generated only when their Rust target is installed, so a
# local arm64-only toolchain can still build an arm64 APK.
build_native "aarch64-linux-android" "arm64-v8a" "aarch64-linux-android23-clang" true
build_native "x86_64-linux-android" "x86_64" "x86_64-linux-android23-clang"
build_native "armv7-linux-androideabi" "armeabi-v7a" "armv7a-linux-androideabi23-clang"
build_native "i686-linux-android" "x86" "i686-linux-android23-clang"
