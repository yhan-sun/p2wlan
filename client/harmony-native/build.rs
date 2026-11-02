use std::env;

fn main() {
    let target = env::var("TARGET").expect("Cargo must set TARGET");
    let arch = env::var("CARGO_CFG_TARGET_ARCH").expect("Cargo must set CARGO_CFG_TARGET_ARCH");

    println!("cargo:rustc-env=P2WLAN_BUILD_TARGET={target}");
    println!("cargo:rustc-env=P2WLAN_BUILD_ARCH={arch}");
    println!("cargo:rerun-if-env-changed=TARGET");
    println!("cargo:rerun-if-env-changed=CARGO_CFG_TARGET_ARCH");
}
