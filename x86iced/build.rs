use std::process::Command;

fn r2_env(key: &str) -> String {
    for bin in ["r2", "radare2"] {
        if let Ok(output) = Command::new(bin).args(["-H", key]).output() {
            if output.status.success() {
                let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !value.is_empty() {
                    return value;
                }
            }
        }
    }
    panic!("failed to run r2 -H {key}");
}

fn main() {
    let version = r2_env("R2_VERSION");
    let abiversion: u32 = r2_env("R2_ABIVERSION")
        .parse()
        .expect("R2_ABIVERSION is not a valid u32");

    println!("cargo:rustc-env=R2_VERSION={version}");
    println!("cargo:rustc-env=R2_ABIVERSION={abiversion}");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=PATH");
}
