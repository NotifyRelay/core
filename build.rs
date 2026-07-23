fn main() {
    setup_android_cmake_toolchain();
    fix_audiopus_cmake();

    let hash = std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    let dirty = std::process::Command::new("git")
        .args(["status", "--porcelain"])
        .output()
        .ok()
        .map(|o| !o.stdout.is_empty())
        .unwrap_or(false);

    let version = if dirty {
        format!("{}-dirty", hash)
    } else {
        hash
    };

    println!("cargo:rustc-env=NOTIFY_RELAY_GIT_HASH={}", version);
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/index");
    println!("cargo:rerun-if-changed=.git/refs/tags");
}

fn setup_android_cmake_toolchain() {
    let target = std::env::var("TARGET").unwrap_or_default();
    if !target.starts_with("aarch64-linux-android") && !target.starts_with("x86_64-linux-android") {
        return;
    }

    let ndk_home = match std::env::var("ANDROID_NDK_HOME") {
        Ok(h) => h,
        Err(_) => {
            if let Ok(sdk_home) = std::env::var("ANDROID_HOME") {
                let ndk_path = format!("{sdk_home}/ndk");
                if std::path::Path::new(&ndk_path).exists() {
                    if let Ok(entries) = std::fs::read_dir(&ndk_path) {
                        if let Some(entry) = entries.filter_map(|e| e.ok()).next() {
                            entry.path().to_string_lossy().to_string()
                        } else {
                            return;
                        }
                    } else {
                        return;
                    }
                } else {
                    return;
                }
            } else {
                return;
            }
        }
    };

    let toolchain_path = format!("{ndk_home}/build/cmake/android.toolchain.cmake");
    if std::path::Path::new(&toolchain_path).exists() {
        println!("cargo:rustc-env=CMAKE_TOOLCHAIN_FILE={toolchain_path}");
        println!("build.rs: set CMAKE_TOOLCHAIN_FILE for Android target: {toolchain_path}");
    }

    let ninja_path = format!("{ndk_home}/prebuilt/windows-x86_64/bin/ninja.exe");
    if std::path::Path::new(&ninja_path).exists() {
        println!("cargo:rustc-env=CMAKE_MAKE_PROGRAM={ninja_path}");
        println!("build.rs: set CMAKE_MAKE_PROGRAM for Android target: {ninja_path}");
    }
}

fn fix_audiopus_cmake() {
    let home = match std::env::var("USERPROFILE").or_else(|_| std::env::var("HOME")) {
        Ok(h) => h,
        Err(_) => return,
    };

    let patterns = [
        "**/audiopus-sys*/CMakeLists.txt",
        "**/audiopus_sys*/CMakeLists.txt",
    ];

    let re = match regex::Regex::new(r"^cmake_minimum_required\([^)]*\)") {
        Ok(r) => r,
        Err(_) => return,
    };

    for pattern in &patterns {
        let search_path = format!("{home}/.cargo/registry/src");
        if let Ok(entries) = glob::glob(&format!("{search_path}/**/{pattern}")) {
            for entry in entries.flatten() {
                if let Ok(content) = std::fs::read_to_string(&entry) {
                    if content.contains("cmake_minimum_required")
                        && !content.contains("VERSION 3.5")
                    {
                        let fixed = re.replace(&content, "cmake_minimum_required(VERSION 3.5)");
                        if let Err(e) = std::fs::write(&entry, fixed.as_ref()) {
                            eprintln!("build.rs: failed to patch audiopus CMakeLists.txt: {}", e);
                        } else {
                            println!(
                                "build.rs: patched audiopus CMakeLists.txt: {}",
                                entry.display()
                            );
                        }
                    }
                }
            }
        }
    }
}
