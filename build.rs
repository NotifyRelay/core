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

    let abi = if target.starts_with("aarch64-linux-android") {
        "arm64-v8a"
    } else {
        "x86_64"
    };

    let toolchain_path = format!("{ndk_home}/build/cmake/android.toolchain.cmake");
    if std::path::Path::new(&toolchain_path).exists() {
        println!("cargo:rustc-env=CMAKE_TOOLCHAIN_FILE={toolchain_path}");
        println!("build.rs: set CMAKE_TOOLCHAIN_FILE for Android target: {toolchain_path}");
    }

    let mut ninja_path = format!("{ndk_home}/prebuilt/windows-x86_64/bin/ninja.exe");
    if !std::path::Path::new(&ninja_path).exists() {
        ninja_path = "C:/msys64/ucrt64/bin/ninja.exe".to_string();
    }
    if std::path::Path::new(&ninja_path).exists() {
        println!("cargo:rustc-env=CMAKE_MAKE_PROGRAM={ninja_path}");
        println!("build.rs: set CMAKE_MAKE_PROGRAM for Android target: {ninja_path}");
    }

    println!("cargo:rustc-env=ANDROID_ABI={abi}");
    println!("cargo:rustc-env=ANDROID_PLATFORM=android-21");

    let cmake_args = format!("-DANDROID_ABI={abi} -DANDROID_PLATFORM=android-21");
    println!("cargo:rustc-env=CMAKE_ARGS={cmake_args}");
    println!("build.rs: set CMAKE_ARGS for Android target: {cmake_args}");

    if let Err(e) = build_opus_for_android(&ndk_home, &ninja_path, &abi) {
        eprintln!("build.rs: failed to build opus for android: {e}");
    }
}

fn build_opus_for_android(ndk_home: &str, ninja_path: &str, abi: &str) -> std::io::Result<()> {
    let home = match std::env::var("USERPROFILE").or_else(|_| std::env::var("HOME")) {
        Ok(h) => h,
        Err(_) => return Ok(()),
    };

    let patterns = [
        "**/audiopus-sys*/opus",
        "**/audiopus_sys*/opus",
    ];

    for pattern in &patterns {
        let search_path = format!("{home}/.cargo/registry/src");
        if let Ok(entries) = glob::glob(&format!("{search_path}/**/{pattern}")) {
            for entry in entries.flatten() {
                let build_dir = entry.join(format!("build-{abi}"));
                let lib_dir = build_dir.join("lib");
                let lib_file = lib_dir.join("libopus.a");

                if lib_file.exists() {
                    let lib_opus_dir = build_dir.to_string_lossy().to_string();
                    println!("cargo:rustc-env=LIBOPUS_LIB_DIR={lib_opus_dir}");
                    println!("build.rs: using prebuilt opus for {abi}: {lib_opus_dir}");
                    return Ok(());
                }

                let toolchain_path = format!("{ndk_home}/build/cmake/android.toolchain.cmake");
                let status = std::process::Command::new("cmake")
                    .arg("-B").arg(&build_dir)
                    .arg("-DCMAKE_TOOLCHAIN_FILE=").arg(&toolchain_path)
                    .arg("-DCMAKE_MAKE_PROGRAM=").arg(ninja_path)
                    .arg("-DANDROID_ABI=").arg(abi)
                    .arg("-DANDROID_PLATFORM=android-21")
                    .arg("-DCMAKE_BUILD_TYPE=Release")
                    .arg("-DBUILD_SHARED_LIBS=OFF")
                    .arg("-G").arg("Ninja")
                    .current_dir(&entry)
                    .status()?;

                if !status.success() {
                    continue;
                }

                let status = std::process::Command::new(ninja_path)
                    .current_dir(&build_dir)
                    .status()?;

                if !status.success() {
                    continue;
                }

                std::fs::create_dir_all(&lib_dir)?;
                let src_lib = build_dir.join("libopus.a");
                if src_lib.exists() {
                    std::fs::copy(&src_lib, &lib_file)?;
                    let lib_opus_dir = build_dir.to_string_lossy().to_string();
                    println!("cargo:rustc-env=LIBOPUS_LIB_DIR={lib_opus_dir}");
                    println!("build.rs: built opus for {abi}: {lib_opus_dir}");
                    return Ok(());
                }
            }
        }
    }

    Ok(())
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
