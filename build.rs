fn main() {
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
