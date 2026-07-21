use std::os::raw::c_char;
use std::sync::Mutex;

use super::common::{from_cstr, to_cstr};
use crate::filter::RemoteFilterConfig;

/// 过滤器状态
pub struct FilterState {
    pub config: Mutex<RemoteFilterConfig>,
}

impl FilterState {
    pub fn new() -> Self {
        Self {
            config: Mutex::new(RemoteFilterConfig::new()),
        }
    }
}

/// 设置过滤配置（JSON 格式）
#[no_mangle]
pub unsafe extern "C" fn nrc_set_filter_config(
    ctx_ptr: *mut crate::SafeContext,
    config_json: *const c_char,
) -> i32 {
    if ctx_ptr.is_null() || config_json.is_null() {
        return -1;
    }
    let json_str = from_cstr(config_json);
    let ctx = &mut *(ctx_ptr as *mut crate::SafeContext);
    let guard = match ctx.lock() {
        Ok(g) => g,
        Err(_) => return -1,
    };

    let config = &guard.filter.config;
    let mut cfg = match config.lock() {
        Ok(c) => c,
        Err(_) => return -1,
    };

    if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&json_str) {
        if let Some(v) = parsed
            .get("enablePackageGroupMapping")
            .and_then(|v| v.as_bool())
        {
            cfg.enable_package_group_mapping = v;
        }
        if let Some(groups) = parsed.get("packageGroups").and_then(|v| v.as_array()) {
            cfg.package_groups.clear();
            for g in groups {
                if let (Some(name), Some(pkgs)) = (
                    g.get("groupName").and_then(|v| v.as_str()),
                    g.get("packages").and_then(|v| v.as_array()),
                ) {
                    let packages: Vec<String> = pkgs
                        .iter()
                        .filter_map(|p| p.as_str().map(|s| s.to_string()))
                        .collect();
                    cfg.package_groups.push(crate::filter::PackageGroup {
                        group_name: name.to_string(),
                        packages,
                    });
                }
            }
        }
        if let Some(enabled) = parsed.get("groupEnabled").and_then(|v| v.as_object()) {
            cfg.group_enabled.clear();
            for (k, v) in enabled {
                if let Some(b) = v.as_bool() {
                    cfg.group_enabled.insert(k.clone(), b);
                }
            }
        }
        if let Some(mode) = parsed.get("filterMode").and_then(|v| v.as_u64()) {
            cfg.filter_mode = mode as u32;
        }
        if let Some(list) = parsed.get("filterList").and_then(|v| v.as_array()) {
            cfg.filter_list.clear();
            for item in list {
                if let Some(s) = item.as_str() {
                    let parts: Vec<&str> = s.splitn(2, '|').collect();
                    cfg.filter_list.push(crate::filter::FilterListEntry {
                        package: parts[0].to_string(),
                        keyword: parts
                            .get(1)
                            .filter(|k| !k.is_empty())
                            .map(|k| k.to_string()),
                    });
                }
            }
        }
        if let Some(v) = parsed.get("enablePeerMode").and_then(|v| v.as_bool()) {
            cfg.enable_peer_mode = v;
        }
        if let Some(pkgs) = parsed.get("installedPackages").and_then(|v| v.as_array()) {
            cfg.installed_packages.clear();
            for p in pkgs {
                if let Some(s) = p.as_str() {
                    cfg.installed_packages.push(s.to_string());
                }
            }
        }
        0
    } else {
        -1
    }
}

/// 映射远程包名为本地包名
#[no_mangle]
pub unsafe extern "C" fn nrc_map_local_package(
    ctx_ptr: *mut crate::SafeContext,
    remote_package: *const c_char,
) -> *mut c_char {
    if ctx_ptr.is_null() || remote_package.is_null() {
        return to_cstr("");
    }
    let pkg = from_cstr(remote_package);
    let ctx = &mut *(ctx_ptr as *mut crate::SafeContext);
    let guard = match ctx.lock() {
        Ok(g) => g,
        Err(_) => return to_cstr(""),
    };
    let config = match guard.filter.config.lock() {
        Ok(c) => c,
        Err(_) => return to_cstr(""),
    };
    let mapped = config.map_to_local_package(&pkg);
    to_cstr(&mapped)
}

/// 检查过滤模式（返回 1=通过, 0=被过滤）
/// 参数: ctx, mappedPkg, originalPkg, title, text
/// title/text 用于关键词匹配
#[no_mangle]
pub unsafe extern "C" fn nrc_check_filter_mode(
    ctx_ptr: *mut crate::SafeContext,
    mapped_package: *const c_char,
    _original_package: *const c_char,
    title: *const c_char,
    text: *const c_char,
) -> i32 {
    if ctx_ptr.is_null() || mapped_package.is_null() {
        return 1;
    }
    let pkg = from_cstr(mapped_package);
    let title_str = if title.is_null() {
        ""
    } else {
        from_cstr(title)
    };
    let text_str = if text.is_null() {
        ""
    } else {
        from_cstr(text)
    };
    let ctx = &mut *(ctx_ptr as *mut crate::SafeContext);
    let guard = match ctx.lock() {
        Ok(g) => g,
        Err(_) => return 1,
    };
    let config = match guard.filter.config.lock() {
        Ok(c) => c,
        Err(_) => return 1,
    };
    if config.check_filter_mode(&pkg, title_str, text_str) {
        1
    } else {
        0
    }
}

/// 过滤通知（返回 1=通过, 0=被过滤）
/// 支持通过 title/text 关键词匹配过滤条目
#[no_mangle]
pub unsafe extern "C" fn nrc_filter_notification(
    ctx_ptr: *mut crate::SafeContext,
    package_name: *const c_char,
    title: *const c_char,
    text: *const c_char,
) -> i32 {
    if ctx_ptr.is_null() || package_name.is_null() {
        return 1;
    }
    let pkg = from_cstr(package_name);
    let title_str = if title.is_null() {
        ""
    } else {
        from_cstr(title)
    };
    let text_str = if text.is_null() {
        ""
    } else {
        from_cstr(text)
    };

    let ctx = &mut *(ctx_ptr as *mut crate::SafeContext);
    let guard = match ctx.lock() {
        Ok(g) => g,
        Err(_) => return 1,
    };
    let config = match guard.filter.config.lock() {
        Ok(c) => c,
        Err(_) => return 1,
    };

    if config.check_filter_mode(&pkg, title_str, text_str) {
        1
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    fn to_cstr_test(s: &str) -> *const c_char {
        CString::new(s).unwrap().into_raw()
    }

    #[test]
    fn test_filter_state_new() {
        let state = FilterState::new();
        let config = state.config.lock().unwrap();
        assert!(!config.enable_package_group_mapping);
        assert_eq!(config.filter_mode, 0);
    }

    #[test]
    fn test_set_and_check_filter() {
        let ctx = crate::SafeContext::new(crate::CoreContext::new());
        let ctx_ptr = &ctx as *const crate::SafeContext as *mut crate::SafeContext;

        let config_json = r#"{"filterMode":1,"filterList":["com.allowed"]}"#;
        let json_ptr = to_cstr_test(config_json);
        let result = unsafe { nrc_set_filter_config(ctx_ptr, json_ptr) };
        assert_eq!(result, 0);
        unsafe {
            let _ = CString::from_raw(json_ptr as *mut c_char);
        }

        let pkg_ptr = to_cstr_test("com.allowed");
        let empty = to_cstr_test("");
        let check = unsafe { nrc_check_filter_mode(ctx_ptr, pkg_ptr, empty, empty, empty) };
        assert_eq!(check, 1);
        unsafe {
            let _ = CString::from_raw(pkg_ptr as *mut c_char);
        }

        let pkg_ptr2 = to_cstr_test("com.blocked");
        let check2 = unsafe { nrc_check_filter_mode(ctx_ptr, pkg_ptr2, empty, empty, empty) };
        assert_eq!(check2, 0);
        unsafe {
            let _ = CString::from_raw(pkg_ptr2 as *mut c_char);
        }
        unsafe {
            let _ = CString::from_raw(empty as *mut c_char);
        }
    }
}
