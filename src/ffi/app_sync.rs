use std::os::raw::{c_char, c_void};

use super::common::{from_cstr, to_cstr};

/// 批量过滤并构造图标请求报文（Rust 内部维护 pending 状态与超时清理）。
///
/// 参数：
/// - packages_json: 候选包名数组 JSON
/// - installed_json: 本机已安装包名数组 JSON
/// - cached_json: 已缓存图标包名数组 JSON
/// - app_device_json: 包名 -> 来源设备 UUID 数组 的映射 JSON（可能为空对象 {}）
/// - source_device_uuid: 当前来源设备 UUID
/// - now_ms: 当前时间戳（毫秒）
///
/// 返回 JSON（ICON_REQUEST 报文）；无需请求时返回 {}
#[no_mangle]
pub unsafe extern "C" fn nrc_app_sync_prepare_icon_request(
    ctx_ptr: *mut c_void,
    packages_json: *const c_char,
    installed_json: *const c_char,
    cached_json: *const c_char,
    app_device_json: *const c_char,
    source_device_uuid: *const c_char,
    now_ms: i64,
) -> *mut c_char {
    if ctx_ptr.is_null() {
        return to_cstr("{}");
    }
    let packages = parse_str_array(from_cstr(packages_json));
    let installed = parse_str_array(from_cstr(installed_json));
    let cached = parse_str_array(from_cstr(cached_json));
    let app_device = parse_map(from_cstr(app_device_json));
    let source = from_cstr(source_device_uuid);

    let ctx = &mut *(ctx_ptr as *mut crate::SafeContext);
    let guard = match ctx.get_mut() {
        Ok(g) => g,
        Err(_) => return to_cstr("{}"),
    };
    let result = crate::app_sync::prepare_icon_request(
        &mut guard.app_sync,
        &packages,
        &installed,
        &cached,
        &app_device,
        source,
        now_ms,
    );
    to_cstr(&result)
}

/// 清除已完成的图标请求登记（收到响应或关联成功后调用）
#[no_mangle]
pub unsafe extern "C" fn nrc_app_sync_clear_icon_pending(
    ctx_ptr: *mut c_void,
    packages_json: *const c_char,
) {
    if ctx_ptr.is_null() {
        return;
    }
    let packages = parse_str_array(from_cstr(packages_json));
    let ctx = &mut *(ctx_ptr as *mut crate::SafeContext);
    if let Ok(g) = ctx.get_mut() {
        crate::app_sync::clear_icon_pending(&mut g.app_sync, &packages);
    }
}

/// 解析图标响应报文（ICON_RESPONSE）。
/// 返回 JSON：{"icons":[{"packageName":"..","iconData":".."}],"missing":[".."]}
#[no_mangle]
pub unsafe extern "C" fn nrc_app_sync_parse_icon_response(
    payload_json: *const c_char,
) -> *mut c_char {
    let payload = from_cstr(payload_json);
    let result = crate::app_sync::parse_icon_response(payload);
    to_cstr(&result)
}

/// 构造应用列表请求报文（APP_LIST_REQUEST）。
/// 参数 scope: 范围（如 "user"）
/// 返回 JSON：{"type":"APP_LIST_REQUEST","scope":"..","time":now}
#[no_mangle]
pub unsafe extern "C" fn nrc_app_sync_build_applist_request(
    scope: *const c_char,
    now_ms: i64,
) -> *mut c_char {
    let scope_str = from_cstr(scope);
    let result = crate::app_sync::build_applist_request(scope_str, now_ms);
    to_cstr(&result)
}

/// 解析应用列表响应报文（APP_LIST_RESPONSE）。
/// 返回 JSON：{"apps":[{"packageName":"..","appName":".."}],"scope":"..","total":N}
#[no_mangle]
pub unsafe extern "C" fn nrc_app_sync_parse_applist_response(
    payload_json: *const c_char,
) -> *mut c_char {
    let payload = from_cstr(payload_json);
    let result = crate::app_sync::parse_applist_response(payload);
    to_cstr(&result)
}

fn parse_str_array(s: &str) -> Vec<String> {
    serde_json::from_str::<Vec<String>>(s)
        .unwrap_or_default()
        .into_iter()
        .filter(|x| !x.is_empty())
        .collect()
}

fn parse_map(s: &str) -> std::collections::HashMap<String, Vec<String>> {
    let mut map = std::collections::HashMap::new();
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(s) {
        if let Some(obj) = v.as_object() {
            for (k, val) in obj {
                if let Some(arr) = val.as_array() {
                    let uuids: Vec<String> = arr
                        .iter()
                        .filter_map(|x| x.as_str().map(|s| s.to_string()))
                        .filter(|x| !x.is_empty())
                        .collect();
                    map.insert(k.clone(), uuids);
                }
            }
        }
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    fn to_cstr_test(s: &str) -> *const c_char {
        std::ffi::CString::new(s).unwrap().into_raw()
    }

    fn free_cstr(p: *const c_char) {
        unsafe {
            let _ = std::ffi::CString::from_raw(p as *mut c_char);
        }
    }

    #[test]
    fn test_prepare_icon_request_ffi() {
        let ctx = crate::SafeContext::new(crate::CoreContext::new());
        let ctx_ptr = &ctx as *const crate::SafeContext as *mut std::os::raw::c_void;

        let p = to_cstr_test(r#"["com.a","com.b"]"#);
        let i = to_cstr_test(r#"["com.b"]"#);
        let c = to_cstr_test(r#"[]"#);
        let m = to_cstr_test(r#"{}"#);
        let s = to_cstr_test("dev1");
        let result = unsafe { nrc_app_sync_prepare_icon_request(ctx_ptr, p, i, c, m, s, 1000) };
        let out = unsafe { from_cstr(result).to_string() };
        assert!(out.contains("com.a"));
        assert!(!out.contains("com.b"));
        free_cstr(p);
        free_cstr(i);
        free_cstr(c);
        free_cstr(m);
        free_cstr(s);
        free_cstr(result);
    }

    #[test]
    fn test_parse_icon_response_ffi() {
        let payload = to_cstr_test(
            r#"{"icons":[{"packageName":"com.a","iconData":"A"}],"missing":["com.b"]}"#,
        );
        let result = unsafe { nrc_app_sync_parse_icon_response(payload) };
        let out = unsafe { from_cstr(result).to_string() };
        assert!(out.contains("\"com.a\""));
        assert!(out.contains("\"com.b\""));
        free_cstr(payload);
        free_cstr(result);
    }
}
