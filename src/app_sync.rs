use std::collections::HashMap;

/// 图标请求超时（毫秒），与平台端一致
const ICON_REQUEST_TIMEOUT_MS: i64 = 10_000;

/// 应用列表/图标同步状态（Rust 内部维护 pending 请求与超时清理）
pub struct AppSyncState {
    /// packageName -> requestTime
    pub pending_icons: HashMap<String, i64>,
}

impl AppSyncState {
    pub fn new() -> Self {
        Self {
            pending_icons: HashMap::new(),
        }
    }
}

impl Default for AppSyncState {
    fn default() -> Self {
        Self::new()
    }
}

/// 判断包名是否应请求图标：
/// - 未缓存
/// - 未本机安装
/// - 不在进行中的请求内（或已过期）
/// - 设备关联：无关联记录或关联包含源设备 UUID
fn should_request_icon(
    pkg: &str,
    installed: &[String],
    cached: &[String],
    app_device: &HashMap<String, Vec<String>>,
    source_device_uuid: &str,
    now: i64,
    pending: &HashMap<String, i64>,
) -> bool {
    if cached.contains(&pkg.to_string()) {
        return false;
    }
    if installed.contains(&pkg.to_string()) {
        return false;
    }
    if let Some(&ts) = pending.get(pkg) {
        if now - ts < ICON_REQUEST_TIMEOUT_MS {
            return false;
        }
    }
    match app_device.get(pkg) {
        None => true,
        Some(uuids) => uuids.is_empty() || uuids.iter().any(|u| u == source_device_uuid),
    }
}

/// 批量过滤并构造图标请求报文。
/// 返回 JSON：{"type":"ICON_REQUEST","packageNames":[...],"time":now}（多包）
///           或 {"type":"ICON_REQUEST","packageName":"...","time":now}（单包）
/// 无需请求时返回空 JSON {}。
pub fn prepare_icon_request(
    state: &mut AppSyncState,
    packages: &[String],
    installed: &[String],
    cached: &[String],
    app_device: &HashMap<String, Vec<String>>,
    source_device_uuid: &str,
    now: i64,
) -> String {
    // 清理过期 pending
    state
        .pending_icons
        .retain(|_, &mut ts| now - ts < ICON_REQUEST_TIMEOUT_MS);

    let need: Vec<String> = packages
        .iter()
        .filter(|p| {
            should_request_icon(
                p,
                installed,
                cached,
                app_device,
                source_device_uuid,
                now,
                &state.pending_icons,
            )
        })
        .cloned()
        .collect();

    if need.is_empty() {
        return "{}".to_string();
    }

    for p in &need {
        state.pending_icons.insert(p.clone(), now);
    }

    let mut obj = serde_json::json!({
        "type": "ICON_REQUEST",
        "time": now,
    });
    if need.len() == 1 {
        obj["packageName"] = serde_json::Value::String(need[0].clone());
    } else {
        obj["packageNames"] = serde_json::Value::Array(
            need.iter()
                .map(|p| serde_json::Value::String(p.clone()))
                .collect(),
        );
    }
    obj.to_string()
}

/// 清除已完成的图标请求登记（收到响应或关联成功后调用）
pub fn clear_icon_pending(state: &mut AppSyncState, packages: &[String]) {
    for p in packages {
        state.pending_icons.remove(p);
    }
}

/// 解析图标响应报文。
/// 返回 JSON：{"icons":[{"packageName":"..","iconData":".."}],"missing":[".."]}
pub fn parse_icon_response(payload: &str) -> String {
    let mut icons: Vec<serde_json::Value> = Vec::new();
    let mut missing: Vec<String> = Vec::new();

    let root = match serde_json::from_str::<serde_json::Value>(payload) {
        Ok(v) => v,
        Err(_) => return serde_json::json!({"icons":[], "missing":[]}).to_string(),
    };

    if let Some(arr) = root.get("icons").and_then(|v| v.as_array()) {
        for item in arr {
            if let Some(obj) = item.as_object() {
                if let (Some(pkg), Some(data)) = (
                    obj.get("packageName").and_then(|v| v.as_str()),
                    obj.get("iconData").and_then(|v| v.as_str()),
                ) {
                    icons.push(serde_json::json!({
                        "packageName": pkg,
                        "iconData": data,
                    }));
                }
            }
        }
    }
    if let Some(single_pkg) = root.get("packageName").and_then(|v| v.as_str()) {
        if single_pkg.is_empty() {
            // 无
        } else if let Some(data) = root.get("iconData").and_then(|v| v.as_str()) {
            if !data.is_empty() {
                icons.push(serde_json::json!({
                    "packageName": single_pkg,
                    "iconData": data,
                }));
            }
        } else if root
            .get("missing")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            missing.push(single_pkg.to_string());
        }
    }
    if let Some(arr) = root.get("missing").and_then(|v| v.as_array()) {
        for m in arr {
            if let Some(s) = m.as_str() {
                if !s.is_empty() {
                    missing.push(s.to_string());
                }
            }
        }
    }

    serde_json::json!({ "icons": icons, "missing": missing }).to_string()
}

/// 构造应用列表请求报文。
/// 返回 JSON：{"type":"APP_LIST_REQUEST","scope":"user","time":now}
pub fn build_applist_request(scope: &str, now: i64) -> String {
    serde_json::json!({
        "type": "APP_LIST_REQUEST",
        "scope": scope,
        "time": now,
    })
    .to_string()
}

/// 解析应用列表响应报文。
/// 返回 JSON：{"apps":[{"packageName":"..","appName":".."}],"scope":"..","total":N}
pub fn parse_applist_response(payload: &str) -> String {
    let mut apps: Vec<serde_json::Value> = Vec::new();
    let mut scope = String::from("user");
    let mut total = 0;

    let root = match serde_json::from_str::<serde_json::Value>(payload) {
        Ok(v) => v,
        Err(_) => return serde_json::json!({"apps":[], "scope":"user", "total":0}).to_string(),
    };

    if let Some(s) = root.get("scope").and_then(|v| v.as_str()) {
        scope = s.to_string();
    }
    if let Some(arr) = root.get("apps").and_then(|v| v.as_array()) {
        for item in arr {
            if let Some(obj) = item.as_object() {
                if let Some(pkg) = obj.get("packageName").and_then(|v| v.as_str()) {
                    if pkg.is_empty() {
                        continue;
                    }
                    let name = obj
                        .get("appName")
                        .and_then(|v| v.as_str())
                        .unwrap_or(pkg)
                        .to_string();
                    apps.push(serde_json::json!({
                        "packageName": pkg,
                        "appName": name,
                    }));
                }
            }
        }
    }
    if let Some(t) = root.get("total").and_then(|v| v.as_i64()) {
        total = t;
    }

    serde_json::json!({
        "apps": apps,
        "scope": scope,
        "total": if total == 0 { apps.len() as i64 } else { total },
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prepare_icon_request_empty() {
        let mut state = AppSyncState::new();
        let result = prepare_icon_request(&mut state, &[], &[], &[], &HashMap::new(), "dev1", 1000);
        assert_eq!(result, "{}");
    }

    #[test]
    fn test_prepare_icon_request_single() {
        let mut state = AppSyncState::new();
        let result = prepare_icon_request(
            &mut state,
            &["com.a".to_string()],
            &[],
            &[],
            &HashMap::new(),
            "dev1",
            1000,
        );
        assert!(result.contains("\"packageName\":\"com.a\""));
        assert!(state.pending_icons.contains_key("com.a"));
    }

    #[test]
    fn test_prepare_icon_request_filters_installed_cached() {
        let mut state = AppSyncState::new();
        let result = prepare_icon_request(
            &mut state,
            &[
                "com.installed".to_string(),
                "com.cached".to_string(),
                "com.need".to_string(),
            ],
            &["com.installed".to_string()],
            &["com.cached".to_string()],
            &HashMap::new(),
            "dev1",
            1000,
        );
        assert!(result.contains("\"packageName\":\"com.need\""));
    }

    #[test]
    fn test_prepare_icon_request_pending_inflight() {
        let mut state = AppSyncState::new();
        state.pending_icons.insert("com.a".to_string(), 900);
        let result = prepare_icon_request(
            &mut state,
            &["com.a".to_string()],
            &[],
            &[],
            &HashMap::new(),
            "dev1",
            1000,
        );
        assert_eq!(result, "{}");
    }

    #[test]
    fn test_prepare_icon_request_device_association() {
        let mut state = AppSyncState::new();
        let mut app_device = HashMap::new();
        app_device.insert("com.other".to_string(), vec!["dev2".to_string()]);
        // 关联到其它设备：不应请求
        let result = prepare_icon_request(
            &mut state,
            &["com.other".to_string()],
            &[],
            &[],
            &app_device,
            "dev1",
            1000,
        );
        assert_eq!(result, "{}");
        // 关联包含源设备：应请求
        app_device.insert(
            "com.both".to_string(),
            vec!["dev1".to_string(), "dev2".to_string()],
        );
        let result2 = prepare_icon_request(
            &mut state,
            &["com.both".to_string()],
            &[],
            &[],
            &app_device,
            "dev1",
            1000,
        );
        assert!(result2.contains("\"com.both\""));
    }

    #[test]
    fn test_parse_icon_response_batch() {
        let payload = r#"{"type":"ICON_RESPONSE","icons":[{"packageName":"com.a","iconData":"AAA="}],"missing":["com.b"],"time":1}"#;
        let result = parse_icon_response(payload);
        let v: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(v["icons"][0]["packageName"], "com.a");
        assert_eq!(v["icons"][0]["iconData"], "AAA=");
        assert_eq!(v["missing"][0], "com.b");
    }

    #[test]
    fn test_parse_icon_response_single() {
        let payload =
            r#"{"type":"ICON_RESPONSE","packageName":"com.a","iconData":"BBB=","time":1}"#;
        let result = parse_icon_response(payload);
        let v: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(v["icons"][0]["packageName"], "com.a");
        assert!(v["missing"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_parse_icon_response_single_missing() {
        let payload = r#"{"type":"ICON_RESPONSE","packageName":"com.a","missing":true,"time":1}"#;
        let result = parse_icon_response(payload);
        let v: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(v["missing"][0], "com.a");
        assert!(v["icons"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_build_applist_request() {
        let result = build_applist_request("user", 1000);
        let v: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(v["type"], "APP_LIST_REQUEST");
        assert_eq!(v["scope"], "user");
    }

    #[test]
    fn test_parse_applist_response() {
        let payload = r#"{"type":"APP_LIST_RESPONSE","scope":"user","apps":[{"packageName":"com.a","appName":"A"}],"total":1,"time":1}"#;
        let result = parse_applist_response(payload);
        let v: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(v["apps"][0]["packageName"], "com.a");
        assert_eq!(v["apps"][0]["appName"], "A");
        assert_eq!(v["total"], 1);
    }
}
