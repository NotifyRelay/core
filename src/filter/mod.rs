use std::collections::HashMap;

/// 包分组映射条目
#[derive(Clone, Debug)]
pub struct PackageGroup {
    pub group_name: String,
    pub packages: Vec<String>,
}

/// 过滤列表条目（支持关键词过滤）
#[derive(Clone, Debug)]
pub struct FilterListEntry {
    pub package: String,
    pub keyword: Option<String>,
}

/// 远程过滤配置
#[derive(Clone, Debug, Default)]
pub struct RemoteFilterConfig {
    pub enable_package_group_mapping: bool,
    pub package_groups: Vec<PackageGroup>,
    pub group_enabled: HashMap<String, bool>,
    pub filter_mode: u32,
    pub filter_list: Vec<FilterListEntry>,
    pub enable_peer_mode: bool,
    pub installed_packages: Vec<String>,
}

impl RemoteFilterConfig {
    pub fn new() -> Self {
        Self::default()
    }

    /// 将远程包名映射为本地包名
    pub fn map_to_local_package(&self, remote_pkg: &str) -> String {
        if !self.enable_package_group_mapping {
            return remote_pkg.to_string();
        }
        for group in &self.package_groups {
            if group.packages.contains(&remote_pkg.to_string()) {
                if let Some(enabled) = self.group_enabled.get(&group.group_name) {
                    if *enabled {
                        return group.group_name.clone();
                    }
                }
            }
        }
        remote_pkg.to_string()
    }

    /// 检查包名是否匹配某条过滤条目（含关键词匹配）
    pub fn matches_filter_entry(&self, pkg: &str, title: &str, text: &str) -> bool {
        self.filter_list.iter().any(|entry| {
            if entry.package != pkg {
                return false;
            }
            match &entry.keyword {
                None => true,
                Some(kw) => title.contains(kw.as_str()) || text.contains(kw.as_str()),
            }
        })
    }

    /// 检查过滤模式: 0=不过滤, 1=白名单, 2=黑名单
    pub fn check_filter_mode(&self, package_name: &str, title: &str, text: &str) -> bool {
        match self.filter_mode {
            0 => true,
            1 => self.matches_filter_entry(package_name, title, text),
            2 => !self.matches_filter_entry(package_name, title, text),
            _ => true,
        }
    }

    /// 检查包名是否在过滤列表中（简化版，无关键词匹配）
    pub fn is_in_filter_list(&self, package_name: &str) -> bool {
        self.filter_list
            .iter()
            .any(|entry| entry.package == package_name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_config() {
        let config = RemoteFilterConfig::new();
        assert!(!config.enable_package_group_mapping);
        assert!(config.package_groups.is_empty());
        assert_eq!(config.filter_mode, 0);
        assert!(config.filter_list.is_empty());
    }

    #[test]
    fn test_map_to_local_package_disabled() {
        let config = RemoteFilterConfig::new();
        assert_eq!(config.map_to_local_package("com.test"), "com.test");
    }

    #[test]
    fn test_map_to_local_package_enabled() {
        let mut config = RemoteFilterConfig::new();
        config.enable_package_group_mapping = true;
        config.package_groups.push(PackageGroup {
            group_name: "messaging".to_string(),
            packages: vec!["com.whatsapp".to_string(), "com.telegram".to_string()],
        });
        config.group_enabled.insert("messaging".to_string(), true);
        assert_eq!(config.map_to_local_package("com.whatsapp"), "messaging");
        assert_eq!(config.map_to_local_package("com.unknown"), "com.unknown");
    }

    #[test]
    fn test_check_filter_mode() {
        let mut config = RemoteFilterConfig::new();
        config.filter_list.push(FilterListEntry {
            package: "com.allowed".to_string(),
            keyword: None,
        });

        config.filter_mode = 0;
        assert!(config.check_filter_mode("com.any", "", ""));

        config.filter_mode = 1;
        assert!(config.check_filter_mode("com.allowed", "", ""));
        assert!(!config.check_filter_mode("com.blocked", "", ""));

        config.filter_mode = 2;
        assert!(!config.check_filter_mode("com.allowed", "", ""));
        assert!(config.check_filter_mode("com.blocked", "", ""));
    }

    #[test]
    fn test_filter_list_keyword() {
        let mut config = RemoteFilterConfig::new();
        config.filter_list.push(FilterListEntry {
            package: "com.app".to_string(),
            keyword: Some("blocked".to_string()),
        });

        config.filter_mode = 2; // blacklist
                                // keyword matches → blocked
        assert!(!config.check_filter_mode("com.app", "blocked content", ""));
        // keyword doesn't match → not blocked
        assert!(config.check_filter_mode("com.app", "normal content", ""));
        // different package → not blocked
        assert!(config.check_filter_mode("com.other", "blocked content", ""));
    }

    #[test]
    fn test_is_in_filter_list() {
        let mut config = RemoteFilterConfig::new();
        config.filter_list.push(FilterListEntry {
            package: "com.whitelist".to_string(),
            keyword: None,
        });
        assert!(config.is_in_filter_list("com.whitelist"));
        assert!(!config.is_in_filter_list("com.other"));
    }
}

// ===== 上下文级过滤状态 =====

use std::sync::Mutex;

/// 过滤器状态（存于核心上下文）。
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

impl Default for FilterState {
    fn default() -> Self {
        Self::new()
    }
}

/// 应用远端过滤配置 JSON；解析失败返回 `false`。
pub fn set_config_json(state: &FilterState, config_json: &str) -> bool {
    let mut cfg = match state.config.lock() {
        Ok(c) => c,
        Err(_) => return false,
    };

    let Ok(parsed) = serde_json::from_str::<serde_json::Value>(config_json) else {
        return false;
    };
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
                cfg.package_groups.push(PackageGroup {
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
                cfg.filter_list.push(FilterListEntry {
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
    true
}

/// 映射远程包名为本地包名；配置锁不可用时回退原值。
pub fn map_local_package(state: &FilterState, remote_package: &str) -> String {
    match state.config.lock() {
        Ok(config) => config.map_to_local_package(remote_package),
        Err(_) => remote_package.to_string(),
    }
}

/// 过滤检查：`true` 表示通过（应展示）。
pub fn check_mode(state: &FilterState, package: &str, title: &str, text: &str) -> bool {
    match state.config.lock() {
        Ok(config) => config.check_filter_mode(package, title, text),
        Err(_) => true,
    }
}

#[cfg(test)]
mod state_tests {
    use super::*;

    #[test]
    fn test_filter_state_new() {
        let state = FilterState::new();
        let config = state.config.lock().unwrap();
        assert!(!config.enable_package_group_mapping);
        assert_eq!(config.filter_mode, 0);
    }

    #[test]
    fn test_set_and_check_filter() {
        let state = FilterState::new();
        assert!(set_config_json(
            &state,
            r#"{"filterMode":1,"filterList":["com.allowed"]}"#
        ));
        assert!(check_mode(&state, "com.allowed", "", ""));
        assert!(!check_mode(&state, "com.blocked", "", ""));
    }
}
