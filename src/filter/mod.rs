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
