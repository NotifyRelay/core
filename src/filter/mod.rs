use std::collections::HashMap;

/// 包分组映射条目
#[derive(Clone, Debug)]
pub struct PackageGroup {
    pub group_name: String,
    pub packages: Vec<String>,
}

/// 远程过滤配置
#[derive(Clone, Debug, Default)]
pub struct RemoteFilterConfig {
    pub enable_package_group_mapping: bool,
    pub package_groups: Vec<PackageGroup>,
    pub group_enabled: HashMap<String, bool>,
    pub filter_mode: u32,
    pub filter_list: Vec<String>,
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

    /// 检查过滤模式: 0=不过滤, 1=白名单, 2=黑名单
    pub fn check_filter_mode(&self, package_name: &str) -> bool {
        match self.filter_mode {
            0 => true,
            1 => self.filter_list.contains(&package_name.to_string()),
            2 => !self.filter_list.contains(&package_name.to_string()),
            _ => true,
        }
    }

    /// 检查包名是否在过滤列表中
    pub fn is_in_filter_list(&self, package_name: &str) -> bool {
        self.filter_list.contains(&package_name.to_string())
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
        config.filter_list.push("com.allowed".to_string());

        config.filter_mode = 0;
        assert!(config.check_filter_mode("com.any"));

        config.filter_mode = 1;
        assert!(config.check_filter_mode("com.allowed"));
        assert!(!config.check_filter_mode("com.blocked"));

        config.filter_mode = 2;
        assert!(!config.check_filter_mode("com.allowed"));
        assert!(config.check_filter_mode("com.blocked"));
    }

    #[test]
    fn test_is_in_filter_list() {
        let mut config = RemoteFilterConfig::new();
        config.filter_list.push("com.whitelist".to_string());
        assert!(config.is_in_filter_list("com.whitelist"));
        assert!(!config.is_in_filter_list("com.other"));
    }
}
