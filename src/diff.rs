use std::collections::HashMap;

/// 差异决策结果
#[derive(Debug, PartialEq)]
pub enum DiffDecision {
    /// 全量发送
    Full,
    /// 差异发送（增量）
    Delta(String),
    /// 不发送（无变化）
    Skip,
}

/// 超级岛差异计算
pub fn compute_superisland_diff(
    old_json: &str,
    new_json: &str,
) -> DiffDecision {
    if old_json.is_empty() {
        return DiffDecision::Full;
    }

    let old_val: serde_json::Value = match serde_json::from_str(old_json) {
        Ok(v) => v,
        Err(_) => return DiffDecision::Full,
    };
    let new_val: serde_json::Value = match serde_json::from_str(new_json) {
        Ok(v) => v,
        Err(_) => return DiffDecision::Full,
    };

    // 提取对象映射
    let old_map = match extract_superisland_map(&old_val) {
        Some(m) => m,
        None => return DiffDecision::Full,
    };
    let new_map = match extract_superisland_map(&new_val) {
        Some(m) => m,
        None => return DiffDecision::Full,
    };

    // 比较 featureIds
    let old_ids: Vec<&String> = old_map.keys().collect();
    let new_ids: Vec<&String> = new_map.keys().collect();

    // 如果新旧 featureId 列表完全相同，尝试计算差异
    if old_ids == new_ids {
        let mut changes = Vec::new();
        for id in &old_ids {
            let old_item = &old_map[id.as_str()];
            let new_item = &new_map[id.as_str()];
            if old_item != new_item {
                changes.push(new_item.clone());
            }
        }
        if changes.is_empty() {
            DiffDecision::Skip
        } else {
            // 构建差异负载
            let delta = serde_json::json!({
                "type": "delta",
                "changes": changes,
            });
            DiffDecision::Delta(delta.to_string())
        }
    } else {
        // featureId 列表不同，需要全量发送
        DiffDecision::Full
    }
}

/// 从超级岛负载中提取 featureId → 对象 的映射
fn extract_superisland_map(val: &serde_json::Value) -> Option<HashMap<String, serde_json::Value>> {
    let features = match val.get("features").and_then(|v| v.as_array()) {
        Some(arr) => arr,
        None => return Some(HashMap::new()),
    };

    let mut map = HashMap::new();
    for feature in features {
        let feature_id = match feature.get("featureId")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
        {
            Some(id) => id,
            None => continue,
        };
        map.insert(feature_id, feature.clone());
    }
    Some(map)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_full_when_empty_old() {
        assert_eq!(compute_superisland_diff("", "{}"), DiffDecision::Full);
    }

    #[test]
    fn test_skip_when_no_changes() {
        let state = r#"{"features":[{"featureId":"a","data":1}]}"#;
        assert_eq!(compute_superisland_diff(state, state), DiffDecision::Skip);
    }

    #[test]
    fn test_full_when_new_feature_added() {
        let old = r#"{"features":[{"featureId":"a","data":1}]}"#;
        let new = r#"{"features":[{"featureId":"a","data":1},{"featureId":"b","data":2}]}"#;
        assert_eq!(compute_superisland_diff(old, new), DiffDecision::Full);
    }

    #[test]
    fn test_delta_when_feature_data_changed() {
        let old = r#"{"features":[{"featureId":"a","data":1}]}"#;
        let new = r#"{"features":[{"featureId":"a","data":2}]}"#;
        match compute_superisland_diff(old, new) {
            DiffDecision::Delta(_) => {} // ok
            _ => panic!("expected delta"),
        }
    }
}
