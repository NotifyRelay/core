use std::os::raw::c_char;

use crate::diff::{self, DiffDecision};

use super::common::{from_cstr, to_cstr};

/// 计算超级岛差异
/// 返回 JSON: {"decision":"full"} 或 {"decision":"delta","payload":"..."} 或 {"decision":"skip"}
#[no_mangle]
pub unsafe extern "C" fn nrc_compute_superisland_diff(
    old_state: *const c_char,
    new_state: *const c_char,
) -> *mut c_char {
    let old = from_cstr(old_state);
    let new_s = from_cstr(new_state);

    let result = match diff::compute_superisland_diff(old, new_s) {
        DiffDecision::Full => r#"{"decision":"full"}"#.to_string(),
        DiffDecision::Delta(payload) => {
            let escaped = serde_json::json!({"decision":"delta","payload":payload});
            escaped.to_string()
        }
        DiffDecision::Skip => r#"{"decision":"skip"}"#.to_string(),
    };

    to_cstr(&result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_diff_ffi_full() {
        let result = unsafe {
            nrc_compute_superisland_diff(
                std::ffi::CString::new("").unwrap().as_ptr(),
                std::ffi::CString::new("{}").unwrap().as_ptr(),
            )
        };
        let s = unsafe { from_cstr(result) };
        assert!(s.contains(r#""full""#));
    }
}
