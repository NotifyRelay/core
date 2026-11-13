//! 无状态工具 C ABI 委托。

use std::os::raw::{c_char, c_void};

use super::common::{from_cstr, to_cstr, with_ctx_or};

/// # Safety
/// 字符串指针须为空或有效 C 字符串。
#[no_mangle]
pub unsafe extern "C" fn nrc_compute_feature_id(
    super_pkg: *const c_char,
    param_v2_raw: *const c_char,
    title: *const c_char,
    text: *const c_char,
    instance_id: *const c_char,
) -> *mut c_char {
    let pkg = unsafe { from_cstr(super_pkg) };
    let param = unsafe { from_cstr(param_v2_raw) };
    let title = unsafe { from_cstr(title) };
    let text = unsafe { from_cstr(text) };
    let iid = unsafe { from_cstr(instance_id) };
    to_cstr(&crate::utils::compute_feature_id(
        pkg, param, title, text, iid,
    ))
}

/// 统一去重接口。
///
/// action: 0=check_and_pend, 1=mark_sent, 2=clear_pending, 3=cleanup。
/// action=0 时返回 1=应发送, 0=重复；action=1/2/3 时返回 0=成功, -1=失败。
///
/// # Safety
/// `dedup_key` 须为空或有效 C 字符串。
#[no_mangle]
pub unsafe extern "C" fn nrc_dedup(
    ctx_ptr: *mut c_void,
    action: i32,
    dedup_key: *const c_char,
    arg1_ms: i64,
    arg2_ms: i64,
) -> i32 {
    if ctx_ptr.is_null() {
        return -1;
    }
    let key = unsafe { from_cstr(dedup_key) };
    with_ctx_or(ctx_ptr, -1, |guard| match action {
        0 => {
            if key.is_empty() {
                return 0;
            }
            i32::from(guard.dedup.check_and_pend(key, arg1_ms))
        }
        1 => {
            if !key.is_empty() {
                guard.dedup.mark_sent(key);
            }
            0
        }
        2 => {
            if !key.is_empty() {
                guard.dedup.clear_pending(key);
            }
            0
        }
        3 => {
            guard.dedup.cleanup(arg1_ms, arg2_ms);
            0
        }
        _ => -1,
    })
}

/// 入站内容去重（10s 窗口；键与 TTL 由 core 持有）。
///
/// 键为「应用名 + 标题 + 正文」。
/// action=0 纯查询：1=窗口内已见 / 0=未见（不写状态）；action=1 标记已见：0；
/// action=2 清除全部内容键：0；空上下文或 action 非法：-1。
///
/// # Safety
/// 字符串指针须为空或有效 C 字符串。
#[no_mangle]
pub unsafe extern "C" fn nrc_content_dedup(
    ctx_ptr: *mut c_void,
    action: i32,
    app_name: *const c_char,
    title: *const c_char,
    text: *const c_char,
) -> i32 {
    let key = crate::dedup::content_key(
        unsafe { from_cstr(app_name) },
        unsafe { from_cstr(title) },
        unsafe { from_cstr(text) },
    );
    with_ctx_or(ctx_ptr, -1, |guard| match action {
        0 => i32::from(
            guard
                .dedup
                .contains(&key, crate::dedup::CONTENT_DEDUP_TTL_MS),
        ),
        1 => {
            guard.dedup.maybe_cleanup();
            guard.dedup.mark_sent(&key);
            0
        }
        2 => {
            guard.dedup.clear_prefix(crate::dedup::CONTENT_KEY_PREFIX);
            0
        }
        _ => -1,
    })
}

/// # Safety
/// 字符串指针须为空或有效 C 字符串。
#[no_mangle]
pub unsafe extern "C" fn nrc_should_deduplicate(
    new_app_name: *const c_char,
    new_title: *const c_char,
    new_text: *const c_char,
    old_app_name: *const c_char,
    old_title: *const c_char,
    old_text: *const c_char,
) -> i32 {
    let na = unsafe { from_cstr(new_app_name) };
    let nt = unsafe { from_cstr(new_title) };
    let ntx = unsafe { from_cstr(new_text) };
    let oa = unsafe { from_cstr(old_app_name) };
    let ot = unsafe { from_cstr(old_title) };
    let otx = unsafe { from_cstr(old_text) };
    i32::from(crate::utils::should_deduplicate(na, nt, ntx, oa, ot, otx))
}

/// # Safety
/// `shared_secret_b64` 须为空或有效 C 字符串。
#[no_mangle]
pub unsafe extern "C" fn nrc_derive_ftp_credentials(
    shared_secret_b64: *const c_char,
) -> *mut c_char {
    let secret = unsafe { from_cstr(shared_secret_b64) };
    to_cstr(&crate::utils::derive_ftp_credentials(secret))
}

/// # Safety
/// `password` 须为空或有效 C 字符串。
#[no_mangle]
pub unsafe extern "C" fn nrc_derive_password_hash(password: *const c_char) -> *mut c_char {
    let pw = unsafe { from_cstr(password) };
    to_cstr(&crate::utils::derive_password_hash(pw))
}

#[no_mangle]
pub extern "C" fn nrc_generate_random_password() -> *mut c_char {
    to_cstr(&crate::utils::generate_random_password())
}

/// 获取本机局域网 IP 地址。
#[no_mangle]
pub extern "C" fn nrc_get_local_ip() -> *mut c_char {
    to_cstr(&crate::utils::get_local_ip())
}
