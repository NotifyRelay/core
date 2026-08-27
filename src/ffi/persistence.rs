use std::os::raw::{c_char, c_void};

use super::common::{from_cstr, to_cstr, with_ctx};
use crate::device_registry::BATTERY_UNKNOWN;

/// 获取本机 UUID（库为准；库无记录则 Rust 生成 v4 UUID 并落库）
/// 读取前自动落盘（dirty 时写入 uuid/state/设备行），失败返回 NULL
#[no_mangle]
pub unsafe extern "C" fn nrc_get_local_uuid(ctx_ptr: *mut c_void) -> *mut c_char {
    with_ctx(ctx_ptr, |ctx| {
        ctx.ensure_persistence_loaded();
        // 平台端通过本接口确认身份来源，激活持久化（uuid 由 Rust 生成持有）
        ctx.persistence_activated = true;
        if !ctx.ensure_local_uuid() {
            return std::ptr::null_mut();
        }
        let _ = ctx.flush_persistence();
        match ctx.persistence.as_ref().and_then(|p| p.get_local_uuid()) {
            Some(u) if !u.is_empty() => to_cstr(&u),
            _ => std::ptr::null_mut(),
        }
    })
}

/// 更新设备显示名（改名；亦用于迁移期设备名称导入）
/// 直写库行 + 同步运行时注册表；非空参数校验
#[no_mangle]
pub unsafe extern "C" fn nrc_rename_device(
    ctx_ptr: *mut c_void,
    device_uuid: *const c_char,
    name: *const c_char,
) -> i32 {
    let uuid = from_cstr(device_uuid).to_string();
    let name = from_cstr(name).to_string();
    with_ctx(ctx_ptr, |ctx| {
        ctx.ensure_persistence_loaded();
        if uuid.is_empty() || name.is_empty() {
            return -1;
        }
        let now = crate::device_registry::now_sec();
        let entry = ctx
            .persisted_devices
            .entry(uuid.clone())
            .or_insert_with(|| crate::persistence::PersistedDevice {
                uuid: uuid.clone(),
                created_at: now,
                ..Default::default()
            });
        entry.display_name = name.clone();
        entry.updated_at = now;
        // 运行时名称同步（不影响 last_seen）
        ctx.registry
            .upsert_no_seen(&uuid, &name, "", 0, BATTERY_UNKNOWN, "");
        ctx.persist_device_row_now(&uuid);
        0
    })
}
