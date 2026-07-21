use std::os::raw::c_char;
use std::os::raw::c_void;

use base64::Engine;

use crate::crypto::aes;
use crate::protocol::codec;

use super::common::{from_cstr, to_cstr, with_ctx};

/// 加密并构造 DATA 消息（平台端发送数据用）
#[no_mangle]
pub unsafe extern "C" fn nrc_encrypt_message(
    ctx_ptr: *mut c_void,
    header_prefix: *const c_char,
    local_uuid: *const c_char,
    local_pub_key: *const c_char,
    remote_uuid: *const c_char,
    plaintext: *const c_char,
) -> *mut c_char {
    let header = from_cstr(header_prefix);
    let uuid = from_cstr(local_uuid);
    let pub_key = from_cstr(local_pub_key);
    let remote = from_cstr(remote_uuid);
    let text = from_cstr(plaintext);
    with_ctx(ctx_ptr, |ctx| {
        let key_b64 = match ctx.crypto.device_keys.get(remote) {
            Some(k) => k.aes_key_b64.clone(),
            None => return std::ptr::null_mut(),
        };
        let key_bytes = base64::engine::general_purpose::STANDARD
            .decode(&key_b64)
            .ok();
        let key_arr: [u8; 32] = match key_bytes {
            Some(b) if b.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&b);
                arr
            }
            _ => return std::ptr::null_mut(),
        };
        match aes::encrypt(&key_arr, text.as_bytes()) {
            Ok(encrypted) => {
                let msg = codec::encode_data_message(header, uuid, pub_key, &encrypted);
                to_cstr(&msg)
            }
            Err(_) => std::ptr::null_mut(),
        }
    })
}
