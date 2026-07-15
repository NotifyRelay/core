use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::os::raw::c_void;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Once;

use base64::Engine;

// ==================== Log bridge (platform-customizable) ====================

type LogCb = extern "C" fn(i32, *const c_char);

static LOG_CB: AtomicUsize = AtomicUsize::new(0);
static LOG_INIT: Once = Once::new();

struct PlatformLogBridge;

impl log::Log for PlatformLogBridge {
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }
    fn log(&self, record: &log::Record) {
        let val = LOG_CB.load(Ordering::Relaxed);
        if val == 0 {
            return;
        }
        let cb: LogCb = unsafe { std::mem::transmute(val) };
        if let Ok(c_msg) = CString::new(format!("{}", record.args())) {
            cb(record.level() as i32, c_msg.as_ptr());
        }
    }
    fn flush(&self) {}
}

static LOG_BRIDGE: PlatformLogBridge = PlatformLogBridge;

fn init_log_bridge() {
    LOG_INIT.call_once(|| {
        #[cfg(target_os = "android")]
        android_logger::init_once(
            android_logger::Config::default()
                .with_tag("NotifyRelayCore")
                .with_max_level(log::LevelFilter::Debug),
        );
        #[cfg(not(target_os = "android"))]
        {
            log::set_logger(&LOG_BRIDGE).ok();
            log::set_max_level(log::LevelFilter::Debug);
        }
    });
}

#[no_mangle]
pub extern "C" fn nrc_set_log_callback(cb: Option<LogCb>) {
    let val = match cb {
        Some(f) => f as usize,
        None => 0,
    };
    LOG_CB.store(val, Ordering::Release);
}

use crate::{
    crypto::{self, aes, ecdh, hkdf},
    protocol::{codec, header::ProtocolHeader},
    CoreContext, SafeContext,
};

fn to_cstr(s: &str) -> *mut c_char {
    CString::new(s).unwrap_or_default().into_raw()
}

unsafe fn from_cstr<'a>(ptr: *const c_char) -> &'a str {
    if ptr.is_null() {
        return "";
    }
    CStr::from_ptr(ptr).to_str().unwrap_or("")
}

fn with_ctx<F, R>(ctx_ptr: *mut c_void, f: F) -> R
where
    F: FnOnce(&mut CoreContext) -> R,
    R: Default,
{
    if ctx_ptr.is_null() {
        return R::default();
    }
    let ctx = unsafe { &mut *(ctx_ptr as *mut SafeContext) };
    match ctx.lock() {
        Ok(mut guard) => f(&mut guard),
        Err(_) => R::default(),
    }
}

// ==================== Lifecycle ====================

#[no_mangle]
pub extern "C" fn nrc_init() -> *mut c_void {
    init_log_bridge();
    let ctx = Box::new(std::sync::Mutex::new(CoreContext::new()));
    Box::into_raw(ctx) as *mut c_void
}

#[no_mangle]
pub extern "C" fn nrc_destroy(ctx_ptr: *mut c_void) {
    if !ctx_ptr.is_null() {
        let ctx = unsafe { Box::from_raw(ctx_ptr as *mut SafeContext) };
        drop(ctx);
    }
}

#[no_mangle]
pub extern "C" fn nrc_free_string(s: *mut c_char) {
    if !s.is_null() {
        unsafe {
            let _ = CString::from_raw(s);
        }
    }
}

// ==================== Long-term ECDH ====================

#[no_mangle]
pub extern "C" fn nrc_ecdh_generate_keypair(ctx_ptr: *mut c_void) -> i32 {
    with_ctx(ctx_ptr, |ctx| {
        let (secret, b64) = ecdh::generate_keypair();
        ctx.crypto.local_key = Some(secret);
        ctx.crypto.local_pub_key_b64 = Some(b64);
        0
    })
}

#[no_mangle]
pub extern "C" fn nrc_ecdh_get_public_key(ctx_ptr: *mut c_void) -> *mut c_char {
    with_ctx(ctx_ptr, |ctx| {
        ctx.crypto
            .local_pub_key_b64
            .as_deref()
            .map(to_cstr)
            .unwrap_or(std::ptr::null_mut())
    })
}

#[no_mangle]
pub extern "C" fn nrc_ecdh_has_keypair(ctx_ptr: *mut c_void) -> i32 {
    with_ctx(ctx_ptr, |ctx| {
        if ctx.crypto.local_key.is_some() { 1 } else { 0 }
    })
}

#[no_mangle]
pub extern "C" fn nrc_ecdh_derive_shared_secret(
    ctx_ptr: *mut c_void,
    peer_uuid: *const c_char,
    peer_pub_key_b64: *const c_char,
) -> i32 {
    let uuid = unsafe { from_cstr(peer_uuid).to_string() };
    let peer = unsafe { from_cstr(peer_pub_key_b64).to_string() };
    with_ctx(ctx_ptr, |ctx| {
        if let Some(ref priv_key) = ctx.crypto.local_key {
            match ecdh::compute_shared_secret(priv_key, &peer) {
                Ok(shared) => {
                    let aes_key = hkdf::derive_session_key(&shared);
                    let b64 = base64::engine::general_purpose::STANDARD.encode(aes_key);
                    ctx.crypto.device_keys.insert(
                        uuid,
                        crypto::DeviceKeyEntry {
                            remote_pub_key: peer.clone(),
                            aes_key_b64: b64,
                        },
                    );
                    0
                }
                Err(_) => -1,
            }
        } else {
            -1
        }
    })
}

// ==================== Ephemeral ECDH (pairing) ====================

#[no_mangle]
pub extern "C" fn nrc_ecdh_generate_ephemeral_keypair(ctx_ptr: *mut c_void) -> i32 {
    with_ctx(ctx_ptr, |ctx| {
        let (secret, b64) = ecdh::generate_keypair();
        ctx.ephemeral_key = Some(secret);
        ctx.ephemeral_pub_b64 = Some(b64);
        0
    })
}

#[no_mangle]
pub extern "C" fn nrc_ecdh_get_ephemeral_public_key(ctx_ptr: *mut c_void) -> *mut c_char {
    with_ctx(ctx_ptr, |ctx| {
        ctx.ephemeral_pub_b64
            .as_deref()
            .map(to_cstr)
            .unwrap_or(std::ptr::null_mut())
    })
}

#[no_mangle]
pub extern "C" fn nrc_ecdh_has_ephemeral_keypair(ctx_ptr: *mut c_void) -> i32 {
    with_ctx(ctx_ptr, |ctx| {
        if ctx.ephemeral_key.is_some() { 1 } else { 0 }
    })
}

#[no_mangle]
pub extern "C" fn nrc_ecdh_clear_ephemeral_keypair(ctx_ptr: *mut c_void) {
    with_ctx(ctx_ptr, |ctx| {
        ctx.ephemeral_key = None;
        ctx.ephemeral_pub_b64 = None;
        ctx.pairing_key = None;
    });
}

// ==================== Pairing code encryption chain ====================

#[no_mangle]
pub extern "C" fn nrc_ecdh_derive_pairing_key(
    ctx_ptr: *mut c_void,
    peer_eph_pub_b64: *const c_char,
) -> i32 {
    let peer = unsafe { from_cstr(peer_eph_pub_b64) };
    with_ctx(ctx_ptr, |ctx| {
        let eph_key = match ctx.ephemeral_key {
            Some(ref k) => k,
            None => return -1,
        };
        match ecdh::compute_shared_secret(eph_key, peer) {
            Ok(shared) => {
                let aes_key = hkdf::derive_pairing_key(&shared);
                ctx.pairing_key = Some(aes_key);
                0
            }
            Err(_) => -1,
        }
    })
}

#[no_mangle]
pub extern "C" fn nrc_ecdh_encrypt_pairing_code(
    ctx_ptr: *mut c_void,
    code: *const c_char,
) -> *mut c_char {
    let code_str = unsafe { from_cstr(code) };
    with_ctx(ctx_ptr, |ctx| {
        let key = match ctx.pairing_key {
            Some(k) => k,
            None => return std::ptr::null_mut(),
        };
        match aes::encrypt(&key, code_str.as_bytes()) {
            Ok(encrypted) => to_cstr(&encrypted),
            Err(_) => std::ptr::null_mut(),
        }
    })
}

#[no_mangle]
pub extern "C" fn nrc_ecdh_decrypt_pairing_code(
    ctx_ptr: *mut c_void,
    encrypted_b64: *const c_char,
) -> *mut c_char {
    let encrypted = unsafe { from_cstr(encrypted_b64) };
    with_ctx(ctx_ptr, |ctx| {
        let key = match ctx.pairing_key {
            Some(k) => k,
            None => return std::ptr::null_mut(),
        };
        match aes::decrypt(&key, encrypted) {
            Ok(plain) => {
                let s = String::from_utf8_lossy(&plain).to_string();
                to_cstr(&s)
            }
            Err(_) => std::ptr::null_mut(),
        }
    })
}

// ==================== Long-term key derivation alias ====================

#[no_mangle]
pub extern "C" fn nrc_ecdh_derive_long_term_key(
    ctx_ptr: *mut c_void,
    peer_uuid: *const c_char,
    peer_lt_pub_b64: *const c_char,
) -> i32 {
    nrc_ecdh_derive_shared_secret(ctx_ptr, peer_uuid, peer_lt_pub_b64)
}

// ==================== Key management ====================

#[no_mangle]
pub extern "C" fn nrc_migrate_shared_secret(
    ctx_ptr: *mut c_void,
    device_uuid: *const c_char,
    aes_key: *const u8,
    len: u32,
) -> i32 {
    if aes_key.is_null() || len == 0 { return -1; }
    let uuid = unsafe { from_cstr(device_uuid) };
    let key_bytes = unsafe { std::slice::from_raw_parts(aes_key, len as usize) };
    if key_bytes.len() != 32 { return -1; }
    with_ctx(ctx_ptr, |ctx| {
        let b64 = base64::engine::general_purpose::STANDARD.encode(key_bytes);
        ctx.crypto.device_keys.insert(
            uuid.to_string(),
            crypto::DeviceKeyEntry { remote_pub_key: String::new(), aes_key_b64: b64 },
        );
        0
    })
}

#[no_mangle]
pub extern "C" fn nrc_remove_device(ctx_ptr: *mut c_void, device_uuid: *const c_char) -> i32 {
    let uuid = unsafe { from_cstr(device_uuid) };
    with_ctx(ctx_ptr, |ctx| { ctx.crypto.device_keys.remove(uuid); 0 })
}

#[no_mangle]
pub extern "C" fn nrc_export_device_key(
    ctx_ptr: *mut c_void, device_uuid: *const c_char,
) -> *mut c_char {
    let uuid = unsafe { from_cstr(device_uuid) };
    with_ctx(ctx_ptr, |ctx| {
        ctx.crypto.device_keys.get(uuid)
            .map(|k| to_cstr(&k.aes_key_b64))
            .unwrap_or(std::ptr::null_mut())
    })
}

#[no_mangle]
pub extern "C" fn nrc_export_local_keypair(ctx_ptr: *mut c_void) -> *mut c_char {
    with_ctx(ctx_ptr, |ctx| {
        let local_priv_pem = ctx.crypto.local_key.as_ref()
            .and_then(|k| ecdh::secret_to_pem(k).ok());
        let json = serde_json::json!({
            "private_key_pem": local_priv_pem,
            "public_key_b64": ctx.crypto.local_pub_key_b64,
        });
        to_cstr(&json.to_string())
    })
}

// ==================== State export/import ====================

#[no_mangle]
pub extern "C" fn nrc_export_state(ctx_ptr: *mut c_void) -> *mut c_char {
    with_ctx(ctx_ptr, |ctx| {
        let local_priv_pem = ctx.crypto.local_key.as_ref()
            .and_then(|k| ecdh::secret_to_pem(k).ok());
        let data = crypto::KeyStoreData {
            local_private_key_pem: local_priv_pem,
            local_public_key_b64: ctx.crypto.local_pub_key_b64.clone(),
            devices: ctx.crypto.device_keys.clone(),
        };
        match serde_json::to_string(&data) {
            Ok(json) => to_cstr(&json),
            Err(_) => std::ptr::null_mut(),
        }
    })
}

#[no_mangle]
pub extern "C" fn nrc_import_state(ctx_ptr: *mut c_void, json: *const c_char) -> i32 {
    let json_str = unsafe { from_cstr(json) };
    with_ctx(ctx_ptr, |ctx| {
        match serde_json::from_str::<crypto::KeyStoreData>(json_str) {
            Ok(data) => {
                if let Some(ref pem) = data.local_private_key_pem {
                    ctx.crypto.local_key = ecdh::secret_from_pem(pem).ok();
                }
                ctx.crypto.local_pub_key_b64 = data.local_public_key_b64;
                ctx.crypto.device_keys = data.devices;
                0
            }
            Err(e) => { log::error!("导入状态解析失败: {}", e); -1 }
        }
    })
}

// ==================== Local state encryption (device-uuid-keyed) ====================

#[no_mangle]
pub extern "C" fn nrc_encrypt_local_state(
    ctx_ptr: *mut c_void,
    plaintext: *const c_char,
    device_uuid: *const c_char,
) -> *mut c_char {
    let text = unsafe { from_cstr(plaintext) };
    let uuid = unsafe { from_cstr(device_uuid) };
    with_ctx(ctx_ptr, |_ctx| {
        let key = hkdf::derive_local_state_key(uuid);
        match aes::encrypt(&key, text.as_bytes()) {
            Ok(enc) => to_cstr(&enc),
            Err(_) => std::ptr::null_mut(),
        }
    })
}

#[no_mangle]
pub extern "C" fn nrc_decrypt_local_state(
    ctx_ptr: *mut c_void,
    encrypted_b64: *const c_char,
    device_uuid: *const c_char,
) -> *mut c_char {
    let enc = unsafe { from_cstr(encrypted_b64) };
    let uuid = unsafe { from_cstr(device_uuid) };
    with_ctx(ctx_ptr, |_ctx| {
        let key = hkdf::derive_local_state_key(uuid);
        match aes::decrypt(&key, enc) {
            Ok(plain) => {
                let s = String::from_utf8_lossy(&plain).to_string();
                to_cstr(&s)
            }
            Err(_) => std::ptr::null_mut(),
        }
    })
}

// ==================== Message encrypt/decrypt (original) ====================

#[no_mangle]
pub extern "C" fn nrc_encrypt_message(
    ctx_ptr: *mut c_void, header_prefix: *const c_char,
    local_uuid: *const c_char, local_pub_key: *const c_char,
    remote_uuid: *const c_char, plaintext: *const c_char,
) -> *mut c_char {
    let header = unsafe { from_cstr(header_prefix) };
    let uuid = unsafe { from_cstr(local_uuid) };
    let pub_key = unsafe { from_cstr(local_pub_key) };
    let remote = unsafe { from_cstr(remote_uuid) };
    let text = unsafe { from_cstr(plaintext) };
    with_ctx(ctx_ptr, |ctx| {
        let key_b64 = match ctx.crypto.device_keys.get(remote) {
            Some(k) => k.aes_key_b64.clone(), None => return std::ptr::null_mut(),
        };
        let key_bytes = base64::engine::general_purpose::STANDARD.decode(&key_b64).ok();
        let key_arr: [u8; 32] = match key_bytes {
            Some(b) if b.len() == 32 => { let mut arr = [0u8; 32]; arr.copy_from_slice(&b); arr }
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

#[no_mangle]
pub extern "C" fn nrc_decrypt_message(
    ctx_ptr: *mut c_void, encrypted_line: *const c_char,
) -> *mut c_char {
    let line = unsafe { from_cstr(encrypted_line) };
    with_ctx(ctx_ptr, |ctx| {
        let fields = match codec::decode_data_message(line) {
            Some(f) => f, None => return std::ptr::null_mut(),
        };
        let key_b64 = match ctx.crypto.device_keys.get(fields.local_uuid) {
            Some(k) => k.aes_key_b64.clone(), None => return std::ptr::null_mut(),
        };
        let key_bytes = base64::engine::general_purpose::STANDARD.decode(&key_b64).ok();
        let key_arr: [u8; 32] = match key_bytes {
            Some(b) if b.len() == 32 => { let mut arr = [0u8; 32]; arr.copy_from_slice(&b); arr }
            _ => return std::ptr::null_mut(),
        };
        match aes::decrypt(&key_arr, fields.encrypted_payload) {
            Ok(plain) => { let s = String::from_utf8_lossy(&plain).to_string(); to_cstr(&s) }
            Err(_) => std::ptr::null_mut(),
        }
    })
}

// ==================== nrc_decode_line (backward compat) ====================

#[no_mangle]
pub extern "C" fn nrc_decode_line(ctx_ptr: *mut c_void, line: *const c_char) -> *mut c_char {
    let line_str = unsafe { from_cstr(line) };
    if line_str.is_empty() { return std::ptr::null_mut(); }
    let header = ProtocolHeader::parse(line_str);
    match header {
        ProtocolHeader::Data(hdr) => with_ctx(ctx_ptr, |ctx| {
            let fields = match codec::decode_data_message(line_str) {
                Some(f) => f, None => return std::ptr::null_mut(),
            };
            let key_b64 = match ctx.crypto.device_keys.get(fields.local_uuid) {
                Some(k) => k.aes_key_b64.clone(), None => return std::ptr::null_mut(),
            };
            let key_bytes = base64::engine::general_purpose::STANDARD.decode(&key_b64).ok();
            let key_arr: [u8; 32] = match key_bytes {
                Some(b) if b.len() == 32 => { let mut arr = [0u8; 32]; arr.copy_from_slice(&b); arr }
                _ => return std::ptr::null_mut(),
            };
            match aes::decrypt(&key_arr, fields.encrypted_payload) {
                Ok(plain) => {
                    let plaintext = String::from_utf8_lossy(&plain).to_string();
                    let json = serde_json::json!({
                        "header": hdr, "type": "data",
                        "local_uuid": fields.local_uuid, "plaintext": plaintext,
                    });
                    to_cstr(&json.to_string())
                }
                Err(_) => std::ptr::null_mut(),
            }
        }),
        ProtocolHeader::Handshake => match codec::decode_handshake(line_str) {
            Some(f) => to_cstr(&serde_json::json!({
                "header": "HANDSHAKE", "uuid": f.uuid, "pub_key": f.pub_key,
                "ip": f.ip, "battery": f.battery, "device_type": f.device_type,
            }).to_string()),
            None => std::ptr::null_mut(),
        },
        ProtocolHeader::PairingInit => match codec::decode_pairing_init(line_str) {
            Some(f) => to_cstr(&serde_json::json!({
                "header": "PAIRING_INIT", "uuid": f.uuid, "tmp_pub_key": f.tmp_pub_key,
                "ip": f.ip, "battery": f.battery, "device_type": f.device_type,
            }).to_string()),
            None => std::ptr::null_mut(),
        },
        ProtocolHeader::PairingResp => match codec::decode_pairing_resp(line_str) {
            Some(f) => to_cstr(&serde_json::json!({
                "header": "PAIRING_RESP", "uuid": f.uuid, "tmp_pub": f.tmp_pub,
                "lt_pub": f.lt_pub, "encrypted_code": f.encrypted_code,
                "ip": f.ip, "battery": f.battery, "device_type": f.device_type,
            }).to_string()),
            None => std::ptr::null_mut(),
        },
        ProtocolHeader::Accept => match codec::decode_accept(line_str) {
            Some(f) => to_cstr(&serde_json::json!({
                "header": "ACCEPT", "uuid": f.uuid, "lt_pub_key": f.lt_pub_key,
                "ip": f.ip, "battery": f.battery, "device_type": f.device_type,
            }).to_string()),
            None => std::ptr::null_mut(),
        },
        ProtocolHeader::HeartbeatTcp => match codec::decode_heartbeat_tcp(line_str) {
            Some(f) => to_cstr(&serde_json::json!({
                "header": "HEARTBEAT_TCP", "uuid": f.uuid, "name_b64": f.name,
                "port": f.port, "battery": f.battery, "device_type": f.device_type,
            }).to_string()),
            None => std::ptr::null_mut(),
        },
        _ => std::ptr::null_mut(),
    }
}

// ==================== Unified send functions (replace formatXxx) ====================

fn encode_name_b64(name: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(name)
}

fn do_send(ctx: &CoreContext, line: &str) {
    if let Some(cb) = ctx.router.on_send {
        if let Ok(c_line) = CString::new(line) {
            cb(c_line.as_ptr(), ctx.router.user_data);
        }
    }
}

fn do_send_udp(ctx: &CoreContext, line: &str) {
    if let Some(cb) = ctx.router.on_send_udp {
        if let Ok(c_line) = CString::new(line) {
            cb(c_line.as_ptr(), ctx.router.user_data);
        }
    }
}

#[no_mangle]
pub extern "C" fn nrc_send_handshake(ctx_ptr: *mut c_void, uuid: *const c_char,
    pub_key: *const c_char, ip: *const c_char, battery: i32,
    device_type: *const c_char) {
    let u = unsafe { from_cstr(uuid).to_string() };
    let p = unsafe { from_cstr(pub_key).to_string() };
    let i = unsafe { from_cstr(ip).to_string() };
    let d = unsafe { from_cstr(device_type).to_string() };
    with_ctx(ctx_ptr, |ctx| {
        do_send(ctx, &codec::encode_handshake(&u, &p, &i, battery, &d));
    });
}

#[no_mangle]
pub extern "C" fn nrc_send_pairing_init(ctx_ptr: *mut c_void, uuid: *const c_char,
    ip: *const c_char, battery: i32, device_type: *const c_char) {
    let u = unsafe { from_cstr(uuid).to_string() };
    let i = unsafe { from_cstr(ip).to_string() };
    let d = unsafe { from_cstr(device_type).to_string() };
    with_ctx(ctx_ptr, |ctx| {
        let (secret, b64) = ecdh::generate_keypair();
        ctx.ephemeral_key = Some(secret);
        ctx.ephemeral_pub_b64 = Some(b64.clone());
        do_send(ctx, &codec::encode_pairing_init(&u, &b64, &i, battery, &d));
    });
}

#[no_mangle]
pub extern "C" fn nrc_send_pairing_resp(ctx_ptr: *mut c_void, uuid: *const c_char,
    lt_pub: *const c_char, pairing_code: *const c_char, ip: *const c_char,
    battery: i32, device_type: *const c_char) {
    let u = unsafe { from_cstr(uuid).to_string() };
    let l = unsafe { from_cstr(lt_pub).to_string() };
    let code = unsafe { from_cstr(pairing_code).to_string() };
    let i = unsafe { from_cstr(ip).to_string() };
    let d = unsafe { from_cstr(device_type).to_string() };
    with_ctx(ctx_ptr, |ctx| {
        if ctx.ephemeral_key.is_none() {
            let (secret, b64) = ecdh::generate_keypair();
            ctx.ephemeral_key = Some(secret);
            ctx.ephemeral_pub_b64 = Some(b64);
        }
        let tmp_pub = ctx.ephemeral_pub_b64.clone().unwrap_or_default();
        if let Some(ref eph_key) = ctx.ephemeral_key.clone() {
            if let Some(ref peer_tmp) = ctx.pairing_ctx.as_ref().map(|c| c.peer_tmp_pub.clone()) {
                if let Ok(shared) = ecdh::compute_shared_secret(eph_key, &peer_tmp) {
                    let aes_key = hkdf::derive_pairing_key(&shared);
                    ctx.pairing_key = Some(aes_key);
                }
            }
        }
        let encrypted = ctx.pairing_key.and_then(|key| {
            aes::encrypt(&key, code.as_bytes()).ok()
        }).unwrap_or_default();
        do_send(ctx, &codec::encode_pairing_resp(&u, &tmp_pub, &l, &encrypted, &i, battery, &d));
    });
}

#[no_mangle]
pub extern "C" fn nrc_send_accept(ctx_ptr: *mut c_void, uuid: *const c_char,
    lt_pub_key: *const c_char, ip: *const c_char, battery: i32,
    device_type: *const c_char) {
    let u = unsafe { from_cstr(uuid).to_string() };
    let l = unsafe { from_cstr(lt_pub_key).to_string() };
    let i = unsafe { from_cstr(ip).to_string() };
    let d = unsafe { from_cstr(device_type).to_string() };
    with_ctx(ctx_ptr, |ctx| {
        do_send(ctx, &codec::encode_accept(&u, &l, &i, battery, &d));
    });
}

#[no_mangle]
pub extern "C" fn nrc_send_reject(ctx_ptr: *mut c_void, uuid: *const c_char) {
    let u = unsafe { from_cstr(uuid).to_string() };
    with_ctx(ctx_ptr, |ctx| {
        do_send(ctx, &codec::encode_reject(&u));
    });
}

#[no_mangle]
pub extern "C" fn nrc_send_heartbeat_tcp(ctx_ptr: *mut c_void, uuid: *const c_char,
    name: *const c_char, port: u16, battery: i32, device_type: *const c_char) {
    let u = unsafe { from_cstr(uuid).to_string() };
    let n_b64 = encode_name_b64(unsafe { from_cstr(name) });
    let d = unsafe { from_cstr(device_type).to_string() };
    with_ctx(ctx_ptr, |ctx| {
        do_send(ctx, &codec::encode_heartbeat_tcp(&u, &n_b64, port, battery, &d));
    });
}

#[no_mangle]
pub extern "C" fn nrc_send_heartbeat_udp(ctx_ptr: *mut c_void, uuid: *const c_char,
    name: *const c_char, port: u16, battery: i32, device_type: *const c_char) {
    let u = unsafe { from_cstr(uuid).to_string() };
    let n_b64 = encode_name_b64(unsafe { from_cstr(name) });
    let d = unsafe { from_cstr(device_type).to_string() };
    with_ctx(ctx_ptr, |ctx| {
        do_send_udp(ctx, &codec::encode_udp_broadcast(&u, &n_b64, port, battery, &d));
    });
}

#[no_mangle]
pub extern "C" fn nrc_send_discovery(ctx_ptr: *mut c_void, uuid: *const c_char,
    name: *const c_char, port: u16, battery: i32, device_type: *const c_char) {
    let u = unsafe { from_cstr(uuid).to_string() };
    let n_b64 = encode_name_b64(unsafe { from_cstr(name) });
    let d = unsafe { from_cstr(device_type).to_string() };
    with_ctx(ctx_ptr, |ctx| {
        do_send_udp(ctx, &codec::encode_udp_broadcast(&u, &n_b64, port, battery, &d));
    });
}

#[no_mangle]
pub extern "C" fn nrc_send_data_message(ctx_ptr: *mut c_void, header: *const c_char,
    local_uuid: *const c_char, local_pub_key: *const c_char,
    remote_uuid: *const c_char, plaintext: *const c_char) {
    let hdr = unsafe { from_cstr(header).to_string() };
    let uuid = unsafe { from_cstr(local_uuid).to_string() };
    let pub_key = unsafe { from_cstr(local_pub_key).to_string() };
    let remote = unsafe { from_cstr(remote_uuid).to_string() };
    let text = unsafe { from_cstr(plaintext).to_string() };
    with_ctx(ctx_ptr, |ctx| {
        let key_b64 = match ctx.crypto.device_keys.get(&remote) {
            Some(k) => k.aes_key_b64.clone(), None => return,
        };
        let key_bytes = match base64::engine::general_purpose::STANDARD.decode(&key_b64) {
            Ok(b) if b.len() == 32 => b, _ => return,
        };
        let mut key_arr = [0u8; 32]; key_arr.copy_from_slice(&key_bytes);
        if let Ok(encrypted) = aes::encrypt(&key_arr, text.as_bytes()) {
            let msg = codec::encode_data_message(&hdr, &uuid, &pub_key, &encrypted);
            do_send(ctx, &msg);
        }
    });
}

// ==================== Unified UDP broadcast processing ====================

#[no_mangle]
pub extern "C" fn nrc_process_udp_broadcast(ctx_ptr: *mut c_void, line: *const c_char) -> i32 {
    if ctx_ptr.is_null() || line.is_null() { return -1; }
    let line_str = unsafe { from_cstr(line) };
    if line_str.is_empty() { return -1; }
    match crate::heartbeat::parse_udp_heartbeat(line_str) {
        Some((uuid, name_b64, port, battery, device_type)) => {
            let (cb, ud) = with_ctx(ctx_ptr, |ctx| (ctx.router.on_heartbeat_udp, ctx.router.user_data));
            if let Some(cb_fn) = cb {
                let uuid_c = CString::new(uuid).unwrap_or_default();
                let name_c = CString::new(name_b64).unwrap_or_default();
                let dt_c = CString::new(device_type).unwrap_or_default();
                cb_fn(uuid_c.as_ptr(), name_c.as_ptr(), port, battery, dt_c.as_ptr(), ud);
            }
            0
        }
        None => -1,
    }
}

// ==================== User data ====================

#[no_mangle]
pub extern "C" fn nrc_set_user_data(ctx_ptr: *mut c_void, user_data: *mut c_void) {
    with_ctx(ctx_ptr, |ctx| { ctx.router.user_data = user_data; });
}

// ==================== Callback setters (non-data) ====================

macro_rules! make_cb_setter {
    ($name:ident, $cb_ty:ty, $field:ident) => {
        #[no_mangle]
        pub extern "C" fn $name(ctx_ptr: *mut c_void, cb: $cb_ty) {
            with_ctx(ctx_ptr, |ctx| { ctx.router.$field = cb; });
        }
    };
}

make_cb_setter!(nrc_set_on_handshake_cb, crate::router::OnHandshakeCb, on_handshake);
make_cb_setter!(nrc_set_on_pairing_init_cb, crate::router::OnPairingInitCb, on_pairing_init);
make_cb_setter!(nrc_set_on_pairing_resp_cb, crate::router::OnPairingRespCb, on_pairing_resp);
make_cb_setter!(nrc_set_on_accept_cb, crate::router::OnAcceptCb, on_accept);
make_cb_setter!(nrc_set_on_reject_cb, crate::router::OnRejectCb, on_reject);
make_cb_setter!(nrc_set_on_heartbeat_tcp_cb, crate::router::OnHeartbeatTcpCb, on_heartbeat_tcp);

make_cb_setter!(nrc_set_on_notification_cb, crate::router::OnDataCb, on_notification);
make_cb_setter!(nrc_set_on_media_play_cb, crate::router::OnDataCb, on_media_play);
make_cb_setter!(nrc_set_on_icon_request_cb, crate::router::OnDataCb, on_icon_request);
make_cb_setter!(nrc_set_on_icon_response_cb, crate::router::OnDataCb, on_icon_response);
make_cb_setter!(nrc_set_on_app_list_request_cb, crate::router::OnDataCb, on_app_list_request);
make_cb_setter!(nrc_set_on_app_list_response_cb, crate::router::OnDataCb, on_app_list_response);
make_cb_setter!(nrc_set_on_media_control_cb, crate::router::OnDataCb, on_media_control);
make_cb_setter!(nrc_set_on_ftp_cb, crate::router::OnDataCb, on_ftp);
make_cb_setter!(nrc_set_on_clipboard_cb, crate::router::OnDataCb, on_clipboard);
make_cb_setter!(nrc_set_on_status_cb, crate::router::OnDataCb, on_status);
make_cb_setter!(nrc_set_on_app_launch_cb, crate::router::OnDataCb, on_app_launch);
make_cb_setter!(nrc_set_on_superisland_cb, crate::router::OnDataCb, on_superisland);
make_cb_setter!(nrc_set_on_unknown_data_cb, crate::router::OnDataCb, on_unknown_data);

make_cb_setter!(nrc_set_on_send_cb, crate::router::OnSendCb, on_send);
make_cb_setter!(nrc_set_on_send_udp_cb, crate::router::OnSendCb, on_send_udp);
make_cb_setter!(nrc_set_on_heartbeat_udp_cb, crate::router::OnHeartbeatUdpCb, on_heartbeat_udp);

// ==================== nrc_process_line (unified entry) ====================

fn dispatch_data(cb: crate::router::OnDataCb, local_uuid: &str, plaintext: &str, ud: *mut c_void) {
    if let Some(cb) = cb {
        log::debug!("分发数据回调: uuid={}, 长度={}", local_uuid, plaintext.len());
        let uuid_c = CString::new(local_uuid).unwrap_or_default();
        let text_c = CString::new(plaintext).unwrap_or_default();
        cb(uuid_c.as_ptr(), text_c.as_ptr(), ud);
    } else {
        log::warn!("数据回调未注册: uuid={}", local_uuid);
    }
}

#[no_mangle]
pub extern "C" fn nrc_process_line(ctx_ptr: *mut c_void, line: *const c_char) -> i32 {
    if ctx_ptr.is_null() || line.is_null() {
        log::error!("处理消息: 空指针");
        return -1;
    }
    let line_str = unsafe { from_cstr(line) };
    if line_str.is_empty() {
        log::error!("处理消息: 空行");
        return -1;
    }
    let header = ProtocolHeader::parse(line_str);
    log::debug!("处理消息: 类型={:?}", header);
    let ctx = unsafe { &mut *(ctx_ptr as *mut SafeContext) };
    match header {
        ProtocolHeader::Handshake => {
            if let Some(f) = codec::decode_handshake(line_str) {
                let (cb, ud, priv_key) = {
                    let guard = match ctx.lock() { Ok(g) => g, Err(_) => return -1 };
                    (guard.router.on_handshake, guard.router.user_data, guard.crypto.local_key.clone())
                };
                let uuid_str = f.uuid.to_string();
                let peer_pub_str = f.pub_key.to_string();
                if let Some(ref key) = priv_key {
                    if let Ok(shared) = ecdh::compute_shared_secret(key, &peer_pub_str) {
                        let aes_key = hkdf::derive_session_key(&shared);
                        let b64 = base64::engine::general_purpose::STANDARD.encode(aes_key);
                        if let Ok(mut guard) = ctx.lock() {
                            guard.crypto.device_keys.insert(
                                uuid_str.clone(),
                                crate::crypto::DeviceKeyEntry { remote_pub_key: peer_pub_str.clone(), aes_key_b64: b64 },
                            );
                        }
                        log::info!("处理消息: HANDSHAKE 自动派生密钥 uuid={}", uuid_str);
                    }
                }
                if let Some(cb_fn) = cb {
                    let uuid_c = CString::new(f.uuid).unwrap_or_default();
                    let pk = CString::new(f.pub_key).unwrap_or_default();
                    let ip = CString::new(f.ip).unwrap_or_default();
                    let dt = CString::new(f.device_type).unwrap_or_default();
                    log::debug!("处理消息: 分发 HANDSHAKE uuid={}", f.uuid);
                    cb_fn(uuid_c.as_ptr(), pk.as_ptr(), ip.as_ptr(), f.battery, dt.as_ptr(), ud);
                } else {
                    log::warn!("处理消息: HANDSHAKE 回调未注册");
                }
                 0
            } else {
                log::error!("处理消息: HANDSHAKE 解析失败");
                -1
            }
        }
        ProtocolHeader::PairingInit => {
            if let Some(f) = codec::decode_pairing_init(line_str) {
                let mut guard = match ctx.lock() { Ok(g) => g, Err(_) => return -1 };
                guard.pairing_ctx = Some(crate::PairingContext {
                    peer_tmp_pub: f.tmp_pub_key.to_string(),
                    peer_lt_pub: None,
                    decrypted_code: None,
                });
                let cb = guard.router.on_pairing_init; let ud = guard.router.user_data;
                drop(guard);
                if let Some(cb) = cb {
                    let uuid = CString::new(f.uuid).unwrap_or_default();
                    let tmp = CString::new(f.tmp_pub_key).unwrap_or_default();
                    let ip = CString::new(f.ip).unwrap_or_default();
                    let dt = CString::new(f.device_type).unwrap_or_default();
                    log::debug!("处理消息: 分发 PAIRING_INIT uuid={}", f.uuid);
                    cb(uuid.as_ptr(), tmp.as_ptr(), ip.as_ptr(), f.battery, dt.as_ptr(), ud);
                } else {
                    log::warn!("处理消息: PAIRING_INIT 回调未注册");
                }
                 0
            } else {
                log::error!("处理消息: PAIRING_INIT 解析失败");
                -1
            }
        }
        ProtocolHeader::PairingResp => {
            if let Some(f) = codec::decode_pairing_resp(line_str) {
                let (eph_key, cb, ud) = {
                    let guard = match ctx.lock() { Ok(g) => g, Err(_) => return -1 };
                    (guard.ephemeral_key.clone(), guard.router.on_pairing_resp, guard.router.user_data)
                };
                let peer_tmp = f.tmp_pub.to_string();
                let peer_lt = f.lt_pub.to_string();
                let enc_code = f.encrypted_code.to_string();
                if let Some(ref ek) = eph_key {
                    if let Ok(shared) = ecdh::compute_shared_secret(ek, &peer_tmp) {
                        let aes_key = hkdf::derive_pairing_key(&shared);
                        let decoded = aes::decrypt(&aes_key, &enc_code).ok()
                            .map(|p| String::from_utf8_lossy(&p).to_string());
                        if let Ok(mut guard) = ctx.lock() {
                            guard.pairing_key = Some(aes_key);
                            guard.pairing_ctx = Some(crate::PairingContext {
                                peer_tmp_pub: peer_tmp.clone(),
                                peer_lt_pub: Some(peer_lt.clone()),
                                decrypted_code: decoded.clone(),
                            });
                        }
                    }
                }
                if let Some(cb_fn) = cb {
                    let uuid_c = CString::new(f.uuid).unwrap_or_default();
                    let tmp = CString::new(f.tmp_pub).unwrap_or_default();
                    let lt = CString::new(f.lt_pub).unwrap_or_default();
                    let enc = CString::new(f.encrypted_code).unwrap_or_default();
                    let ip = CString::new(f.ip).unwrap_or_default();
                    let dt = CString::new(f.device_type).unwrap_or_default();
                    log::debug!("处理消息: 分发 PAIRING_RESP uuid={}", f.uuid);
                    cb_fn(uuid_c.as_ptr(), tmp.as_ptr(), lt.as_ptr(), enc.as_ptr(), ip.as_ptr(), f.battery, dt.as_ptr(), ud);
                } else {
                    log::warn!("处理消息: PAIRING_RESP 回调未注册");
                }
                 0
            } else {
                log::error!("处理消息: PAIRING_RESP 解析失败");
                -1
            }
        }
        ProtocolHeader::Accept => {
            if let Some(f) = codec::decode_accept(line_str) {
                let guard = match ctx.lock() { Ok(g) => g, Err(_) => return -1 };
                let cb = guard.router.on_accept; let ud = guard.router.user_data;
                drop(guard);
                if let Some(cb) = cb {
                    let uuid = CString::new(f.uuid).unwrap_or_default();
                    let lt = CString::new(f.lt_pub_key).unwrap_or_default();
                    let ip = CString::new(f.ip).unwrap_or_default();
                    let dt = CString::new(f.device_type).unwrap_or_default();
                    log::debug!("处理消息: 分发 ACCEPT uuid={}", f.uuid);
                    cb(uuid.as_ptr(), lt.as_ptr(), ip.as_ptr(), f.battery, dt.as_ptr(), ud);
                } else {
                    log::warn!("处理消息: ACCEPT 回调未注册");
                }
                 0
            } else {
                log::error!("处理消息: ACCEPT 解析失败");
                -1
            }
        }
        ProtocolHeader::Reject => {
            if let Some(payload) = line_str.strip_prefix("REJECT:") {
                let guard = match ctx.lock() { Ok(g) => g, Err(_) => return -1 };
                let cb = guard.router.on_reject; let ud = guard.router.user_data;
                drop(guard);
                if let Some(cb) = cb {
                    log::debug!("处理消息: 分发 REJECT uuid={}", payload);
                    let uuid_c = CString::new(payload).unwrap_or_default();
                    cb(uuid_c.as_ptr(), ud);
                } else {
                    log::warn!("处理消息: REJECT 回调未注册");
                }
                 0
            } else {
                log::error!("处理消息: REJECT 解析失败");
                -1
            }
        }
        ProtocolHeader::HeartbeatTcp => {
            if let Some(f) = codec::decode_heartbeat_tcp(line_str) {
                let guard = match ctx.lock() { Ok(g) => g, Err(_) => return -1 };
                let cb = guard.router.on_heartbeat_tcp; let ud = guard.router.user_data;
                drop(guard);
                if let Some(cb) = cb {
                    let uuid = CString::new(f.uuid).unwrap_or_default();
                    let name = CString::new(f.name).unwrap_or_default();
                    let dt = CString::new(f.device_type).unwrap_or_default();
                    let ip = CString::new("").unwrap_or_default();
                    log::debug!("处理消息: 分发 HEARTBEAT_TCP uuid={}", f.uuid);
                    cb(uuid.as_ptr(), name.as_ptr(), f.port, f.battery, dt.as_ptr(), ip.as_ptr(), ud);
                } else {
                    log::warn!("处理消息: HEARTBEAT_TCP 回调未注册");
                }
                 0
            } else {
                log::error!("处理消息: HEARTBEAT_TCP 解析失败");
                -1
            }
        }
        ProtocolHeader::Data(hdr) => {
            log::debug!("处理消息: DATA 消息 header={}", hdr);
            let fields = match codec::decode_data_message(line_str) {
                Some(f) => f, None => {
                    log::error!("处理消息: DATA 消息解析失败");
                    return -1;
                }
            };
            let guard = match ctx.lock() {
                Ok(g) => g, Err(_) => {
                    log::error!("处理消息: DATA 消息加锁失败");
                    return -1;
                }
            };
            let key_b64 = guard.crypto.device_keys.get(fields.local_uuid)
                .map(|k| k.aes_key_b64.clone());
            let (cb_notif, cb_media, cb_icon_req, cb_icon_resp,
                 cb_app_req, cb_app_resp, cb_ctrl, cb_ftp,
                 cb_clip, cb_status, cb_launch, cb_super, cb_unk, ud) = {
                let r = &guard.router;
                (r.on_notification, r.on_media_play, r.on_icon_request, r.on_icon_response,
                 r.on_app_list_request, r.on_app_list_response, r.on_media_control, r.on_ftp,
                 r.on_clipboard, r.on_status, r.on_app_launch, r.on_superisland, r.on_unknown_data,
                 r.user_data)
            };
            drop(guard);
            let key_b64 = match key_b64 {
                Some(k) => k, None => {
                    log::warn!("处理消息: 未找到密钥 uuid={}, header={}", fields.local_uuid, hdr);
                    return -1;
                }
            };
            let key_bytes = match base64::engine::general_purpose::STANDARD.decode(&key_b64) {
                Ok(b) if b.len() == 32 => b, _ => {
                    log::error!("处理消息: 密钥格式无效 uuid={}", fields.local_uuid);
                    return -1;
                }
            };
            let mut key_arr = [0u8; 32]; key_arr.copy_from_slice(&key_bytes);
            log::debug!("处理消息: 解密 DATA header={}, uuid={}, 密文长度={}",
                hdr, fields.local_uuid, fields.encrypted_payload.len());
            let plain = match aes::decrypt(&key_arr, fields.encrypted_payload) {
                Ok(p) => p, Err(_) => {
                    log::error!("处理消息: DATA 解密失败 header={}, uuid={}", hdr, fields.local_uuid);
                    return -1;
                }
            };
            let plaintext = String::from_utf8_lossy(&plain).to_string();
            let uuid_s = fields.local_uuid;
            log::info!("处理消息: DATA 解密成功 header={}, uuid={}, 明文长度={}", hdr, uuid_s, plaintext.len());
            match hdr {
                "DATA_NOTIFICATION" => {
                    let n = serde_json::from_str::<crate::models::Notification>(&plaintext)
                        .ok().and_then(|v| serde_json::to_string(&v).ok()).unwrap_or(plaintext.clone());
                    dispatch_data(cb_notif, uuid_s, &n, ud);
                }
                "DATA_MEDIAPLAY" | "DATA_SUPERISLAND" => {
                    let n = serde_json::from_str::<crate::models::MediaPayload>(&plaintext)
                        .ok().and_then(|v| serde_json::to_string(&v).ok()).unwrap_or(plaintext.clone());
                    let cb = if hdr == "DATA_MEDIAPLAY" { cb_media } else { cb_super };
                    dispatch_data(cb, uuid_s, &n, ud);
                }
                "DATA_ICON_REQUEST" => {
                    let n = serde_json::from_str::<crate::models::IconRequest>(&plaintext)
                        .ok().and_then(|v| serde_json::to_string(&v).ok()).unwrap_or(plaintext.clone());
                    dispatch_data(cb_icon_req, uuid_s, &n, ud);
                }
                "DATA_ICON_RESPONSE" => {
                    let n = serde_json::from_str::<crate::models::IconResponse>(&plaintext)
                        .ok().and_then(|v| serde_json::to_string(&v).ok()).unwrap_or(plaintext.clone());
                    dispatch_data(cb_icon_resp, uuid_s, &n, ud);
                }
                "DATA_APP_LIST_REQUEST" => {
                    let n = serde_json::from_str::<crate::models::AppListRequest>(&plaintext)
                        .ok().and_then(|v| serde_json::to_string(&v).ok()).unwrap_or(plaintext.clone());
                    dispatch_data(cb_app_req, uuid_s, &n, ud);
                }
                "DATA_APP_LIST_RESPONSE" => {
                    let n = serde_json::from_str::<crate::models::AppListResponse>(&plaintext)
                        .ok().and_then(|v| serde_json::to_string(&v).ok()).unwrap_or(plaintext.clone());
                    dispatch_data(cb_app_resp, uuid_s, &n, ud);
                }
                "DATA_MEDIA_CONTROL" => {
                    let n = serde_json::from_str::<crate::models::MediaControl>(&plaintext)
                        .ok().and_then(|v| serde_json::to_string(&v).ok()).unwrap_or(plaintext.clone());
                    dispatch_data(cb_ctrl, uuid_s, &n, ud);
                }
                "DATA_FTP" => {
                    let n = serde_json::from_str::<crate::models::FtpMessage>(&plaintext)
                        .ok().and_then(|v| serde_json::to_string(&v).ok()).unwrap_or(plaintext.clone());
                    dispatch_data(cb_ftp, uuid_s, &n, ud);
                }
                "DATA_CLIPBOARD" => {
                    let n = serde_json::from_str::<crate::models::ClipboardData>(&plaintext)
                        .ok().and_then(|v| serde_json::to_string(&v).ok()).unwrap_or(plaintext.clone());
                    dispatch_data(cb_clip, uuid_s, &n, ud);
                }
                "DATA_STATUS" => {
                    let n = serde_json::from_str::<crate::models::StatusMessage>(&plaintext)
                        .ok().and_then(|v| serde_json::to_string(&v).ok()).unwrap_or(plaintext.clone());
                    dispatch_data(cb_status, uuid_s, &n, ud);
                }
                "DATA_APP_LAUNCH" => {
                    let n = serde_json::from_str::<crate::models::AppLaunch>(&plaintext)
                        .ok().and_then(|v| serde_json::to_string(&v).ok()).unwrap_or(plaintext.clone());
                    dispatch_data(cb_launch, uuid_s, &n, ud);
                }
                _ => dispatch_data(cb_unk, uuid_s, &plaintext, ud),
            }
            0
        }
        _ => {
            log::warn!("处理消息: 未知消息类型");
            -1
        }
    }
}

// ==================== Simplified decrypt (no protocol line needed) ====================

#[no_mangle]
pub extern "C" fn nrc_decrypt_payload(
    ctx_ptr: *mut c_void, local_uuid: *const c_char, encrypted_b64: *const c_char,
) -> *mut c_char {
    let uuid = unsafe { from_cstr(local_uuid) };
    let enc = unsafe { from_cstr(encrypted_b64) };
    with_ctx(ctx_ptr, |ctx| {
        let key_b64 = match ctx.crypto.device_keys.get(uuid) {
            Some(k) => k.aes_key_b64.clone(), None => return std::ptr::null_mut(),
        };
        let key_bytes = base64::engine::general_purpose::STANDARD.decode(&key_b64).ok();
        let key_arr: [u8; 32] = match key_bytes {
            Some(b) if b.len() == 32 => { let mut arr = [0u8; 32]; arr.copy_from_slice(&b); arr }
            _ => return std::ptr::null_mut(),
        };
        match aes::decrypt(&key_arr, enc) {
            Ok(plain) => { let s = String::from_utf8_lossy(&plain).to_string(); to_cstr(&s) }
            Err(_) => std::ptr::null_mut(),
        }
    })
}
