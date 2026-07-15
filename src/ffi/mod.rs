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
        log::set_logger(&LOG_BRIDGE).ok();
        log::set_max_level(log::LevelFilter::Debug);
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
            Err(e) => { log::error!("import_state parse error: {}", e); -1 }
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

// ==================== Format helpers (kept as-is) ====================

#[no_mangle]
pub extern "C" fn nrc_format_heartbeat(uuid: *const c_char, name: *const c_char,
    port: u16, battery: i32, device_type: *const c_char) -> *mut c_char {
    let u = unsafe { from_cstr(uuid) }; let n = unsafe { from_cstr(name) };
    let dt = unsafe { from_cstr(device_type) };
    to_cstr(&crate::heartbeat::format_udp_heartbeat(u, n, port, battery, dt))
}

#[no_mangle]
pub extern "C" fn nrc_parse_heartbeat(line: *const c_char) -> *mut c_char {
    let l = unsafe { from_cstr(line) };
    let result = crate::heartbeat::parse_udp_heartbeat(l)
        .map(|(u, n, p, b, d)| codec::encode_udp_broadcast(&u, &n, p, b, &d))
        .unwrap_or_default();
    to_cstr(&result)
}

#[no_mangle]
pub extern "C" fn nrc_format_discovery(uuid: *const c_char, name: *const c_char,
    port: u16, battery: i32, device_type: *const c_char) -> *mut c_char {
    let u = unsafe { from_cstr(uuid) }; let n = unsafe { from_cstr(name) };
    let dt = unsafe { from_cstr(device_type) };
    to_cstr(&crate::discovery::format_discovery_broadcast(u, n, port, battery, dt))
}

#[no_mangle]
pub extern "C" fn nrc_format_tcp_heartbeat(uuid: *const c_char, name_b64: *const c_char,
    port: u16, battery: i32, device_type: *const c_char) -> *mut c_char {
    let u = unsafe { from_cstr(uuid) }; let n = unsafe { from_cstr(name_b64) };
    let dt = unsafe { from_cstr(device_type) };
    to_cstr(&crate::heartbeat::format_tcp_heartbeat(u, n, port, battery, dt))
}

#[no_mangle]
pub extern "C" fn nrc_parse_heartbeat_json(line: *const c_char) -> *mut c_char {
    let l = unsafe { from_cstr(line) };
    match crate::heartbeat::parse_udp_heartbeat(l) {
        Some((uuid, name, port, battery, device_type)) =>
            to_cstr(&serde_json::json!({ "uuid": uuid, "name_b64": name,
                "port": port, "battery": battery, "device_type": device_type }).to_string()),
        None => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn nrc_parse_heartbeat_tcp_json(line: *const c_char) -> *mut c_char {
    let l = unsafe { from_cstr(line) };
    match codec::decode_heartbeat_tcp(l) {
        Some(f) => to_cstr(&serde_json::json!({ "uuid": f.uuid, "name_b64": f.name,
            "port": f.port, "battery": f.battery, "device_type": f.device_type }).to_string()),
        None => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn nrc_format_pairing_init(uuid: *const c_char, tmp_pub_key: *const c_char,
    ip: *const c_char, battery: i32, device_type: *const c_char) -> *mut c_char {
    let u = unsafe { from_cstr(uuid) }; let t = unsafe { from_cstr(tmp_pub_key) };
    let i = unsafe { from_cstr(ip) }; let d = unsafe { from_cstr(device_type) };
    to_cstr(&codec::encode_pairing_init(u, t, i, battery, d))
}

#[no_mangle]
pub extern "C" fn nrc_format_pairing_resp(uuid: *const c_char, tmp_pub: *const c_char,
    lt_pub: *const c_char, encrypted_code: *const c_char, ip: *const c_char,
    battery: i32, device_type: *const c_char) -> *mut c_char {
    let u = unsafe { from_cstr(uuid) }; let t = unsafe { from_cstr(tmp_pub) };
    let l = unsafe { from_cstr(lt_pub) }; let e = unsafe { from_cstr(encrypted_code) };
    let i = unsafe { from_cstr(ip) }; let d = unsafe { from_cstr(device_type) };
    to_cstr(&codec::encode_pairing_resp(u, t, l, e, i, battery, d))
}

#[no_mangle]
pub extern "C" fn nrc_format_accept(uuid: *const c_char, lt_pub_key: *const c_char,
    ip: *const c_char, battery: i32, device_type: *const c_char) -> *mut c_char {
    let u = unsafe { from_cstr(uuid) }; let l = unsafe { from_cstr(lt_pub_key) };
    let i = unsafe { from_cstr(ip) }; let d = unsafe { from_cstr(device_type) };
    to_cstr(&codec::encode_accept(u, l, i, battery, d))
}

#[no_mangle]
pub extern "C" fn nrc_format_handshake(uuid: *const c_char, pub_key: *const c_char,
    ip: *const c_char, battery: i32, device_type: *const c_char) -> *mut c_char {
    let u = unsafe { from_cstr(uuid) }; let p = unsafe { from_cstr(pub_key) };
    let i = unsafe { from_cstr(ip) }; let d = unsafe { from_cstr(device_type) };
    to_cstr(&codec::encode_handshake(u, p, i, battery, d))
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
make_cb_setter!(nrc_set_on_discover_manual_cb, crate::router::OnDiscoverManualCb, on_discover_manual);

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

// ==================== nrc_process_line (unified entry) ====================

fn dispatch_data(cb: crate::router::OnDataCb, local_uuid: &str, plaintext: &str, ud: *mut c_void) {
    if let Some(cb) = cb {
        log::debug!("dispatch_data: uuid={}, len={}", local_uuid, plaintext.len());
        let uuid_c = CString::new(local_uuid).unwrap_or_default();
        let text_c = CString::new(plaintext).unwrap_or_default();
        cb(uuid_c.as_ptr(), text_c.as_ptr(), ud);
    } else {
        log::warn!("dispatch_data: no callback for uuid={}", local_uuid);
    }
}

#[no_mangle]
pub extern "C" fn nrc_process_line(ctx_ptr: *mut c_void, line: *const c_char) -> i32 {
    if ctx_ptr.is_null() || line.is_null() {
        log::error!("process_line: null pointer");
        return -1;
    }
    let line_str = unsafe { from_cstr(line) };
    if line_str.is_empty() {
        log::error!("process_line: empty line");
        return -1;
    }
    let header = ProtocolHeader::parse(line_str);
    log::debug!("process_line: type={:?}", header);
    let ctx = unsafe { &mut *(ctx_ptr as *mut SafeContext) };
    match header {
        ProtocolHeader::Handshake => {
            if let Some(f) = codec::decode_handshake(line_str) {
                let guard = match ctx.lock() { Ok(g) => g, Err(_) => return -1 };
                let cb = guard.router.on_handshake; let ud = guard.router.user_data;
                drop(guard);
                if let Some(cb) = cb {
                    let uuid = CString::new(f.uuid).unwrap_or_default();
                    let pk = CString::new(f.pub_key).unwrap_or_default();
                    let ip = CString::new(f.ip).unwrap_or_default();
                    let dt = CString::new(f.device_type).unwrap_or_default();
                    log::debug!("process_line: dispatching HANDSHAKE uuid={}", f.uuid);
                    cb(uuid.as_ptr(), pk.as_ptr(), ip.as_ptr(), f.battery, dt.as_ptr(), ud);
                } else {
                    log::warn!("process_line: on_handshake callback not registered");
                }
                0
            } else {
                log::error!("process_line: failed to decode HANDSHAKE");
                -1
            }
        }
        ProtocolHeader::PairingInit => {
            if let Some(f) = codec::decode_pairing_init(line_str) {
                let guard = match ctx.lock() { Ok(g) => g, Err(_) => return -1 };
                let cb = guard.router.on_pairing_init; let ud = guard.router.user_data;
                drop(guard);
                if let Some(cb) = cb {
                    let uuid = CString::new(f.uuid).unwrap_or_default();
                    let tmp = CString::new(f.tmp_pub_key).unwrap_or_default();
                    let ip = CString::new(f.ip).unwrap_or_default();
                    let dt = CString::new(f.device_type).unwrap_or_default();
                    log::debug!("process_line: dispatching PAIRING_INIT uuid={}", f.uuid);
                    cb(uuid.as_ptr(), tmp.as_ptr(), ip.as_ptr(), f.battery, dt.as_ptr(), ud);
                } else {
                    log::warn!("process_line: on_pairing_init callback not registered");
                }
                0
            } else {
                log::error!("process_line: failed to decode PAIRING_INIT");
                -1
            }
        }
        ProtocolHeader::PairingResp => {
            if let Some(f) = codec::decode_pairing_resp(line_str) {
                let guard = match ctx.lock() { Ok(g) => g, Err(_) => return -1 };
                let cb = guard.router.on_pairing_resp; let ud = guard.router.user_data;
                drop(guard);
                if let Some(cb) = cb {
                    let uuid = CString::new(f.uuid).unwrap_or_default();
                    let tmp = CString::new(f.tmp_pub).unwrap_or_default();
                    let lt = CString::new(f.lt_pub).unwrap_or_default();
                    let enc = CString::new(f.encrypted_code).unwrap_or_default();
                    let ip = CString::new(f.ip).unwrap_or_default();
                    let dt = CString::new(f.device_type).unwrap_or_default();
                    log::debug!("process_line: dispatching PAIRING_RESP uuid={}", f.uuid);
                    cb(uuid.as_ptr(), tmp.as_ptr(), lt.as_ptr(), enc.as_ptr(), ip.as_ptr(), f.battery, dt.as_ptr(), ud);
                } else {
                    log::warn!("process_line: on_pairing_resp callback not registered");
                }
                0
            } else {
                log::error!("process_line: failed to decode PAIRING_RESP");
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
                    log::debug!("process_line: dispatching ACCEPT uuid={}", f.uuid);
                    cb(uuid.as_ptr(), lt.as_ptr(), ip.as_ptr(), f.battery, dt.as_ptr(), ud);
                } else {
                    log::warn!("process_line: on_accept callback not registered");
                }
                0
            } else {
                log::error!("process_line: failed to decode ACCEPT");
                -1
            }
        }
        ProtocolHeader::Reject => {
            if let Some(payload) = line_str.strip_prefix("REJECT:") {
                let guard = match ctx.lock() { Ok(g) => g, Err(_) => return -1 };
                let cb = guard.router.on_reject; let ud = guard.router.user_data;
                drop(guard);
                if let Some(cb) = cb {
                    log::debug!("process_line: dispatching REJECT uuid={}", payload);
                    let uuid_c = CString::new(payload).unwrap_or_default();
                    cb(uuid_c.as_ptr(), ud);
                } else {
                    log::warn!("process_line: on_reject callback not registered");
                }
                0
            } else {
                log::error!("process_line: failed to decode REJECT");
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
                    log::debug!("process_line: dispatching HEARTBEAT_TCP uuid={}", f.uuid);
                    cb(uuid.as_ptr(), name.as_ptr(), f.port, f.battery, dt.as_ptr(), ip.as_ptr(), ud);
                } else {
                    log::warn!("process_line: on_heartbeat_tcp callback not registered");
                }
                0
            } else {
                log::error!("process_line: failed to decode HEARTBEAT_TCP");
                -1
            }
        }
        ProtocolHeader::DiscoverManual => {
            if let Some(f) = codec::decode_discovery_line(line_str) {
                let guard = match ctx.lock() { Ok(g) => g, Err(_) => return -1 };
                let cb = guard.router.on_discover_manual; let ud = guard.router.user_data;
                drop(guard);
                if let Some(cb) = cb {
                    let uuid = CString::new(f.uuid).unwrap_or_default();
                    let name = CString::new(f.name_b64).unwrap_or_default();
                    let dt = CString::new(f.device_type).unwrap_or_default();
                    log::debug!("process_line: dispatching DISCOVER_MANUAL uuid={}", f.uuid);
                    cb(uuid.as_ptr(), name.as_ptr(), f.port, f.battery, dt.as_ptr(), ud);
                } else {
                    log::warn!("process_line: on_discover_manual callback not registered");
                }
                0
            } else {
                log::error!("process_line: failed to decode DISCOVER_MANUAL");
                -1
            }
        }
        ProtocolHeader::Data(hdr) => {
            log::debug!("process_line: DATA message header={}", hdr);
            let fields = match codec::decode_data_message(line_str) {
                Some(f) => f, None => {
                    log::error!("process_line: failed to decode DATA message");
                    return -1;
                }
            };
            let guard = match ctx.lock() {
                Ok(g) => g, Err(_) => {
                    log::error!("process_line: lock failed for DATA message");
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
                    log::warn!("process_line: no key for uuid={}, header={}", fields.local_uuid, hdr);
                    return -1;
                }
            };
            let key_bytes = match base64::engine::general_purpose::STANDARD.decode(&key_b64) {
                Ok(b) if b.len() == 32 => b, _ => {
                    log::error!("process_line: invalid key for uuid={}", fields.local_uuid);
                    return -1;
                }
            };
            let mut key_arr = [0u8; 32]; key_arr.copy_from_slice(&key_bytes);
            log::debug!("process_line: decrypting DATA header={}, uuid={}, payload_len={}",
                hdr, fields.local_uuid, fields.encrypted_payload.len());
            let plain = match aes::decrypt(&key_arr, fields.encrypted_payload) {
                Ok(p) => p, Err(_) => {
                    log::error!("process_line: decryption failed header={}, uuid={}", hdr, fields.local_uuid);
                    return -1;
                }
            };
            let plaintext = String::from_utf8_lossy(&plain).to_string();
            let uuid_s = fields.local_uuid;
            log::info!("process_line: DATA decrypted header={}, uuid={}, plaintext_len={}", hdr, uuid_s, plaintext.len());
            match hdr {
                "DATA_NOTIFICATION" => dispatch_data(cb_notif, uuid_s, &plaintext, ud),
                "DATA_MEDIAPLAY" => dispatch_data(cb_media, uuid_s, &plaintext, ud),
                "DATA_ICON_REQUEST" => dispatch_data(cb_icon_req, uuid_s, &plaintext, ud),
                "DATA_ICON_RESPONSE" => dispatch_data(cb_icon_resp, uuid_s, &plaintext, ud),
                "DATA_APP_LIST_REQUEST" => dispatch_data(cb_app_req, uuid_s, &plaintext, ud),
                "DATA_APP_LIST_RESPONSE" => dispatch_data(cb_app_resp, uuid_s, &plaintext, ud),
                "DATA_MEDIA_CONTROL" => dispatch_data(cb_ctrl, uuid_s, &plaintext, ud),
                "DATA_FTP" => dispatch_data(cb_ftp, uuid_s, &plaintext, ud),
                "DATA_CLIPBOARD" => dispatch_data(cb_clip, uuid_s, &plaintext, ud),
                "DATA_STATUS" => dispatch_data(cb_status, uuid_s, &plaintext, ud),
                "DATA_APP_LAUNCH" => dispatch_data(cb_launch, uuid_s, &plaintext, ud),
                "DATA_SUPERISLAND" => dispatch_data(cb_super, uuid_s, &plaintext, ud),
                _ => dispatch_data(cb_unk, uuid_s, &plaintext, ud),
            }
            0
        }
        _ => {
            log::warn!("process_line: unhandled message type");
            -1
        }
    }
}
