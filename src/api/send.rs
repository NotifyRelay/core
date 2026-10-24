//! 发送链路、网络与服务启动的委托实现。

use super::conv::{cs, take_cstr_or_empty};
use super::Core;

#[uniffi::export]
impl Core {
    // ===== 发送队列 =====

    /// 入队一条待发送报文。
    ///
    /// header 的 DATA_ 前缀规范化、去重键推导与 3s 发送去重均在内部完成。
    /// 返回 true=已入队（命中去重也视为成功）。
    pub fn enqueue_message(&self, device_uuid: String, header: String, plaintext: String) -> bool {
        let queue = self.queue_handle();
        let u = cs(&device_uuid);
        let h = cs(&header);
        let p = cs(&plaintext);
        unsafe {
            crate::ffi::sender_queue::nrc_enqueue_message(
                self.ctx_ptr(),
                queue,
                u.as_ptr(),
                h.as_ptr(),
                p.as_ptr(),
            ) == 1
        }
    }

    /// 发送队列是否已就绪（`start_core` 已创建队列）。
    pub fn is_sender_queue_ready(&self) -> bool {
        self.queue_handle() != 0
    }

    // ===== 握手与配对 =====

    /// 发送握手；优先走已建立会话，失败则 one-shot 连接。
    pub fn send_handshake(
        &self,
        uuid: String,
        local_ip: String,
        target_ip: String,
        battery: i32,
        device_type: String,
    ) -> i32 {
        let u = cs(&uuid);
        let li = cs(&local_ip);
        let ti = cs(&target_ip);
        let d = cs(&device_type);
        unsafe {
            crate::ffi::send::nrc_send_handshake(
                self.ctx_ptr(),
                u.as_ptr(),
                std::ptr::null(),
                li.as_ptr(),
                ti.as_ptr(),
                battery,
                d.as_ptr(),
            )
        }
    }

    /// 发起配对（客户端侧）。
    pub fn send_pairing_init(
        &self,
        local_uuid: String,
        target_uuid: String,
        expected_code: String,
        battery: i32,
        device_type: String,
    ) -> i32 {
        let lu = cs(&local_uuid);
        let tu = cs(&target_uuid);
        let ec = cs(&expected_code);
        let d = cs(&device_type);
        unsafe {
            crate::ffi::send::nrc_send_pairing_init(
                self.ctx_ptr(),
                lu.as_ptr(),
                tu.as_ptr(),
                ec.as_ptr(),
                battery,
                d.as_ptr(),
            )
        }
    }

    /// 回应配对（服务端侧）。
    pub fn send_pairing_resp(
        &self,
        uuid: String,
        lt_pub: String,
        pairing_code: String,
        ip: String,
        battery: i32,
        device_type: String,
    ) -> i32 {
        let u = cs(&uuid);
        let l = cs(&lt_pub);
        let c = cs(&pairing_code);
        let i = cs(&ip);
        let d = cs(&device_type);
        unsafe {
            crate::ffi::send::nrc_send_pairing_resp(
                self.ctx_ptr(),
                u.as_ptr(),
                l.as_ptr(),
                c.as_ptr(),
                i.as_ptr(),
                battery,
                d.as_ptr(),
            )
        }
    }

    /// 发送 ACCEPT。
    pub fn send_accept(
        &self,
        target_uuid: String,
        lt_pub_key: String,
        ip: String,
        battery: i32,
        device_type: String,
    ) {
        let u = cs(&target_uuid);
        let l = cs(&lt_pub_key);
        let i = cs(&ip);
        let d = cs(&device_type);
        unsafe {
            crate::ffi::send::nrc_send_accept(
                self.ctx_ptr(),
                u.as_ptr(),
                l.as_ptr(),
                i.as_ptr(),
                battery,
                d.as_ptr(),
            )
        }
    }

    /// 发送 REJECT。
    pub fn send_reject(&self, uuid: String) {
        let u = cs(&uuid);
        unsafe { crate::ffi::send::nrc_send_reject(self.ctx_ptr(), u.as_ptr()) }
    }

    /// 主动连接设备（带重试）。
    pub fn connect_device(
        &self,
        uuid: String,
        target_ip: String,
        battery: i32,
        device_type: String,
    ) -> i32 {
        let u = cs(&uuid);
        let t = cs(&target_ip);
        let d = cs(&device_type);
        unsafe {
            crate::ffi::send::nrc_connect_device(
                self.ctx_ptr(),
                u.as_ptr(),
                t.as_ptr(),
                battery,
                d.as_ptr(),
            )
        }
    }

    // ===== 广播与配对码 =====

    /// 周期性 UDP 广播发现控制：0=停止，1=启动，2=仅更新参数。
    pub fn periodic_broadcast(
        &self,
        action: i32,
        uuid: String,
        name: String,
        battery: i32,
        device_type: String,
    ) -> i32 {
        let u = cs(&uuid);
        let n = cs(&name);
        let d = cs(&device_type);
        unsafe {
            crate::ffi::send::nrc_periodic_broadcast(
                self.ctx_ptr(),
                action,
                u.as_ptr(),
                n.as_ptr(),
                battery,
                d.as_ptr(),
            )
        }
    }

    /// 生成 6 位配对码并设置有效期（秒；0 表示 300s）。
    pub fn generate_pairing_code(&self, ttl_secs: u32) -> String {
        unsafe {
            take_cstr_or_empty(crate::ffi::send::nrc_generate_pairing_code(
                self.ctx_ptr(),
                ttl_secs,
            ))
        }
    }

    /// 清除配对码。
    pub fn clear_pairing_code(&self) {
        crate::ffi::send::nrc_clear_pairing_code(self.ctx_ptr())
    }

    // ===== 网络与服务 =====

    /// 移除指定设备的 TCP 会话。
    pub fn remove_device_session(&self, uuid: String) -> i32 {
        let u = cs(&uuid);
        unsafe { crate::ffi::network::nrc_remove_device_session(self.ctx_ptr(), u.as_ptr()) }
    }

    /// 网络变化通知（重启已知设备扫描器）；`local_ip` 为空表示未取到。
    pub fn on_network_changed(&self, local_ip: String) {
        let ip = cs(&local_ip);
        unsafe { crate::ffi::network::nrc_on_network_changed(self.ctx_ptr(), ip.as_ptr()) }
    }

    /// 启动核心：TCP 服务器、心跳、离线检测、发送队列、发现扫描器、重连状态机。
    ///
    /// 返回发送队列句柄；0 表示启动失败。
    #[allow(clippy::too_many_arguments)]
    pub fn start_core(
        &self,
        uuid: String,
        name: String,
        battery: i32,
        device_type: String,
        tcp_port: u16,
        heartbeat_interval_ms: u64,
        offline_timeout_sec: i64,
        offline_check_interval_ms: u64,
        reconnect_interval_secs: u64,
        reconnect_max_retries: u32,
    ) -> u64 {
        let u = cs(&uuid);
        let n = cs(&name);
        let d = cs(&device_type);
        unsafe {
            crate::ffi::network::nrc_start_core(
                self.ctx_ptr(),
                u.as_ptr(),
                n.as_ptr(),
                battery,
                d.as_ptr(),
                tcp_port,
                std::ptr::null(),
                heartbeat_interval_ms,
                offline_timeout_sec,
                offline_check_interval_ms,
                reconnect_interval_secs,
                reconnect_max_retries,
            )
        }
    }

    /// 更新心跳调度器的广播参数。
    pub fn update_heartbeat_scheduler_params(
        &self,
        name: String,
        battery: i32,
        device_type: String,
    ) {
        let n = cs(&name);
        let d = cs(&device_type);
        unsafe {
            crate::ffi::heartbeat::nrc_update_heartbeat_scheduler_params(
                self.ctx_ptr(),
                n.as_ptr(),
                battery,
                d.as_ptr(),
            )
        }
    }

    // ===== 发现与重连 =====

    /// 登记已知设备。
    pub fn add_known_device(&self, uuid: String, ip: String) {
        let u = cs(&uuid);
        let i = cs(&ip);
        unsafe {
            crate::ffi::discovery::nrc_add_known_device(self.ctx_ptr(), u.as_ptr(), i.as_ptr())
        }
    }

    /// 移除已知设备。
    pub fn remove_known_device(&self, uuid: String) {
        let u = cs(&uuid);
        unsafe { crate::ffi::discovery::nrc_remove_known_device(self.ctx_ptr(), u.as_ptr()) }
    }

    /// 登记重连目标。
    pub fn reconnect_add_target(&self, uuid: String, ip: String) {
        let u = cs(&uuid);
        let i = cs(&ip);
        unsafe {
            crate::ffi::reconnect::nrc_reconnect_add_target(self.ctx_ptr(), u.as_ptr(), i.as_ptr())
        }
    }

    /// 移除重连目标。
    pub fn reconnect_remove_target(&self, uuid: String) {
        let u = cs(&uuid);
        unsafe { crate::ffi::reconnect::nrc_reconnect_remove_target(self.ctx_ptr(), u.as_ptr()) }
    }

    // ===== 过滤 =====

    /// 设置远端过滤配置（JSON）。
    pub fn set_filter_config(&self, config_json: String) -> i32 {
        let c = cs(&config_json);
        unsafe {
            crate::ffi::filter::nrc_set_filter_config(
                self.ctx_ptr() as *mut crate::SafeContext,
                c.as_ptr(),
            )
        }
    }

    /// 由远端包名映射到本机包名。
    pub fn map_local_package(&self, remote_package: String) -> String {
        let p = cs(&remote_package);
        unsafe {
            take_cstr_or_empty(crate::ffi::filter::nrc_map_local_package(
                self.ctx_ptr() as *mut crate::SafeContext,
                p.as_ptr(),
            ))
        }
    }

    /// 检查过滤模式：true = 应过滤（不展示）。
    pub fn check_filter_mode(
        &self,
        mapped_package: String,
        original_package: String,
        title: String,
        text: String,
    ) -> i32 {
        let m = cs(&mapped_package);
        let o = cs(&original_package);
        let t = cs(&title);
        let x = cs(&text);
        unsafe {
            crate::ffi::filter::nrc_check_filter_mode(
                self.ctx_ptr() as *mut crate::SafeContext,
                m.as_ptr(),
                o.as_ptr(),
                t.as_ptr(),
                x.as_ptr(),
            )
        }
    }

    // ===== 去重 =====

    /// 统一去重接口：action 0=check_and_pend / 1=mark_sent / 2=clear_pending / 3=cleanup。
    pub fn dedup(&self, action: i32, dedup_key: String, arg1_ms: i64, arg2_ms: i64) -> i32 {
        let k = cs(&dedup_key);
        unsafe {
            crate::ffi::utils::nrc_dedup(self.ctx_ptr(), action, k.as_ptr(), arg1_ms, arg2_ms)
        }
    }

    /// 入站内容去重：0=纯查询 / 1=标记已见 / 2=清除内容键。
    pub fn content_dedup(&self, action: i32, title: String, text: String) -> i32 {
        let t = cs(&title);
        let x = cs(&text);
        unsafe {
            crate::ffi::utils::nrc_content_dedup(self.ctx_ptr(), action, t.as_ptr(), x.as_ptr())
        }
    }
}

impl Core {
    /// 发送队列句柄（由 `start_core` 创建）；未启动时为 0。
    pub(crate) fn queue_handle(&self) -> u64 {
        crate::ffi::send::queue_handle_of(self.ctx_ptr())
    }
}
