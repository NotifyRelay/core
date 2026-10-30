//! 发送链路、网络与服务启动的导出实现。

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
        crate::sender_queue::enqueue_message(
            self.ctx_ptr() as usize,
            queue,
            &device_uuid,
            &header,
            &plaintext,
        ) == 1
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
        crate::send::send_handshake(
            self.ctx(),
            &uuid,
            &local_ip,
            &target_ip,
            battery,
            &device_type,
        )
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
        crate::send::send_pairing_init(
            self.ctx(),
            &local_uuid,
            &target_uuid,
            &expected_code,
            battery,
            &device_type,
        )
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
        crate::send::send_pairing_resp(
            self.ctx(),
            &uuid,
            &lt_pub,
            &pairing_code,
            &ip,
            battery,
            &device_type,
        )
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
        crate::send::send_accept(
            self.ctx(),
            &target_uuid,
            &lt_pub_key,
            &ip,
            battery,
            &device_type,
        );
    }

    /// 发送 REJECT。
    pub fn send_reject(&self, uuid: String) {
        crate::send::send_reject(self.ctx(), &uuid);
    }

    /// 主动连接设备（带重试）。
    pub fn connect_device(
        &self,
        uuid: String,
        target_ip: String,
        battery: i32,
        device_type: String,
    ) -> i32 {
        crate::send::connect_device(self.ctx(), &uuid, &target_ip, battery, &device_type)
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
        crate::send::periodic_broadcast(
            self.ctx_ptr() as usize,
            action,
            Some(&uuid),
            Some(&name),
            battery,
            Some(&device_type),
        )
    }

    /// 生成 6 位配对码并设置有效期（秒；0 表示 300s）。
    pub fn generate_pairing_code(&self, ttl_secs: u32) -> String {
        crate::send::generate_pairing_code(self.ctx(), ttl_secs)
    }

    /// 清除配对码。
    pub fn clear_pairing_code(&self) {
        crate::send::clear_pairing_code(self.ctx());
    }

    // ===== 网络与服务 =====

    /// 移除指定设备的 TCP 会话。
    pub fn remove_device_session(&self, uuid: String) -> i32 {
        let Ok(mut guard) = self.ctx().lock() else {
            return -1;
        };
        crate::network::remove_session(&mut guard, &uuid)
    }

    /// 网络变化通知（重启已知设备扫描器）；`local_ip` 为空表示未取到。
    pub fn on_network_changed(&self, local_ip: String) {
        let ip = if local_ip.is_empty() {
            None
        } else {
            Some(local_ip.as_str())
        };
        crate::network::notify_network_changed(self.ctx_ptr() as usize, ip);
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
        crate::service::start_core(
            self.ctx_ptr() as usize,
            crate::service::StartCoreParams {
                uuid: &uuid,
                name: &name,
                battery,
                device_type: &device_type,
                tcp_port,
                heartbeat_interval_ms,
                offline_timeout_sec,
                offline_check_interval_ms,
                reconnect_interval_secs,
                reconnect_max_retries,
            },
        )
    }

    /// 更新心跳调度器的广播参数。
    pub fn update_heartbeat_scheduler_params(
        &self,
        name: String,
        battery: i32,
        device_type: String,
    ) {
        crate::heartbeat::update_scheduler_params(self.ctx(), &name, battery, &device_type);
    }

    // ===== 发现与重连 =====

    /// 登记已知设备。
    pub fn add_known_device(&self, uuid: String, ip: String) {
        let Ok(mut guard) = self.ctx().lock() else {
            return;
        };
        crate::discovery::add_known_device(&mut guard, &uuid, &ip);
    }

    /// 移除已知设备。
    pub fn remove_known_device(&self, uuid: String) {
        let Ok(mut guard) = self.ctx().lock() else {
            return;
        };
        crate::discovery::remove_known_device(&mut guard, &uuid);
    }

    /// 登记重连目标。
    pub fn reconnect_add_target(&self, uuid: String, ip: String) {
        let Ok(mut guard) = self.ctx().lock() else {
            return;
        };
        crate::reconnect::add_target(&mut guard, &uuid, &ip);
    }

    /// 移除重连目标。
    pub fn reconnect_remove_target(&self, uuid: String) {
        let Ok(mut guard) = self.ctx().lock() else {
            return;
        };
        crate::reconnect::remove_target(&mut guard, &uuid);
    }

    // ===== 过滤 =====

    /// 设置远端过滤配置（JSON）。
    pub fn set_filter_config(&self, config_json: String) -> i32 {
        let Ok(guard) = self.ctx().lock() else {
            return -1;
        };
        if crate::filter::set_config_json(&guard.filter, &config_json) {
            0
        } else {
            -1
        }
    }

    /// 由远端包名映射到本机包名。
    pub fn map_local_package(&self, remote_package: String) -> String {
        let Ok(guard) = self.ctx().lock() else {
            return remote_package;
        };
        crate::filter::map_local_package(&guard.filter, &remote_package)
    }

    /// 检查过滤模式：返回 1=通过，0=被过滤。
    pub fn check_filter_mode(
        &self,
        mapped_package: String,
        original_package: String,
        title: String,
        text: String,
    ) -> i32 {
        let _ = original_package;
        let Ok(guard) = self.ctx().lock() else {
            return 1;
        };
        i32::from(crate::filter::check_mode(
            &guard.filter,
            &mapped_package,
            &title,
            &text,
        ))
    }

    // ===== 去重 =====

    /// 统一去重接口：action 0=check_and_pend / 1=mark_sent / 2=clear_pending / 3=cleanup。
    pub fn dedup(&self, action: i32, dedup_key: String, arg1_ms: i64, arg2_ms: i64) -> i32 {
        let Ok(mut guard) = self.ctx().lock() else {
            return -1;
        };
        match action {
            0 => {
                if dedup_key.is_empty() {
                    return 0;
                }
                i32::from(guard.dedup.check_and_pend(&dedup_key, arg1_ms))
            }
            1 => {
                if !dedup_key.is_empty() {
                    guard.dedup.mark_sent(&dedup_key);
                }
                0
            }
            2 => {
                if !dedup_key.is_empty() {
                    guard.dedup.clear_pending(&dedup_key);
                }
                0
            }
            3 => {
                guard.dedup.cleanup(arg1_ms, arg2_ms);
                0
            }
            _ => -1,
        }
    }

    /// 入站内容去重：0=纯查询 / 1=标记已见 / 2=清除内容键。
    pub fn content_dedup(&self, action: i32, app_name: String, title: String, text: String) -> i32 {
        let key = crate::dedup::content_key(&app_name, &title, &text);
        let Ok(mut guard) = self.ctx().lock() else {
            return -1;
        };
        match action {
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
        }
    }
}

impl Core {
    /// 发送队列句柄（由 `start_core` 创建）；未启动时为 0。
    pub(crate) fn queue_handle(&self) -> u64 {
        crate::sender_queue::handle_of(self.ctx_ptr() as usize)
    }
}
