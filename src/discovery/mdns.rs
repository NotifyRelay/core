//! mDNS 设备发现（替代 UDP 广播）。
//!
//! 设计要点：
//! - 用标准 mDNS/DNS-SD 广播服务，跨平台（Android/iOS/Windows/Linux）系统级可见；
//! - 服务类型固定，TXT 记录承载设备身份与状态，**不依赖自定义 UDP 报文格式**；
//! - 发现结果统一走 `consume_discovered_device`，与其它发现来源共用消费链。

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};

use crate::SafeContext;

/// mDNS 服务类型（`.local` 域名下）。
pub const SERVICE_TYPE: &str = "_notifyrelay._udp.local.";

/// 注册本机服务并开始监听对端。
pub struct MdnsDiscovery {
    daemon: ServiceDaemon,
    running: Arc<AtomicBool>,
    fullname: String,
    /// 注册参数快照：电量为动态字段，变更时据此重新注册 TXT 记录
    uuid: String,
    name_b64: String,
    port: u16,
    device_type: String,
}

impl MdnsDiscovery {
    /// 更新电量：重新注册服务，使对端从 mDNS TXT 记录读到最新值。
    ///
    /// mDNS 的 TXT 记录在注册时固化，不重新注册就不会刷新；
    /// 因此电量变化必须走这里，而不是只改内存中的 broadcast_info。
    pub fn update_battery(&mut self, battery: i32) {
        let mut props = HashMap::new();
        props.insert("uuid".to_string(), self.uuid.clone());
        props.insert("name".to_string(), self.name_b64.clone());
        props.insert("battery".to_string(), battery.to_string());
        props.insert("type".to_string(), self.device_type.clone());
        props.insert(
            "ver".to_string(),
            crate::protocol::version::CORE_VERSION.to_string(),
        );
        let instance = format!("nr-{}", self.uuid);
        let host = format!("{}.local.", instance);
        let info = match ServiceInfo::new(SERVICE_TYPE, &instance, &host, "", self.port, props) {
            Ok(i) => i.enable_addr_auto(),
            Err(e) => {
                log::warn!("更新 mDNS 电量失败（构造服务信息）: {}", e);
                return;
            }
        };
        // 先注销旧记录再注册新记录，避免出现两条同名服务
        let _ = self.daemon.unregister(&self.fullname);
        match self.daemon.register(info) {
            Ok(()) => log::debug!("mDNS 电量已更新: {}", battery),
            Err(e) => log::warn!("更新 mDNS 电量失败（注册）: {}", e),
        }
    }
}

impl MdnsDiscovery {
    /// 启动 mDNS 发现：注册本机服务 + 订阅同类型服务事件。
    ///
    /// `port` 为 QUIC 端口；TXT 记录携带 uuid/base64 名称/电量/设备类型，
    /// 使对端无需额外探测即可完成发现与展示。
    pub fn start(
        ctx_ptr: usize,
        uuid: &str,
        name: &str,
        port: u16,
        battery: i32,
        device_type: &str,
    ) -> Result<Self, String> {
        let daemon = ServiceDaemon::new().map_err(|e| format!("创建 mDNS daemon 失败: {e}"))?;

        let name_b64 = crate::utils::encode_name_b64(name);
        let mut props = HashMap::new();
        props.insert("uuid".to_string(), uuid.to_string());
        props.insert("name".to_string(), name_b64);
        props.insert("battery".to_string(), battery.to_string());
        props.insert("type".to_string(), device_type.to_string());
        props.insert(
            "ver".to_string(),
            crate::protocol::version::CORE_VERSION.to_string(),
        );

        // 实例名必须全局唯一，用 uuid 避免同名冲突
        let instance = format!("nr-{}", uuid);
        let host = format!("{}.local.", instance);
        let info = ServiceInfo::new(SERVICE_TYPE, &instance, &host, "", port, props)
            .map_err(|e| format!("构造 mDNS 服务信息失败: {e}"))?
            .enable_addr_auto();

        let fullname = info.get_fullname().to_string();
        daemon
            .register(info)
            .map_err(|e| format!("注册 mDNS 服务失败: {e}"))?;

        let receiver = daemon
            .browse(SERVICE_TYPE)
            .map_err(|e| format!("订阅 mDNS 服务失败: {e}"))?;

        let running = Arc::new(AtomicBool::new(true));
        let running_clone = running.clone();

        thread::Builder::new()
            .name("mdns-discovery".to_string())
            .spawn(move || {
                while running_clone.load(Ordering::Relaxed) {
                    match receiver.recv_timeout(Duration::from_millis(500)) {
                        Ok(ServiceEvent::ServiceResolved(resolved)) => {
                            handle_resolved(ctx_ptr, &resolved);
                        }
                        Ok(ServiceEvent::ServiceRemoved(_, fullname)) => {
                            log::debug!("mDNS 服务移除: {}", fullname);
                        }
                        Ok(_) => {}
                        Err(_) => continue,
                    }
                }
            })
            .map_err(|e| format!("启动 mDNS 发现线程失败: {e}"))?;

        log::info!(
            "mDNS 发现已启动: service={}, instance={}, port={}",
            SERVICE_TYPE,
            instance,
            port
        );
        Ok(Self {
            daemon,
            running,
            fullname,
            uuid: uuid.to_string(),
            name_b64: crate::utils::encode_name_b64(name),
            port,
            device_type: device_type.to_string(),
        })
    }

    /// 停止发现并注销本机服务。
    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
        let _ = self.daemon.unregister(&self.fullname);
        let _ = self.daemon.shutdown();
        log::info!("mDNS 发现已停止");
    }
}

impl Drop for MdnsDiscovery {
    fn drop(&mut self) {
        self.stop();
    }
}

/// 处理一条已解析的对端服务记录。
fn handle_resolved(ctx_ptr: usize, resolved: &mdns_sd::ResolvedService) {
    let Some(uuid) = resolved.txt_properties.get_property_val_str("uuid") else {
        log::debug!("mDNS 服务缺少 uuid 属性，忽略: {}", resolved.fullname);
        return;
    };
    if uuid.is_empty() {
        return;
    }
    let name_b64 = resolved
        .txt_properties
        .get_property_val_str("name")
        .unwrap_or("");
    let battery = resolved
        .txt_properties
        .get_property_val_str("battery")
        .and_then(|s| s.trim_end_matches('+').parse::<i32>().ok())
        .unwrap_or(0);
    let device_type = resolved
        .txt_properties
        .get_property_val_str("type")
        .unwrap_or("");

    // 取首个可用 IPv4 地址：必须排除环回与链路本地址。
    // mDNS 解析结果里可能同时出现 127.0.0.1（本机接口）与真实局域网地址，
    // 选中 127.0.0.1 会让后续连接发往本机，对端永远连不上。
    let Some(ip) = resolved
        .addresses
        .iter()
        .map(|a| a.to_ip_addr())
        .find(|ip| match ip {
            std::net::IpAddr::V4(v4) => {
                !v4.is_loopback() && !v4.is_link_local() && !v4.is_unspecified()
            }
            std::net::IpAddr::V6(v6) => !v6.is_loopback() && !v6.is_unspecified(),
        })
        .map(|ip| ip.to_string())
    else {
        log::debug!("mDNS 服务无可用（非环回）地址，忽略: {}", uuid);
        return;
    };

    log::debug!(
        "mDNS 发现设备: uuid={}, ip={}, port={}, name_b64={}, type={}",
        uuid,
        ip,
        resolved.port,
        name_b64,
        device_type
    );
    let ctx = unsafe { &*(ctx_ptr as *const SafeContext) };
    crate::send::consume_discovered_device(
        ctx,
        uuid,
        name_b64,
        resolved.port,
        battery,
        device_type,
        &ip,
    );
}
