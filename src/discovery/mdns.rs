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

        // 网卡策略：在所有 UP 且非回环的 IPv4 网卡上收发组播。
        //
        // 与 miLink 一致（每网卡独立 socket + IP_MULTICAST_IF）：
        // 组播必须逐网卡投递，任一网卡都可能承载对端通告。
        // mdns-sd 默认即覆盖全部网卡，不做接口收敛
        // （enable_interface 只做追加、disable_interface 无法缩小搜索范围）。
        let lan_addrs = crate::utils::local_ipv4_addrs();
        log::debug!("mDNS 组播网卡数: {}", lan_addrs.len());

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
                        Ok(ev) => {
                            log::debug!("mDNS 其它事件: {:?}", ev);
                        }
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

/// 判断两个 IPv4 是否属于同一 /24 网段（局域网可达性的实用近似）。
fn same_subnet_24(a: std::net::Ipv4Addr, b: std::net::Ipv4Addr) -> bool {
    let (ao, bo) = (a.octets(), b.octets());
    ao[0] == bo[0] && ao[1] == bo[1] && ao[2] == bo[2]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    /// 同 /24 网段判定：仅前三段相同才算同网段。
    #[test]
    fn same_subnet_only_matches_first_three_octets() {
        assert!(same_subnet_24(
            Ipv4Addr::new(192, 168, 31, 1),
            Ipv4Addr::new(192, 168, 31, 200)
        ));
        assert!(!same_subnet_24(
            Ipv4Addr::new(192, 168, 31, 1),
            Ipv4Addr::new(192, 168, 32, 1)
        ));
        assert!(!same_subnet_24(
            Ipv4Addr::new(10, 39, 123, 115),
            Ipv4Addr::new(192, 168, 31, 135)
        ));
    }

    /// 排序规则：同网段 IPv4 最优，其次其他 IPv4，IPv6 最后。
    /// 这是「对端同时通告局域网地址与蜂窝地址」时的正确选路依据。
    #[test]
    fn address_ranking_prefers_lan_ipv4() {
        let local = Ipv4Addr::new(192, 168, 31, 123);
        let rank = |ip: &IpAddr| -> u8 {
            match ip {
                IpAddr::V4(v4) => {
                    if same_subnet_24(local, *v4) {
                        0
                    } else {
                        1
                    }
                }
                IpAddr::V6(_) => 2,
            }
        };
        let lan = IpAddr::V4(Ipv4Addr::new(192, 168, 31, 135));
        let cell = IpAddr::V4(Ipv4Addr::new(10, 39, 123, 115));
        let v6 = IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
        assert!(rank(&lan) < rank(&cell), "同网段 IPv4 必须优先于蜂窝地址");
        assert!(rank(&cell) < rank(&v6), "IPv4 必须优先于 IPv6");

        // 混合候选集按 (rank, 字符串) 排序后，首位应是局域网地址
        let mut cands = vec![v6, cell, lan];
        cands.sort_by_key(|ip| (rank(ip), ip.to_string()));
        assert_eq!(cands[0], lan);
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

    // 地址选择：同一设备锁定一个地址，避免 device_ips 反复被覆盖。
    //
    // 说明：mDNS 为同一设备解析出多个地址（IPv4 / IPv6 / 链路本地）是正常现象，
    // 这里只需保证**本机记录的目标地址稳定**，不涉及对端可达性判定。
    // 优先同网段 IPv4，其次其他 IPv4，最后 IPv6——局域网直连最可靠。
    let candidates: Vec<std::net::IpAddr> = resolved
        .addresses
        .iter()
        .map(|a| a.to_ip_addr())
        .filter(|ip| match ip {
            std::net::IpAddr::V4(v4) => {
                !v4.is_loopback() && !v4.is_link_local() && !v4.is_unspecified()
            }
            std::net::IpAddr::V6(v6) => {
                !v6.is_loopback() && !v6.is_unspecified() && !v6.is_unicast_link_local()
            }
        })
        .collect();
    if candidates.is_empty() {
        log::debug!("mDNS 服务无可用地址，忽略: {}", uuid);
        return;
    }
    // 排序：同网段 IPv4 > 其他 IPv4 > IPv6（真可达性由建连阶段逐个尝试确认）
    let locals = crate::utils::local_ipv4_addrs();
    let rank = |ip: &std::net::IpAddr| -> u8 {
        match ip {
            std::net::IpAddr::V4(v4) => {
                if locals.iter().any(|l| same_subnet_24(*l, *v4)) {
                    0
                } else {
                    1
                }
            }
            std::net::IpAddr::V6(_) => 2,
        }
    };
    let mut ordered = candidates.clone();
    ordered.sort_by_key(|ip| (rank(ip), ip.to_string()));
    let addrs: Vec<String> = ordered.iter().map(|ip| ip.to_string()).collect();
    let ip = addrs[0].clone();

    let ctx = unsafe { &*(ctx_ptr as *const SafeContext) };
    // 记录全部候选地址：建连阶段逐个尝试，避免「挑中坏地址就彻底连不上」
    if let Ok(guard) = ctx.lock() {
        if let Ok(mut m) = guard.device_addrs.lock() {
            m.insert(uuid.to_string(), addrs.clone());
        }
    }

    log::debug!("mDNS 发现设备: uuid={}, ip={}", uuid, ip);
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
