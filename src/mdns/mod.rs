use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use base64::Engine;
use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};

const MDNS_SERVICE_TYPE: &str = "_notifyrelay._tcp.local.";
pub struct MdnsState {
    daemon: Option<ServiceDaemon>,
    browse_handle: Option<thread::JoinHandle<()>>,
    browse_running: Option<Arc<AtomicBool>>,
}

impl MdnsState {
    pub fn new() -> Self {
        Self {
            daemon: None,
            browse_handle: None,
            browse_running: None,
        }
    }

    pub fn is_advertising(&self) -> bool {
        self.daemon.is_some()
    }

    pub fn start_advertiser(
        &mut self,
        uuid: &str,
        name: &str,
        port: u16,
        pubkey: &str,
        device_type: &str,
    ) -> Result<(), String> {
        if self.daemon.is_some() {
            log::warn!("mDNS 广告已在运行，跳过");
            return Ok(());
        }

        let daemon =
            ServiceDaemon::new().map_err(|e| format!("创建 mDNS 服务守护进程失败: {}", e))?;

        let name_b64 = base64::engine::general_purpose::STANDARD.encode(name.as_bytes());
        let mut properties = HashMap::new();
        properties.insert("uuid".to_string(), uuid.to_string());
        properties.insert("name".to_string(), name_b64);
        properties.insert("pubkey".to_string(), pubkey.to_string());
        properties.insert("device_type".to_string(), device_type.to_string());

        let service_info = ServiceInfo::new(
            MDNS_SERVICE_TYPE,
            uuid,
            "localhost.local.",
            &[] as &[std::net::IpAddr],
            port,
            properties,
        )
        .map_err(|e| format!("创建 mDNS 服务信息失败: {}", e))?;

        daemon
            .register(service_info)
            .map_err(|e| format!("注册 mDNS 服务失败: {}", e))?;

        log::info!(
            "mDNS 广告已启动: uuid={}, name={}, type={}",
            uuid,
            name,
            device_type
        );
        self.daemon = Some(daemon);
        Ok(())
    }

    pub fn stop_advertiser(&mut self) {
        if let Some(daemon) = self.daemon.take() {
            drop(daemon);
            log::info!("mDNS 广告已停止");
        }
    }

    pub fn start_browser(
        &mut self,
        _ctx_ptr: usize,
        on_discovered_cb: crate::router::OnMdnsDiscoveredCb,
        user_data: *mut std::os::raw::c_void,
    ) -> Result<(), String> {
        if self.browse_handle.is_some() {
            log::warn!("mDNS 浏览已在运行，跳过");
            return Ok(());
        }

        let daemon =
            ServiceDaemon::new().map_err(|e| format!("创建 mDNS 浏览守护进程失败: {}", e))?;

        let receiver = daemon
            .browse(MDNS_SERVICE_TYPE)
            .map_err(|e| format!("启动 mDNS 浏览失败: {}", e))?;

        let running = Arc::new(AtomicBool::new(true));
        let r = running.clone();
        let user_data_usize = user_data as usize;

        let handle = thread::Builder::new()
            .name("mdns-browser".to_string())
            .spawn(move || {
                let user_data_ptr = user_data_usize as *mut std::os::raw::c_void;
                while r.load(Ordering::Relaxed) {
                    match receiver.recv_timeout(Duration::from_millis(1000)) {
                        Ok(event) => match event {
                            ServiceEvent::ServiceResolved(info) => {
                                let uuid = info
                                    .get_property_val_str("uuid")
                                    .unwrap_or_default()
                                    .to_string();
                                let name_b64 = info
                                    .get_property_val_str("name")
                                    .unwrap_or_default()
                                    .to_string();
                                let device_type = info
                                    .get_property_val_str("device_type")
                                    .unwrap_or_default()
                                    .to_string();

                                if uuid.is_empty() {
                                    continue;
                                }

                                let name = String::from_utf8(
                                    base64::engine::general_purpose::STANDARD
                                        .decode(&name_b64)
                                        .unwrap_or_default(),
                                )
                                .unwrap_or(name_b64);

                                let ip = info
                                    .get_addresses_v4()
                                    .iter()
                                    .next()
                                    .map(|a| a.to_string())
                                    .unwrap_or_default();

                                let mdns_port = info.get_port();
                                let dt = device_type;

                                if let Some(cb) = on_discovered_cb {
                                    let uuid_c = std::ffi::CString::new(uuid).unwrap_or_default();
                                    let name_c = std::ffi::CString::new(name).unwrap_or_default();
                                    let ip_c = std::ffi::CString::new(ip).unwrap_or_default();
                                    let dt_c = std::ffi::CString::new(dt).unwrap_or_default();
                                    cb(
                                        uuid_c.as_ptr(),
                                        name_c.as_ptr(),
                                        ip_c.as_ptr(),
                                        mdns_port,
                                        dt_c.as_ptr(),
                                        user_data_ptr,
                                    );
                                }
                            }
                            ServiceEvent::ServiceRemoved(_, full_name) => {
                                log::debug!("mDNS 服务已移除: {}", full_name);
                            }
                            _ => {}
                        },
                        Err(_) => {
                            // 超时正常，继续循环检查退出标志
                            continue;
                        }
                    }
                }
                // 浏览器退出时，丢弃 receiver 以通知守护进程停止浏览
                drop(receiver);
                drop(daemon);
                log::debug!("mDNS 浏览线程已退出");
            })
            .map_err(|e| format!("启动 mDNS 浏览线程失败: {}", e))?;

        self.browse_handle = Some(handle);
        self.browse_running = Some(running);
        log::info!("mDNS 浏览已启动");
        Ok(())
    }

    pub fn stop_browser(&mut self) {
        if let Some(running) = self.browse_running.take() {
            running.store(false, Ordering::Relaxed);
        }
        if let Some(handle) = self.browse_handle.take() {
            let _ = handle.join();
        }
        log::info!("mDNS 浏览已停止");
    }
}
