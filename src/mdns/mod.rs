use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use base64::Engine;
use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};

const MDNS_SERVICE_TYPE: &str = "_notifyrelay._tcp.local.";

/// 广告参数（保存用于电量变化时重建广告）
#[derive(Clone)]
struct AdvertiseParams {
    uuid: String,
    name: String,
    port: u16,
    pubkey: String,
    device_type: String,
    battery: i32,
}

pub struct MdnsState {
    daemon: Option<ServiceDaemon>,
    browse_handle: Option<thread::JoinHandle<()>>,
    browse_running: Option<Arc<AtomicBool>>,
    advertise_params: Option<AdvertiseParams>,
}

impl MdnsState {
    pub fn new() -> Self {
        Self {
            daemon: None,
            browse_handle: None,
            browse_running: None,
            advertise_params: None,
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
        battery: i32,
    ) -> Result<(), String> {
        if self.daemon.is_some() {
            return Ok(());
        }
        let params = AdvertiseParams {
            uuid: uuid.to_string(),
            name: name.to_string(),
            port,
            pubkey: pubkey.to_string(),
            device_type: device_type.to_string(),
            battery,
        };
        self.start_advertiser_inner(&params)?;
        self.advertise_params = Some(params);
        Ok(())
    }

    /// 更新广告携带的电量（未知值跳过；电量相同跳过；否则重注册广告使 TXT 生效）
    pub fn update_battery(&mut self, battery: i32) {
        if battery.abs() > 100 {
            return;
        }
        let Some(params) = self.advertise_params.as_ref() else {
            return;
        };
        if params.battery == battery {
            return;
        }
        let params = params.clone();
        match self.start_advertiser_inner(&AdvertiseParams {
            battery,
            ..params.clone()
        }) {
            Ok(_) => {
                if let Some(p) = self.advertise_params.as_mut() {
                    p.battery = battery;
                }
            }
            Err(e) => log::error!("更新 mDNS 广告电量失败: {}", e),
        }
    }

    /// 更新广告携带的名称与电量（未知值跳过；未变化跳过；否则重注册广告使 TXT 生效）
    pub fn update_name_battery(&mut self, name: &str, battery: i32) {
        let Some(params) = self.advertise_params.as_ref() else {
            return;
        };
        if name.is_empty() && battery.abs() > 100 {
            return;
        }
        if params.battery == battery && params.name == name {
            return;
        }
        let params = params.clone();
        let new_name = if name.is_empty() {
            params.name.clone()
        } else {
            name.to_string()
        };
        let new_battery = if battery.abs() > 100 {
            params.battery
        } else {
            battery
        };
        match self.start_advertiser_inner(&AdvertiseParams {
            name: new_name.clone(),
            battery: new_battery,
            ..params
        }) {
            Ok(_) => {
                if let Some(p) = self.advertise_params.as_mut() {
                    p.name = new_name;
                    p.battery = new_battery;
                }
            }
            Err(e) => log::error!("更新 mDNS 广告名称失败: {}", e),
        }
    }

    fn start_advertiser_inner(&mut self, params: &AdvertiseParams) -> Result<(), String> {
        // 复用已有 daemon：mdns_sd 同名 register 会覆盖并重新宣告，避免每次重建泄漏线程
        if self.daemon.is_none() {
            let daemon =
                ServiceDaemon::new().map_err(|e| format!("创建 mDNS 服务守护进程失败: {}", e))?;
            self.daemon = Some(daemon);
        }

        let name_b64 = base64::engine::general_purpose::STANDARD.encode(params.name.as_bytes());
        let mut properties = HashMap::new();
        properties.insert("uuid".to_string(), params.uuid.clone());
        properties.insert("name".to_string(), name_b64);
        properties.insert("pubkey".to_string(), params.pubkey.clone());
        properties.insert("device_type".to_string(), params.device_type.clone());
        properties.insert("battery".to_string(), params.battery.to_string());

        let service_info = ServiceInfo::new(
            MDNS_SERVICE_TYPE,
            &params.uuid,
            "localhost.local.",
            &[] as &[std::net::IpAddr],
            params.port,
            properties,
        )
        .map_err(|e| format!("创建 mDNS 服务信息失败: {}", e))?;

        self.daemon
            .as_ref()
            .unwrap()
            .register(service_info)
            .map_err(|e| format!("注册 mDNS 服务失败: {}", e))
    }

    pub fn stop_advertiser(&mut self) {
        if let Some(daemon) = self.daemon.take() {
            if let Ok(status_rx) = daemon.shutdown() {
                let _ = status_rx.recv_timeout(Duration::from_secs(2));
            }
            drop(daemon);
        }
        self.advertise_params = None;
    }

    pub fn start_browser(
        &mut self,
        ctx_ptr: usize,
        on_discovered_cb: crate::router::OnMdnsDiscoveredCb,
        user_data: *mut std::os::raw::c_void,
    ) -> Result<(), String> {
        if self.browse_handle.is_some() {
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

                                // 过滤本机自身广告（同机浏览器会收到本机广播的回环），
                                // 防止本机被登记为远程设备导致自我连接/自我发送循环
                                if ctx_ptr != 0 {
                                    if let Ok(ctx) =
                                        unsafe { &mut *(ctx_ptr as *mut crate::SafeContext) }
                                            .get_mut()
                                    {
                                        let local_uuid = ctx
                                            .broadcast_info
                                            .as_ref()
                                            .map(|b| b.uuid.clone())
                                            .unwrap_or_default();
                                        if !local_uuid.is_empty() && uuid == local_uuid {
                                            continue;
                                        }
                                    }
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
                                let battery = info
                                    .get_property_val_str("battery")
                                    .and_then(|s| s.parse::<i32>().ok())
                                    .unwrap_or(crate::device_registry::BATTERY_UNKNOWN);

                                // mDNS 发现：登记设备状态（广告 TXT 携带电量，缺失时为未知 -101）
                                if ctx_ptr != 0 {
                                    if let Ok(ctx) =
                                        unsafe { &mut *(ctx_ptr as *mut crate::SafeContext) }
                                            .get_mut()
                                    {
                                        ctx.registry
                                            .upsert(&uuid, &name, &ip, mdns_port, battery, &dt);
                                    }
                                }

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
                                        battery,
                                        dt_c.as_ptr(),
                                        user_data_ptr,
                                    );
                                }
                            }
                            ServiceEvent::ServiceRemoved(_, _) => {}
                            _ => {}
                        },
                        Err(_) => {
                            // 超时正常，继续循环检查退出标志
                            continue;
                        }
                    }
                }
                // 浏览器退出时，先优雅关闭守护进程（仅 drop 无法终止 mdns_sd 内部线程），
                // 再丢弃 receiver 以通知守护进程停止浏览
                if let Ok(status_rx) = daemon.shutdown() {
                    let _ = status_rx.recv_timeout(Duration::from_secs(2));
                }
                drop(receiver);
                drop(daemon);
            })
            .map_err(|e| format!("启动 mDNS 浏览线程失败: {}", e))?;

        self.browse_handle = Some(handle);
        self.browse_running = Some(running);
        Ok(())
    }

    pub fn stop_browser(&mut self) {
        if let Some(running) = self.browse_running.take() {
            running.store(false, Ordering::Relaxed);
        }
        if let Some(handle) = self.browse_handle.take() {
            let _ = handle.join();
        }
    }
}
