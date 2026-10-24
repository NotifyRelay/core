//! 音频、剪贴板、状态合并与应用同步（带上下文）的委托实现。

use super::conv::{cs, take_cstr};
use super::Core;

#[uniffi::export]
impl Core {
    // ===== 音频 =====

    /// 启动音频流。`direction` 为 "send" 或 "recv"。
    pub fn audio_start(
        &self,
        direction: String,
        port: i32,
        sample_rate: i32,
        channels: i32,
        remote_uuid: String,
    ) -> i32 {
        let d = cs(&direction);
        let u = cs(&remote_uuid);
        unsafe {
            crate::ffi::audio_stream::nrc_audio_start(
                self.ctx_ptr(),
                d.as_ptr(),
                port,
                sample_rate,
                channels,
                u.as_ptr(),
            )
        }
    }

    /// 写入一帧 PCM 数据。
    pub fn audio_write_frame(&self, pcm_data: Vec<u8>) -> i32 {
        if pcm_data.is_empty() {
            return -1;
        }
        unsafe {
            crate::ffi::audio_stream::nrc_audio_write_frame(
                self.ctx_ptr(),
                pcm_data.as_ptr(),
                pcm_data.len() as i32,
            )
        }
    }

    /// 停止音频流。
    pub fn audio_stop(&self) -> i32 {
        crate::ffi::audio_stream::nrc_audio_stop(self.ctx_ptr())
    }

    /// 音频流是否活跃。
    pub fn audio_is_active(&self) -> i32 {
        crate::ffi::audio_stream::nrc_audio_is_active(self.ctx_ptr())
    }

    // ===== 剪贴板 =====

    /// 剪贴板内容变更：构造并发送到指定目标设备集合。
    pub fn clipboard_on_changed(
        &self,
        targets_json: String,
        mime: String,
        content: String,
        now_ms: i64,
        force: bool,
    ) -> Option<String> {
        let queue = self.queue_handle();
        let t = cs(&targets_json);
        let m = cs(&mime);
        let c = cs(&content);
        unsafe {
            take_cstr(crate::ffi::clipboard::nrc_clipboard_on_changed(
                self.ctx_ptr(),
                queue,
                t.as_ptr(),
                m.as_ptr(),
                c.as_ptr(),
                now_ms,
                if force { 1 } else { 0 },
            ))
        }
    }

    /// 剪贴板内容接收。
    pub fn clipboard_on_received(&self, payload_json: String, now_ms: i64) -> Option<String> {
        let p = cs(&payload_json);
        unsafe {
            take_cstr(crate::ffi::clipboard::nrc_clipboard_on_received(
                self.ctx_ptr(),
                p.as_ptr(),
                now_ms,
            ))
        }
    }

    // ===== 状态合并推送 =====

    /// 推送超级岛全量状态；`is_query` 为真表示响应状态查询。
    pub fn push_superisland_state(
        &self,
        device_uuid: String,
        full_json: String,
        is_end: bool,
        is_query: bool,
    ) -> bool {
        let queue = self.queue_handle();
        let u = cs(&device_uuid);
        let f = cs(&full_json);
        crate::ffi::state_merge::nrc_push_superisland_state(
            self.ctx_ptr(),
            queue,
            u.as_ptr(),
            f.as_ptr(),
            if is_end { 1 } else { 0 },
            if is_query { 1 } else { 0 },
        ) == 0
    }

    /// 推送媒体全量状态；`is_query` 为真表示响应状态查询。
    pub fn push_media_state(
        &self,
        device_uuid: String,
        full_json: String,
        is_end: bool,
        is_query: bool,
    ) -> bool {
        let queue = self.queue_handle();
        let u = cs(&device_uuid);
        let f = cs(&full_json);
        crate::ffi::state_merge::nrc_push_media_state(
            self.ctx_ptr(),
            queue,
            u.as_ptr(),
            f.as_ptr(),
            if is_end { 1 } else { 0 },
            if is_query { 1 } else { 0 },
        ) == 0
    }

    // ===== 应用同步 =====

    /// 批量过滤并构造图标请求报文（维护 pending 状态与超时清理）。
    #[allow(clippy::too_many_arguments)]
    pub fn app_sync_prepare_icon_request(
        &self,
        packages_json: String,
        installed_json: String,
        cached_json: String,
        app_device_json: String,
        source_device_uuid: String,
        now_ms: i64,
    ) -> Option<String> {
        let a = cs(&packages_json);
        let b = cs(&installed_json);
        let c = cs(&cached_json);
        let d = cs(&app_device_json);
        let e = cs(&source_device_uuid);
        unsafe {
            take_cstr(crate::ffi::app_sync::nrc_app_sync_prepare_icon_request(
                self.ctx_ptr(),
                a.as_ptr(),
                b.as_ptr(),
                c.as_ptr(),
                d.as_ptr(),
                e.as_ptr(),
                now_ms,
            ))
        }
    }

    /// 图标请求聚合入口：先解除同批包名的旧登记，再过滤并构造报文。
    #[allow(clippy::too_many_arguments)]
    pub fn app_sync_request_icons(
        &self,
        packages_json: String,
        installed_json: String,
        cached_json: String,
        app_device_json: String,
        source_device_uuid: String,
        now_ms: i64,
    ) -> Option<String> {
        let a = cs(&packages_json);
        let b = cs(&installed_json);
        let c = cs(&cached_json);
        let d = cs(&app_device_json);
        let e = cs(&source_device_uuid);
        unsafe {
            take_cstr(crate::ffi::app_sync::nrc_app_sync_request_icons(
                self.ctx_ptr(),
                a.as_ptr(),
                b.as_ptr(),
                c.as_ptr(),
                d.as_ptr(),
                e.as_ptr(),
                now_ms,
            ))
        }
    }

    /// 清除已完成的图标请求登记。
    pub fn app_sync_clear_icon_pending(&self, packages_json: String) {
        let p = cs(&packages_json);
        unsafe { crate::ffi::app_sync::nrc_app_sync_clear_icon_pending(self.ctx_ptr(), p.as_ptr()) }
    }
}
