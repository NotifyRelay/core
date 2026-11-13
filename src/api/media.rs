//! 音频、剪贴板、状态合并与应用同步的导出实现。

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
        crate::audio_stream::start(
            self.ctx(),
            &direction,
            port,
            sample_rate,
            channels,
            &remote_uuid,
        )
    }

    /// 写入一帧 PCM 数据。
    pub fn audio_write_frame(&self, pcm_data: Vec<u8>) -> i32 {
        crate::audio_stream::write_pcm_frame(self.ctx(), &pcm_data)
    }

    /// 停止音频流。
    pub fn audio_stop(&self) -> i32 {
        crate::audio_stream::stop_stream(self.ctx())
    }

    /// 音频流是否活跃。
    pub fn audio_is_active(&self) -> i32 {
        i32::from(crate::audio_stream::is_active(self.ctx()))
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
        if queue == 0 {
            return Some(r#"{"action":"skipped","reason":"invalid ctx or queue"}"#.to_string());
        }
        Some(crate::clipboard::on_changed_for(
            self.ctx_ptr() as usize,
            queue,
            &targets_json,
            &mime,
            &content,
            now_ms,
            force,
        ))
    }

    /// 剪贴板内容接收。
    pub fn clipboard_on_received(&self, payload_json: String, now_ms: i64) -> Option<String> {
        Some(crate::clipboard::on_received_for(
            self.ctx_ptr() as usize,
            &payload_json,
            now_ms,
        ))
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
        crate::state_merge::push_state(
            self.ctx_ptr() as usize,
            self.queue_handle(),
            &device_uuid,
            &full_json,
            is_end,
            is_query,
            false,
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
        crate::state_merge::push_state(
            self.ctx_ptr() as usize,
            self.queue_handle(),
            &device_uuid,
            &full_json,
            is_end,
            is_query,
            true,
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
        Some(crate::app_sync::request_icons_for(
            self.ctx_ptr() as usize,
            &packages_json,
            &installed_json,
            &cached_json,
            &app_device_json,
            &source_device_uuid,
            now_ms,
            false,
        ))
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
        Some(crate::app_sync::request_icons_for(
            self.ctx_ptr() as usize,
            &packages_json,
            &installed_json,
            &cached_json,
            &app_device_json,
            &source_device_uuid,
            now_ms,
            true,
        ))
    }

    /// 清除已完成的图标请求登记。
    pub fn app_sync_clear_icon_pending(&self, packages_json: String) {
        crate::app_sync::clear_icon_pending_for(self.ctx_ptr() as usize, &packages_json);
    }
}
