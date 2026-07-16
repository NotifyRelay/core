use std::os::raw::c_void;

use super::common::{with_ctx};

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


make_cb_setter!(nrc_set_on_heartbeat_udp_cb, crate::router::OnHeartbeatUdpCb, on_heartbeat_udp);

make_cb_setter!(nrc_set_on_device_timeout_cb, crate::router::OnDeviceTimeoutCb, on_device_timeout);

// 网络层回调
make_cb_setter!(nrc_set_on_device_connected_cb, crate::router::OnDeviceConnectedCb, on_device_connected);
make_cb_setter!(nrc_set_on_device_disconnected_cb, crate::router::OnDeviceDisconnectedCb, on_device_disconnected);
make_cb_setter!(nrc_set_on_tcp_error_cb, crate::router::OnTcpErrorCb, on_tcp_error);

#[no_mangle]
pub extern "C" fn nrc_set_user_data(ctx_ptr: *mut c_void, user_data: *mut c_void) {
    with_ctx(ctx_ptr, |ctx| { ctx.router.user_data = user_data; });
}