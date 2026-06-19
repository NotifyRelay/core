export type ActionType =
  | 'handshake_request'
  | 'notification'
  | 'super_island'
  | 'media_play'
  | 'clipboard'
  | 'heartbeat'
  | 'device_connected'
  | 'device_disconnected'
  | 'device_discovered'
  | 'app_list_request'
  | 'app_list_response'
  | 'icon_request'
  | 'icon_response'
  | 'media_control'
  | 'ftp_message'
  | 'app_launch'
  | 'status_response'
  | 'send_line'
  | 'send_data'
  | 'set_shared_secret'
  | 'noop';

export interface Action {
  type: ActionType;
  connId?: string;
  data?: Record<string, unknown>;
  line?: string;
  targetUuid?: string;
  senderUuid?: string;
  message?: Record<string, unknown>;
  deviceUuid?: string;
  sharedSecret?: string;
  [key: string]: unknown;
}

export function action(type: ActionType, extra?: Record<string, unknown>): Action {
  return { type, ...extra };
}
