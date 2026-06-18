import type {
  NotificationMessage,
  SuperIslandMessage,
  MediaPlayMessage,
} from './notification';
import type { StatusType } from './protocol';

export type RawMessageType =
  | 'DATA'
  | 'DATA_NOTIFICATION'
  | 'DATA_SUPERISLAND'
  | 'DATA_MEDIAPLAY'
  | 'DATA_ICON_REQUEST'
  | 'DATA_ICON_RESPONSE'
  | 'DATA_APP_LIST_REQUEST'
  | 'DATA_APP_LIST_RESPONSE'
  | 'DATA_MEDIA_CONTROL'
  | 'DATA_CLIPBOARD'
  | 'DATA_FTP'
  | 'DATA_STATUS'
  | 'DATA_APP_LAUNCH'
  | 'DATA_AUDIO_REQUEST'
  | 'HANDSHAKE'
  | 'ACCEPT'
  | 'REJECT'
  | 'HEARTBEAT_TCP';

export interface RawDataMessage {
  header: RawMessageType;
  senderUuid: string;
  senderPubKey: string;
  encryptedPayload: string;
}

export interface ParsedHandshake {
  type: 'HANDSHAKE';
  uuid: string;
  publicKey: string;
  ipAddress: string;
  batteryLevel: number;
  isCharging: boolean;
  deviceType: string;
}

export interface ParsedHeartbeat {
  type: 'HEARTBEAT_TCP';
  uuid: string;
  displayName: string;
  port: number;
  batteryStatus: string;
  deviceType: string;
}

export type ParsedLine =
  | ParsedHandshake
  | ParsedHeartbeat
  | { type: 'ACCEPT' | 'REJECT'; uuid: string; reason?: string }
  | (RawDataMessage & { type: 'ENCRYPTED_DATA' });

export interface StatusMessage {
  type: StatusType;
  message?: string;
  data?: Record<string, string>;
  timestamp: number;
}

export interface ClipboardMessage {
  text: string;
  timestamp: number;
  sourceDevice: string;
}

export interface AppListRequest {
  deviceUuid: string;
  timestamp: number;
}

export interface AppListResponse {
  deviceUuid: string;
  apps: AppInfo[];
  timestamp: number;
}

export interface AppInfo {
  packageName: string;
  appName: string;
  versionName?: string;
  versionCode?: number;
  iconHash?: string;
  isSystemApp?: boolean;
  isEnabled?: boolean;
}

export interface IconRequest {
  pkgName: string;
  iconHash: string;
  deviceUuid: string;
}

export interface IconResponse {
  pkgName: string;
  iconHash: string;
  iconData: string;
  deviceUuid: string;
}

export interface FtpMessage {
  action: 'START' | 'STOP';
  port?: number;
  username?: string;
  password?: string;
  rootDir?: string;
}

export interface MediaControlMessage {
  action: 'PLAY' | 'PAUSE' | 'NEXT' | 'PREVIOUS' | 'STOP' | 'SEEK' | 'VOLUME_UP' | 'VOLUME_DOWN';
  value?: number;
  targetDevice?: string;
}

export interface AppLaunchMessage {
  pkgName: string;
  intentUri?: string;
  sourceDevice: string;
  timestamp: number;
}

export type ProtocolMessage =
  | NotificationMessage
  | SuperIslandMessage
  | MediaPlayMessage
  | StatusMessage
  | ClipboardMessage
  | AppListRequest
  | AppListResponse
  | IconRequest
  | IconResponse
  | FtpMessage
  | MediaControlMessage
  | AppLaunchMessage;

export type MessageHandler<T = any> = (message: T, senderUuid: string) => void | Promise<void>;

export interface RouterHandlerMap {
  onNotification?: MessageHandler<NotificationMessage>;
  onSuperIsland?: MessageHandler<SuperIslandMessage>;
  onMediaPlay?: MessageHandler<MediaPlayMessage>;
  onStatus?: MessageHandler<StatusMessage>;
  onClipboard?: MessageHandler<ClipboardMessage>;
  onAppListRequest?: MessageHandler<AppListRequest>;
  onAppListResponse?: MessageHandler<AppListResponse>;
  onIconRequest?: MessageHandler<IconRequest>;
  onIconResponse?: MessageHandler<IconResponse>;
  onFtp?: MessageHandler<FtpMessage>;
  onMediaControl?: MessageHandler<MediaControlMessage>;
  onAppLaunch?: MessageHandler<AppLaunchMessage>;
}
