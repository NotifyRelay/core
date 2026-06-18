export const PROTOCOL_VERSION = 1;

export const DATA_HEADERS = {
  NOTIFICATION: 'DATA_NOTIFICATION',
  SUPERISLAND: 'DATA_SUPERISLAND',
  MEDIAPLAY: 'DATA_MEDIAPLAY',
  ICON_REQUEST: 'DATA_ICON_REQUEST',
  ICON_RESPONSE: 'DATA_ICON_RESPONSE',
  APP_LIST_REQUEST: 'DATA_APP_LIST_REQUEST',
  APP_LIST_RESPONSE: 'DATA_APP_LIST_RESPONSE',
  MEDIA_CONTROL: 'DATA_MEDIA_CONTROL',
  CLIPBOARD: 'DATA_CLIPBOARD',
  FTP: 'DATA_FTP',
  STATUS: 'DATA_STATUS',
  APP_LAUNCH: 'DATA_APP_LAUNCH',
  AUDIO_REQUEST: 'DATA_AUDIO_REQUEST',
} as const;

export type DataHeader = typeof DATA_HEADERS[keyof typeof DATA_HEADERS];

export const LINE_PREFIX = {
  HANDSHAKE: 'HANDSHAKE',
  ACCEPT: 'ACCEPT',
  REJECT: 'REJECT',
  HEARTBEAT_TCP: 'HEARTBEAT_TCP',
} as const;

export type LinePrefix = typeof LINE_PREFIX[keyof typeof LINE_PREFIX];

export const DEVICE_TYPE = {
  ANDROID: 'android',
  PC: 'pc',
  LINUX: 'linux',
  MACOS: 'macos',
} as const;

export type DeviceType = typeof DEVICE_TYPE[keyof typeof DEVICE_TYPE];

export const MESSAGE_PRIORITY = {
  LOW: 0,
  NORMAL: 1,
  HIGH: 2,
  CRITICAL: 3,
} as const;

export type MessagePriority = typeof MESSAGE_PRIORITY[keyof typeof MESSAGE_PRIORITY];

export const STATUS_TYPE = {
  OK: 'OK',
  ERROR: 'ERROR',
  ACK: 'ACK',
  PONG: 'PONG',
} as const;

export type StatusType = typeof STATUS_TYPE[keyof typeof STATUS_TYPE];
