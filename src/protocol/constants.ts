import { DATA_HEADERS, LINE_PREFIX } from '../types/protocol'
import type { RouterHandlerMap } from '../types/message'

export const ROUTE_TABLE: Record<string, keyof RouterHandlerMap> = {
  'DATA': 'onNotification',
  'DATA_NOTIFICATION': 'onNotification',
  'DATA_SUPERISLAND': 'onSuperIsland',
  'DATA_MEDIAPLAY': 'onMediaPlay',
  'DATA_STATUS': 'onStatus',
  'DATA_CLIPBOARD': 'onClipboard',
  'DATA_APP_LIST_REQUEST': 'onAppListRequest',
  'DATA_APP_LIST_RESPONSE': 'onAppListResponse',
  'DATA_ICON_REQUEST': 'onIconRequest',
  'DATA_ICON_RESPONSE': 'onIconResponse',
  'DATA_FTP': 'onFtp',
  'DATA_MEDIA_CONTROL': 'onMediaControl',
  'DATA_APP_LAUNCH': 'onAppLaunch',
}

export function isDataHeader(header: string): boolean {
  return header in ROUTE_TABLE || Object.values(DATA_HEADERS).includes(header as any)
}

export function isLinePrefix(prefix: string): boolean {
  return Object.values(LINE_PREFIX).includes(prefix as any)
}
