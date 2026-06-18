import type { NotificationMessage, MediaPlayMessage, SuperIslandMessage } from '../types/notification'
import { CATEGORY } from '../types/notification'

export type ProcessedNotificationType = 'normal' | 'media' | 'superisland' | 'unknown'

export interface ProcessedNotification {
  type: ProcessedNotificationType
  message: NotificationMessage | SuperIslandMessage | MediaPlayMessage | Record<string, unknown>
  rawType: string
  timestamp: number
}

export function classifyNotification(raw: Record<string, unknown>): ProcessedNotificationType {
  const pkgName = raw.pkgName as string | undefined
  const category = raw.category as string | undefined

  if (
    (pkgName && pkgName.toLowerCase().includes('media')) ||
    category === CATEGORY.TRANSPORT
  ) {
    return 'media'
  }

  if (
    raw.superPkg !== undefined ||
    raw.paramV2Raw !== undefined ||
    raw.featureId !== undefined
  ) {
    return 'superisland'
  }

  if (pkgName) {
    return 'normal'
  }

  return 'unknown'
}

export function processNotification(raw: Record<string, unknown>): ProcessedNotification {
  const type = classifyNotification(raw)
  const timestamp = Date.now()
  const rawType = (raw.type as string) || ''

  let message: NotificationMessage | SuperIslandMessage | MediaPlayMessage | Record<string, unknown>

  switch (type) {
    case 'media':
      message = {
        type: (raw.mediaType as MediaPlayMessage['type']) || 'FULL',
        title: raw.title as string | undefined,
        text: raw.text as string | undefined,
        packageName: raw.pkgName as string | undefined,
        coverUrl: raw.coverUrl as string | undefined,
        sentTime: (raw.sentTime as number) || timestamp,
      } as MediaPlayMessage
      break

    case 'superisland':
      message = {
        featureId: raw.featureId as string,
        deviceUuid: raw.deviceUuid as string,
        mappedPkg: (raw.mappedPkg as string) || (raw.pkgName as string),
        instanceId: raw.instanceId as string | undefined,
        timestamp,
        changes: raw.changes as SuperIslandMessage['changes'],
        terminateValue: raw.terminateValue as SuperIslandMessage['terminateValue'],
        featureKeyValue: raw.featureKeyValue as string | undefined,
        state: raw.state as SuperIslandMessage['state'],
      } as SuperIslandMessage
      break

    case 'normal':
      message = {
        type: rawType,
        pkgName: raw.pkgName as string,
        tag: (raw.tag as string) || '',
        key: (raw.key as string) || '',
        id: (raw.id as number) || 0,
        title: raw.title as string | undefined,
        text: raw.text as string | undefined,
        subText: raw.subText as string | undefined,
        category: raw.category as NotificationMessage['category'],
        timestamp,
      } as NotificationMessage
      break

    default:
      message = { ...raw }
      break
  }

  return { type, message, rawType, timestamp }
}

export function extractMetadata(raw: Record<string, unknown>): {
  pkgName?: string
  category?: string
  isMedia: boolean
  isSuperIsland: boolean
  superPkg?: string
  hasExtraPictures: boolean
} {
  const pkgName = raw.pkgName as string | undefined
  const category = raw.category as string | undefined
  const superPkg = raw.superPkg as string | undefined
  const pics = raw.pics as Record<string, string> | undefined
  const extraPictures = raw.extraPictures as string[] | undefined

  return {
    pkgName,
    category,
    isMedia: classifyNotification(raw) === 'media',
    isSuperIsland: classifyNotification(raw) === 'superisland',
    superPkg,
    hasExtraPictures: !!(pics && Object.keys(pics).length > 0) || !!(extraPictures && extraPictures.length > 0),
  }
}

export function computeDedupKey(notification: NotificationMessage): string {
  return `${notification.pkgName}|${notification.tag}|${notification.id}`
}
