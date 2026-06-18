export const NOTIFICATION_TYPE = {
  ACTIVE: 'Active',
  REMOVED: 'Removed',
  NEW: 'New',
  ACTION: 'Action',
  INVOKE: 'Invoke',
} as const;

export type NotificationType = typeof NOTIFICATION_TYPE[keyof typeof NOTIFICATION_TYPE];

export const CATEGORY = {
  TRANSPORT: 'transport',
  CALL: 'call',
  MESSAGE: 'msg',
  EMAIL: 'email',
  EVENT: 'event',
  PROMO: 'promo',
  ALARM: 'alarm',
  PROGRESS: 'progress',
  SOCIAL: 'social',
  ERROR: 'err',
  UNDEFINED: 'undefined',
  SYSTEM: 'system',
} as const;

export type NotificationCategory = typeof CATEGORY[keyof typeof CATEGORY];

export const PRIORITY_LEVEL = {
  MIN: -2,
  LOW: -1,
  DEFAULT: 0,
  HIGH: 1,
  MAX: 2,
} as const;

export type PriorityLevel = typeof PRIORITY_LEVEL[keyof typeof PRIORITY_LEVEL];

export interface NotificationMessage {
  type: NotificationType;
  pkgName: string;
  tag: string;
  key: string;
  id: number;
  title?: string;
  text?: string;
  subText?: string;
  category?: NotificationCategory;
  priority?: PriorityLevel;
  tickerText?: string;
  isGroup?: boolean;
  groupKey?: string;
  sortKey?: string;
  timestamp: number;
  iconHash?: string;
  largeIconHash?: string;
  hasExtraPicture?: boolean;
  extraPictures?: string[];
  actions?: NotificationAction[];
  launchAction?: NotificationLaunchAction;
}

export interface NotificationAction {
  id: number;
  title: string;
  iconHash?: string;
  requiresInput?: boolean;
  inputPlaceholder?: string;
  isLaunchAction?: boolean;
}

export interface NotificationLaunchAction {
  pkgName: string;
  intentUri?: string;
}

export interface SuperIslandState {
  title?: string;
  text?: string;
  paramV2Raw?: string;
  pics?: Record<string, string>;
  packageName?: string;
  appName?: string;
  time?: number;
  isLocked?: boolean;
}

export interface SuperIslandDiff {
  title?: string | null;
  text?: string | null;
  paramV2Raw?: string | null;
  picsChanged?: Record<string, string>;
  picsRemoved?: string[];
}

export const SUPERISLAND_TERMINATE_VALUE = '__END__';

export const SUPERISLAND_FEATURE_KEY = 'si_feature_id';

export interface SuperIslandMessage {
  featureId: string;
  deviceUuid: string;
  mappedPkg: string;
  instanceId?: string;
  timestamp: number;
  changes?: SuperIslandDiff;
  terminateValue?: typeof SUPERISLAND_TERMINATE_VALUE;
  featureKeyValue?: string;
  state?: SuperIslandState;
}

export interface MediaPlayState {
  title?: string;
  text?: string;
  packageName?: string;
  coverUrl?: string;
  sentTime: number;
}

export interface MediaPlayDiff {
  title?: string | null;
  text?: string | null;
  coverUrl?: string | null;
}

export interface MediaPlayMessage {
  type: 'FULL' | 'DIFF' | 'END';
  title?: string;
  text?: string;
  packageName?: string;
  coverUrl?: string;
  sentTime: number;
  mediaType?: string;
  terminateValue?: string;
}
