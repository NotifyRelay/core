declare const NOTIFICATION_TYPE: {
    readonly ACTIVE: "Active";
    readonly REMOVED: "Removed";
    readonly NEW: "New";
    readonly ACTION: "Action";
    readonly INVOKE: "Invoke";
};
type NotificationType = typeof NOTIFICATION_TYPE[keyof typeof NOTIFICATION_TYPE];
declare const CATEGORY: {
    readonly TRANSPORT: "transport";
    readonly CALL: "call";
    readonly MESSAGE: "msg";
    readonly EMAIL: "email";
    readonly EVENT: "event";
    readonly PROMO: "promo";
    readonly ALARM: "alarm";
    readonly PROGRESS: "progress";
    readonly SOCIAL: "social";
    readonly ERROR: "err";
    readonly UNDEFINED: "undefined";
    readonly SYSTEM: "system";
};
type NotificationCategory = typeof CATEGORY[keyof typeof CATEGORY];
declare const PRIORITY_LEVEL: {
    readonly MIN: -2;
    readonly LOW: -1;
    readonly DEFAULT: 0;
    readonly HIGH: 1;
    readonly MAX: 2;
};
type PriorityLevel = typeof PRIORITY_LEVEL[keyof typeof PRIORITY_LEVEL];
interface NotificationMessage {
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
interface NotificationAction {
    id: number;
    title: string;
    iconHash?: string;
    requiresInput?: boolean;
    inputPlaceholder?: string;
    isLaunchAction?: boolean;
}
interface NotificationLaunchAction {
    pkgName: string;
    intentUri?: string;
}
interface SuperIslandState {
    title?: string;
    text?: string;
    paramV2Raw?: string;
    pics?: Record<string, string>;
    packageName?: string;
    appName?: string;
    time?: number;
    isLocked?: boolean;
}
interface SuperIslandDiff {
    title?: string | null;
    text?: string | null;
    paramV2Raw?: string | null;
    picsChanged?: Record<string, string>;
    picsRemoved?: string[];
}
declare const SUPERISLAND_TERMINATE_VALUE = "__END__";
interface SuperIslandMessage {
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
interface MediaPlayState {
    title?: string;
    text?: string;
    packageName?: string;
    coverUrl?: string;
    sentTime: number;
}
interface MediaPlayDiff {
    title?: string | null;
    text?: string | null;
    coverUrl?: string | null;
}
interface MediaPlayMessage {
    type: 'FULL' | 'DIFF' | 'END';
    title?: string;
    text?: string;
    packageName?: string;
    coverUrl?: string;
    sentTime: number;
    mediaType?: string;
    terminateValue?: string;
}

declare const DEVICE_TYPE: {
    readonly ANDROID: "android";
    readonly PC: "pc";
    readonly LINUX: "linux";
    readonly MACOS: "macos";
};
type DeviceType = typeof DEVICE_TYPE[keyof typeof DEVICE_TYPE];
declare const STATUS_TYPE: {
    readonly OK: "OK";
    readonly ERROR: "ERROR";
    readonly ACK: "ACK";
    readonly PONG: "PONG";
};
type StatusType = typeof STATUS_TYPE[keyof typeof STATUS_TYPE];

type RawMessageType = 'DATA' | 'DATA_NOTIFICATION' | 'DATA_SUPERISLAND' | 'DATA_MEDIAPLAY' | 'DATA_ICON_REQUEST' | 'DATA_ICON_RESPONSE' | 'DATA_APP_LIST_REQUEST' | 'DATA_APP_LIST_RESPONSE' | 'DATA_MEDIA_CONTROL' | 'DATA_CLIPBOARD' | 'DATA_FTP' | 'DATA_STATUS' | 'DATA_APP_LAUNCH' | 'DATA_AUDIO_REQUEST' | 'HANDSHAKE' | 'ACCEPT' | 'REJECT' | 'HEARTBEAT_TCP';
interface RawDataMessage {
    header: RawMessageType;
    senderUuid: string;
    senderPubKey: string;
    encryptedPayload: string;
}
interface ParsedHandshake {
    type: 'HANDSHAKE';
    uuid: string;
    publicKey: string;
    ipAddress: string;
    batteryLevel: number;
    isCharging: boolean;
    deviceType: string;
}
interface ParsedHeartbeat {
    type: 'HEARTBEAT_TCP';
    uuid: string;
    displayName: string;
    port: number;
    batteryStatus: string;
    deviceType: string;
}
type ParsedLine = ParsedHandshake | ParsedHeartbeat | {
    type: 'ACCEPT' | 'REJECT';
    uuid: string;
    reason?: string;
} | (RawDataMessage & {
    type: 'ENCRYPTED_DATA';
});
interface StatusMessage {
    type: StatusType;
    message?: string;
    data?: Record<string, string>;
    timestamp: number;
}
interface ClipboardMessage {
    text: string;
    timestamp: number;
    sourceDevice: string;
}
interface AppListRequest {
    deviceUuid: string;
    timestamp: number;
}
interface AppListResponse {
    deviceUuid: string;
    apps: AppInfo[];
    timestamp: number;
}
interface AppInfo {
    packageName: string;
    appName: string;
    versionName?: string;
    versionCode?: number;
    iconHash?: string;
    isSystemApp?: boolean;
    isEnabled?: boolean;
}
interface IconRequest {
    pkgName: string;
    iconHash: string;
    deviceUuid: string;
}
interface IconResponse {
    pkgName: string;
    iconHash: string;
    iconData: string;
    deviceUuid: string;
}
interface FtpMessage {
    action: 'START' | 'STOP';
    port?: number;
    username?: string;
    password?: string;
    rootDir?: string;
}
interface MediaControlMessage {
    action: 'PLAY' | 'PAUSE' | 'NEXT' | 'PREVIOUS' | 'STOP' | 'SEEK' | 'VOLUME_UP' | 'VOLUME_DOWN';
    value?: number;
    targetDevice?: string;
}
interface AppLaunchMessage {
    pkgName: string;
    intentUri?: string;
    sourceDevice: string;
    timestamp: number;
}
type MessageHandler<T = any> = (message: T, senderUuid: string) => void | Promise<void>;
interface RouterHandlerMap {
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

declare function encrypt(plaintext: string, key: string): string;
declare function decrypt(data: string, key: string): string;

declare function generateKeyPair(): {
    publicKey: string;
    privateKey: string;
};
declare function computeSharedSecret(privateKey: string, publicKey: string): string;

declare function hkdfDerive(localKey: string, remoteKey: string): string;

declare function computeFeatureId(superPkg: string, paramV2: string, instanceId?: string): string;
declare function diff$1(oldState: SuperIslandState, newState: SuperIslandState): SuperIslandDiff | null;
declare function buildFullPayload(featureId: string, state: SuperIslandState): Record<string, unknown>;
declare function buildDeltaPayload(featureId: string, state: SuperIslandState, diffObj: SuperIslandDiff): Record<string, unknown>;
declare function buildEndPayload(featureId: string, state?: SuperIslandState): Record<string, unknown>;
declare class SuperIslandSendManager {
    private lastState;
    private forceFull;
    updateAndGetPayload(deviceUuid: string, featureId: string, newState: SuperIslandState, forceFull?: boolean): {
        isFull: boolean;
        payload: Record<string, unknown> | null;
    };
    markForceFull(deviceUuid: string, featureId: string): void;
    ackReceived(deviceUuid: string, featureId: string): void;
}

declare function diffMediaPlay(oldState: MediaPlayState, newState: MediaPlayState): MediaPlayDiff | null;
declare function shouldSendFull(oldState: MediaPlayState | null, newState: MediaPlayState, lastSentTime: number): boolean;
declare function buildMediaPlayFull(state: MediaPlayState): Record<string, unknown>;
declare function buildMediaPlayDelta(diff: MediaPlayDiff): Record<string, unknown>;
declare function buildMediaPlayEnd(): Record<string, unknown>;

declare class RemoteStore {
    private store;
    applyIncoming(deviceUuid: string, featureId: string, rawData: Record<string, unknown>): SuperIslandState | null;
    applyDelta(oldState: SuperIslandState, changes: Record<string, unknown>): SuperIslandState;
    removeByDeviceAndPkgPrefix(prefix: string): void;
    getState(deviceUuid: string, featureId: string): SuperIslandState | undefined;
    getAllStates(): Map<string, Map<string, SuperIslandState>>;
}

declare function isDataHeader(header: string): boolean;
declare function isLinePrefix(prefix: string): boolean;

interface HandshakePayload {
    uuid: string;
    publicKey: string;
    ipAddress: string;
    batteryLevel: number;
    isCharging: boolean;
    deviceType: DeviceType;
}
interface HandshakeResponse {
    uuid: string;
    publicKey: string;
    ipAddress: string;
    batteryLevel: number;
    isCharging: boolean;
    deviceType: DeviceType;
    accepted: boolean;
    rejectReason?: string;
}
interface HeartbeatPayload {
    uuid: string;
    displayName: string;
    port: number;
    batteryLevel: number;
    deviceType: DeviceType;
    isCharging: boolean;
}

declare function parseLine(line: string): ParsedLine;
declare function parseDataLine(line: string): RawDataMessage;
declare function parseHandshake(payload: string): HandshakePayload;
declare function parseHeartbeat(line: string): HeartbeatPayload;
declare function encodeMessage(obj: unknown): string;
declare function decodeMessage<T>(str: string): T;

interface RouterHandlers extends RouterHandlerMap {
    onHandshake?: MessageHandler<HandshakePayload>;
    onAuthResponse?: MessageHandler<HandshakeResponse>;
    onHeartbeat?: MessageHandler<HeartbeatPayload>;
}
declare class ProtocolRouter {
    private handlers;
    constructor(handlers: RouterHandlers);
    routeLine(line: string): void | Promise<void>;
    routeData(header: string, payload: string, senderUuid: string): void | Promise<void>;
    setHandler<K extends keyof RouterHandlerMap>(key: K, handler: RouterHandlerMap[K]): void;
    removeHandler(key: keyof RouterHandlerMap): void;
}

declare class ProtocolSender {
    private sendCallback;
    constructor(sendCallback: (message: string) => void | Promise<void>);
    send(header: string, senderUuid: string, senderPubKey: string, encryptedPayload: string): void | Promise<void>;
    buildMessage(header: string, senderUuid: string, senderPubKey: string, encryptedPayload: string): string;
    setSendCallback(callback: (message: string) => void | Promise<void>): void;
}

type ProcessedNotificationType = 'normal' | 'media' | 'superisland' | 'unknown';
interface ProcessedNotification {
    type: ProcessedNotificationType;
    message: NotificationMessage | SuperIslandMessage | MediaPlayMessage | Record<string, unknown>;
    rawType: string;
    timestamp: number;
}
declare function classifyNotification(raw: Record<string, unknown>): ProcessedNotificationType;
declare function processNotification(raw: Record<string, unknown>): ProcessedNotification;
declare function extractMetadata(raw: Record<string, unknown>): {
    pkgName?: string;
    category?: string;
    isMedia: boolean;
    isSuperIsland: boolean;
    superPkg?: string;
    hasExtraPictures: boolean;
};
declare function computeDedupKey(notification: NotificationMessage): string;

interface FilterRule {
    type: 'whitelist' | 'blacklist';
    pattern: string;
    enabled: boolean;
}
interface FilterResult {
    allowed: boolean;
    matchedRule?: FilterRule;
    reason?: string;
}
declare class FilterEngine {
    private rules;
    private defaultAllowed;
    constructor(rules?: FilterRule[]);
    loadRules(rules: FilterRule[]): void;
    shouldForward(pkgName: string, notification?: NotificationMessage): FilterResult;
    private checkContentFilter;
    addRule(rule: FilterRule): void;
    removeRule(pattern: string): void;
    getRules(): FilterRule[];
}

interface LocalDeviceInfo {
    uuid: string;
    publicKey: string;
    deviceType: string;
    ipAddress: string;
    batteryLevel: number;
    isCharging: boolean;
    displayName?: string;
}
declare class CoreEngine {
    private localInfo;
    private sharedSecrets;
    private pendingHandshakes;
    private superIslandMgr;
    private remoteStore;
    private mediaLastState;
    setLocalInfo(infoJson: string): void;
    setSharedSecret(deviceUuid: string, secret: string): void;
    getSharedSecret(deviceUuid: string): string | null;
    removeSharedSecret(deviceUuid: string): void;
    processLine(line: string, connId: string, senderIp?: string): string;
    completeHandshake(connId: string, accepted: boolean, sharedSecret?: string): string;
    buildMessage(header: string, payloadJson: string, deviceUuid: string): string;
    buildSuperIslandData(deviceUuid: string, featureId: string, stateJson: string): string;
    buildSuperIslandEnd(deviceUuid: string, featureId: string, stateJson?: string): string;
    buildMediaPlayData(deviceUuid: string, stateJson: string): string;
    buildMediaPlayEnd(deviceUuid: string): string;
    handleSuperIslandAck(deviceUuid: string, featureId: string): void;
    getSuperIslandState(deviceUuid: string, featureId: string): string;
    private _handleHandshake;
    private _handleEncryptedData;
    private _routeDataAction;
    private _processSuperIsland;
    private _handleHeartbeat;
    private _handleAccept;
    private _encryptMessage;
    private _buildAcceptLine;
    private _parseBattery;
}

declare const crypto: {
    aesEncrypt: typeof encrypt;
    aesDecrypt: typeof decrypt;
    ecdhGenerateKeyPair: typeof generateKeyPair;
    ecdhDeriveSharedSecret: typeof computeSharedSecret;
    hkdfDerive: typeof hkdfDerive;
};
declare const diff: {
    superIsland: {
        computeFeatureId: typeof computeFeatureId;
        diff: typeof diff$1;
        buildFullPayload: typeof buildFullPayload;
        buildDeltaPayload: typeof buildDeltaPayload;
        buildEndPayload: typeof buildEndPayload;
        SuperIslandSendManager: typeof SuperIslandSendManager;
    };
    mediaPlay: {
        diffMediaPlay: typeof diffMediaPlay;
        shouldSendFull: typeof shouldSendFull;
        buildMediaPlayFull: typeof buildMediaPlayFull;
        buildMediaPlayDelta: typeof buildMediaPlayDelta;
        buildMediaPlayEnd: typeof buildMediaPlayEnd;
    };
    RemoteStore: typeof RemoteStore;
};
declare const protocol: {
    ROUTE_TABLE: Record<string, keyof RouterHandlerMap>;
    isDataHeader: typeof isDataHeader;
    isLinePrefix: typeof isLinePrefix;
    parseLine: typeof parseLine;
    parseDataLine: typeof parseDataLine;
    parseHandshake: typeof parseHandshake;
    parseHeartbeat: typeof parseHeartbeat;
    encodeMessage: typeof encodeMessage;
    decodeMessage: typeof decodeMessage;
    ProtocolRouter: typeof ProtocolRouter;
    ProtocolSender: typeof ProtocolSender;
};
declare const notification: {
    classifyNotification: typeof classifyNotification;
    processNotification: typeof processNotification;
    extractMetadata: typeof extractMetadata;
    computeDedupKey: typeof computeDedupKey;
    FilterEngine: typeof FilterEngine;
};

export { CoreEngine, crypto, diff, notification, protocol };
export type { LocalDeviceInfo };
