import type { SuperIslandState, MediaPlayState } from '../types/notification';
import type { HandshakePayload } from '../types/device';
import { computeFeatureId, buildEndPayload, SuperIslandSendManager } from '../diff/superisland';
import { diffMediaPlay, buildMediaPlayFull, buildMediaPlayDelta, buildMediaPlayEnd } from '../diff/mediaplay';
import { RemoteStore } from '../diff/store';
import { parseLine } from '../protocol/codec';
import { SUPERISLAND_TERMINATE_VALUE } from '../types/notification';
import type { Action } from './ActionTypes';
import { action } from './ActionTypes';

export interface LocalDeviceInfo {
  uuid: string;
  publicKey: string;
  deviceType: string;
  ipAddress: string;
  batteryLevel: number;
  isCharging: boolean;
  displayName?: string;
}

interface HandshakeState {
  handshake: HandshakePayload;
  timestamp: number;
}

export class CoreEngine {
  private localInfo: LocalDeviceInfo | null = null;
  private sharedSecrets: Map<string, string> = new Map();
  private pendingHandshakes: Map<string, HandshakeState> = new Map();
  private superIslandMgr = new SuperIslandSendManager();
  private remoteStore = new RemoteStore();
  private mediaLastState: Map<string, Map<string, MediaPlayState>> = new Map();

  // ==================== Lifecycle ====================

  setLocalInfo(infoJson: string): void {
    this.localInfo = JSON.parse(infoJson) as LocalDeviceInfo;
  }

  // ==================== Device management ====================

  setSharedSecret(deviceUuid: string, secret: string): void {
    this.sharedSecrets.set(deviceUuid, secret);
  }

  getSharedSecret(deviceUuid: string): string | null {
    return this.sharedSecrets.get(deviceUuid) || null;
  }

  removeSharedSecret(deviceUuid: string): void {
    this.sharedSecrets.delete(deviceUuid);
  }

  // ==================== Incoming line processing ====================

  processLine(line: string, connId: string, senderIp?: string): string {
    try {
      const parsed = parseLine(line);

      switch (parsed.type) {
        case 'HANDSHAKE':
          return JSON.stringify(this._handleHandshake(parsed as unknown as HandshakePayload & { type: 'HANDSHAKE' }, connId));
        case 'ENCRYPTED_DATA':
          return JSON.stringify(this._handleEncryptedData(parsed, senderIp));
        case 'HEARTBEAT_TCP':
          return JSON.stringify(this._handleHeartbeat(parsed, senderIp));
        case 'ACCEPT':
          return JSON.stringify(this._handleAccept(parsed));
        case 'REJECT':
          return JSON.stringify([action('noop')]);
        default:
          return JSON.stringify([action('noop')]);
      }
    } catch {
      return JSON.stringify([action('noop')]);
    }
  }

  completeHandshake(connId: string, accepted: boolean, sharedSecret?: string): string {
    try {
      const pending = this.pendingHandshakes.get(connId);
      if (!pending) return JSON.stringify([action('noop')]);

      this.pendingHandshakes.delete(connId);

      if (!this.localInfo) return JSON.stringify([action('noop')]);

      if (accepted) {
        const secret = sharedSecret;
        if (!secret) {
          return JSON.stringify([action('noop')]);
        }

        this.sharedSecrets.set(pending.handshake.uuid, secret);

        const results: Action[] = [
          action('send_line', { connId, line: this._buildAcceptLine() }),
          action('set_shared_secret', { deviceUuid: pending.handshake.uuid, sharedSecret: secret }),
          action('device_connected', {
            deviceUuid: pending.handshake.uuid,
            data: {
              uuid: pending.handshake.uuid,
              publicKey: pending.handshake.publicKey,
              ipAddress: pending.handshake.ipAddress,
              batteryLevel: pending.handshake.batteryLevel,
              isCharging: pending.handshake.isCharging,
              deviceType: pending.handshake.deviceType,
            },
          }),
        ];
        return JSON.stringify(results);
      }

      return JSON.stringify([action('send_line', { connId, line: `REJECT:${this.localInfo.uuid}\n` })]);
    } catch {
      return JSON.stringify([action('noop')]);
    }
  }

  // ==================== Message building ====================

  buildMessage(header: string, payloadJson: string, deviceUuid: string): string {
    try {
      const payload = JSON.parse(payloadJson);
      const line = this._encryptMessage(header, payload, deviceUuid);
      return line || '';
    } catch {
      return '';
    }
  }

  buildSuperIslandData(deviceUuid: string, featureId: string, stateJson: string): string {
    try {
      const state = JSON.parse(stateJson) as SuperIslandState;
      const result = this.superIslandMgr.updateAndGetPayload(deviceUuid, featureId, state);
      if (!result.payload) return '';
      return this._encryptMessage('DATA_SUPERISLAND', result.payload, deviceUuid) || '';
    } catch {
      return '';
    }
  }

  buildSuperIslandEnd(deviceUuid: string, featureId: string, stateJson?: string): string {
    try {
      const state = stateJson ? JSON.parse(stateJson) as SuperIslandState : undefined;
      this.superIslandMgr.markForceFull(deviceUuid, featureId);
      const payload = buildEndPayload(featureId, state);
      return this._encryptMessage('DATA_SUPERISLAND', payload, deviceUuid) || '';
    } catch {
      return '';
    }
  }

  buildMediaPlayData(deviceUuid: string, stateJson: string): string {
    try {
      const state = JSON.parse(stateJson) as MediaPlayState;
      const mediaKey = 'global_media_session';

      if (!this.mediaLastState.has(deviceUuid)) {
        this.mediaLastState.set(deviceUuid, new Map());
      }
      const deviceMap = this.mediaLastState.get(deviceUuid)!;
      const lastState = deviceMap.get(mediaKey);
      const now = Date.now();

      const diff = lastState ? diffMediaPlay(lastState, state) : null;
      const needFull = !lastState || (diff?.coverUrl !== undefined && diff.coverUrl !== null)
        || (now - (lastState.sentTime || 0) > 6000);

      let payload: Record<string, unknown>;
      if (needFull) {
        payload = buildMediaPlayFull(state);
      } else if (diff) {
        payload = buildMediaPlayDelta(diff);
      } else {
        return '';
      }

      deviceMap.set(mediaKey, { ...state, sentTime: now });
      return this._encryptMessage('DATA_MEDIAPLAY', payload, deviceUuid) || '';
    } catch {
      return '';
    }
  }

  buildMediaPlayEnd(deviceUuid: string): string {
    try {
      if (this.mediaLastState.has(deviceUuid)) {
        this.mediaLastState.get(deviceUuid)!.delete('global_media_session');
      }
      const payload = buildMediaPlayEnd();
      return this._encryptMessage('DATA_MEDIAPLAY', payload, deviceUuid) || '';
    } catch {
      return '';
    }
  }

  // ==================== ACK handling ====================

  handleSuperIslandAck(deviceUuid: string, featureId: string): void {
    try {
      this.superIslandMgr.ackReceived(deviceUuid, featureId);
    } catch {
      // ignore
    }
  }

  getSuperIslandState(deviceUuid: string, featureId: string): string {
    try {
      const state = this.remoteStore.getState(deviceUuid, featureId);
      return state ? JSON.stringify(state) : '';
    } catch {
      return '';
    }
  }

  // ==================== Private: Handshake ====================

  private _handleHandshake(parsed: HandshakePayload & { type: 'HANDSHAKE' }, connId: string): Action[] {
    if (!this.localInfo) return [action('noop')];

    const existingSecret = this.sharedSecrets.get(parsed.uuid);
    if (existingSecret) {
      return [
        action('send_line', { connId, line: this._buildAcceptLine() }),
        action('device_connected', {
          deviceUuid: parsed.uuid,
          data: {
            uuid: parsed.uuid,
            publicKey: parsed.publicKey,
            ipAddress: parsed.ipAddress,
            batteryLevel: parsed.batteryLevel,
            isCharging: parsed.isCharging,
            deviceType: parsed.deviceType,
          },
        }),
      ];
    }

    this.pendingHandshakes.set(connId, { handshake: parsed, timestamp: Date.now() });
    return [action('handshake_request', {
      connId,
      data: {
        remoteUuid: parsed.uuid,
        remotePubKey: parsed.publicKey,
        remoteIp: parsed.ipAddress,
        remoteBattery: parsed.batteryLevel,
        remoteIsCharging: parsed.isCharging,
        remoteDeviceType: parsed.deviceType,
        displayName: parsed.uuid,
      },
    })];
  }

  // ==================== Private: Encrypted data ====================

  private _handleEncryptedData(parsed: { header: string; senderUuid: string; encryptedPayload: string }, _senderIp?: string): Action[] {
    const payload = parsed.encryptedPayload;
    const header = parsed.header;
    const senderUuid = parsed.senderUuid;

    switch (header) {
      case 'DATA':
      case 'DATA_NOTIFICATION':
        return this._routeDataAction('notification', payload, senderUuid);

      case 'DATA_SUPERISLAND':
        return this._processSuperIsland(payload, senderUuid);

      case 'DATA_MEDIAPLAY':
        return this._routeDataAction('media_play', payload, senderUuid);

      case 'DATA_CLIPBOARD':
        return this._routeDataAction('clipboard', payload, senderUuid);

      case 'DATA_ICON_REQUEST':
        return this._routeDataAction('icon_request', payload, senderUuid);

      case 'DATA_ICON_RESPONSE':
        return this._routeDataAction('icon_response', payload, senderUuid);

      case 'DATA_APP_LIST_REQUEST':
        return this._routeDataAction('app_list_request', payload, senderUuid);

      case 'DATA_APP_LIST_RESPONSE':
        return this._routeDataAction('app_list_response', payload, senderUuid);

      case 'DATA_MEDIA_CONTROL':
        return this._routeDataAction('media_control', payload, senderUuid);

      case 'DATA_FTP':
        return this._routeDataAction('ftp_message', payload, senderUuid);

      case 'DATA_APP_LAUNCH':
        return this._routeDataAction('app_launch', payload, senderUuid);

      case 'DATA_STATUS':
        return this._routeDataAction('status_response', payload, senderUuid);

      default:
        return [action('noop')];
    }
  }

  private _routeDataAction(actionType: string, decrypted: string, senderUuid: string): Action[] {
    try {
      const message = JSON.parse(decrypted);
      return [action(actionType as any, { senderUuid, message })];
    } catch {
      return [action('noop')];
    }
  }

  // ==================== Private: SuperIsland processor ====================

  private _processSuperIsland(decrypted: string, senderUuid: string): Action[] {
    try {
      const json = JSON.parse(decrypted);
      const siType = json.type || '';

      if (siType === 'SI_ACK') {
        const featureId = json.featureKeyValue || '';
        if (featureId) {
          this.superIslandMgr.ackReceived(senderUuid, featureId);
        }
        return [action('noop')];
      }

      const pkg = json.packageName || '';
      const paramV2Raw = json.param_v2_raw || '';
      const termVal = json.terminateValue || '';
      const explicitFeatureKey = json.featureKeyValue || '';
      const isEnd = termVal === SUPERISLAND_TERMINATE_VALUE;

      const featureId = explicitFeatureKey || computeFeatureId(pkg, paramV2Raw);
      const sourceKey = [senderUuid, pkg, featureId].filter(Boolean).join('|');

      if (isEnd) {
        this.remoteStore.applyIncoming(senderUuid, featureId, json);
        return [action('super_island', {
          senderUuid,
          message: { ...json, featureId, sourceKey, isEnd: true },
        })];
      }

      this.remoteStore.applyIncoming(senderUuid, featureId, json);

      const actions: Action[] = [];

      const recvHash = json.hash || '';
      if (recvHash) {
        const ackPayload = {
          originalHeader: 'DATA_SUPERISLAND',
          result: 'success',
          action: 'SI_ACK',
          hash: recvHash,
          featureKeyName: 'si_feature_id',
          featureKeyValue: featureId,
        };
        const ackLine = this._encryptMessage('DATA_STATUS', ackPayload, senderUuid);
        if (ackLine) {
          actions.push(action('send_data', { targetUuid: senderUuid, line: ackLine }));
        }
      }

      actions.push(action('super_island', {
        senderUuid,
        message: { ...json, featureId, sourceKey, isEnd: false },
      }));

      return actions;
    } catch {
      return [action('noop')];
    }
  }

  // ==================== Private: Heartbeat ====================

  private _handleHeartbeat(parsed: { uuid: string; displayName: string; port: number; batteryStatus: string; deviceType: string }, senderIp?: string): Action[] {
    try {
      const battery = this._parseBattery(parsed.batteryStatus);
      return [action('heartbeat', {
        data: {
          uuid: parsed.uuid,
          displayName: parsed.displayName,
          port: parsed.port,
          ip: senderIp || '',
          batteryLevel: battery.level,
          isCharging: battery.isCharging,
          deviceType: parsed.deviceType,
        },
      })];
    } catch {
      return [action('noop')];
    }
  }

  // ==================== Private: Accept ====================

  private _handleAccept(parsed: { uuid: string }): Action[] {
    return [action('device_connected', {
      deviceUuid: parsed.uuid,
    })];
  }

  // ==================== Private: Helpers ====================

  private _buildDataLine(header: string, payload: object): string | null {
    if (!this.localInfo) return null;
    return `${header}:${this.localInfo.uuid}:${this.localInfo.publicKey}:${JSON.stringify(payload)}\n`;
  }

  private _encryptMessage(header: string, payload: object, _targetUuid: string): string | null {
    return this._buildDataLine(header, payload);
  }

  private _buildAcceptLine(): string {
    const li = this.localInfo!;
    const battery = li.isCharging ? `+${li.batteryLevel}` : `${li.batteryLevel}`;
    return `ACCEPT:${li.uuid}:${li.publicKey}:${li.ipAddress}:${battery}:${li.deviceType}\n`;
  }

  private _parseBattery(status: string): { level: number; isCharging: boolean } {
    const isCharging = status.startsWith('+');
    const raw = isCharging ? status.substring(1) : status;
    const level = parseInt(raw, 10);
    return { level: isNaN(level) ? 0 : Math.min(100, Math.max(0, level)), isCharging };
  }
}
