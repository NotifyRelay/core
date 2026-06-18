import type { SuperIslandState, SuperIslandDiff } from '../types/notification';
import { SUPERISLAND_TERMINATE_VALUE, SUPERISLAND_FEATURE_KEY } from '../types/notification';
import { sha1 } from '@noble/hashes/sha1';
import { sha256 } from '@noble/hashes/sha256';

function bytesToHex(bytes: Uint8Array): string {
  let hex = '';
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, '0');
  }
  return hex;
}

export function computeFeatureId(superPkg: string, paramV2: string, instanceId?: string): string {
  const stableFields: string[] = [superPkg];
  try {
    const root = JSON.parse(paramV2);
    const extract = (path: string): string[] => {
      const obj = root[path];
      if (obj && typeof obj === 'object' && !Array.isArray(obj)) {
        const result: string[] = [];
        if (obj.title != null) result.push(String(obj.title));
        if (obj.content != null) result.push(String(obj.content));
        return result;
      }
      return [];
    };
    stableFields.push(...extract('chatInfo'));
    stableFields.push(...extract('baseInfo'));
    stableFields.push(...extract('highlightInfo'));
  } catch {
    if (paramV2 != null) stableFields.push(paramV2);
    if (instanceId != null) stableFields.push(instanceId);
  }
  if (instanceId != null) stableFields.push(instanceId);
  const raw = stableFields.join('|');
  return bytesToHex(sha1(raw));
}

export function diff(oldState: SuperIslandState, newState: SuperIslandState): SuperIslandDiff | null {
  const result: SuperIslandDiff = {};
  let changed = false;

  if (newState.title !== undefined && newState.title !== oldState.title) {
    result.title = newState.title;
    changed = true;
  }
  if (newState.text !== undefined && newState.text !== oldState.text) {
    result.text = newState.text;
    changed = true;
  }
  if (newState.paramV2Raw !== undefined && newState.paramV2Raw !== oldState.paramV2Raw) {
    result.paramV2Raw = newState.paramV2Raw;
    changed = true;
  }

  const oldPics = oldState.pics || {};
  const newPics = newState.pics || {};
  const picsChanged: Record<string, string> = {};
  const picsRemoved: string[] = [];

  for (const key of Object.keys(newPics)) {
    if (oldPics[key] !== newPics[key]) {
      picsChanged[key] = newPics[key];
      changed = true;
    }
  }
  for (const key of Object.keys(oldPics)) {
    if (!(key in newPics)) {
      picsRemoved.push(key);
      changed = true;
    }
  }

  if (Object.keys(picsChanged).length > 0) {
    result.picsChanged = picsChanged;
  }
  if (picsRemoved.length > 0) {
    result.picsRemoved = picsRemoved;
  }

  return changed ? result : null;
}

export function buildFullPayload(featureId: string, state: SuperIslandState): Record<string, unknown> {
  const payload: Record<string, unknown> = {
    packageName: state.packageName ?? '',
    appName: state.appName ?? '',
    time: state.time ?? 0,
    isLocked: state.isLocked ?? false,
    [SUPERISLAND_FEATURE_KEY]: featureId,
    title: state.title ?? '',
    text: state.text ?? '',
    param_v2_raw: state.paramV2Raw ?? '',
    pics: state.pics ?? {},
  };
  payload.hash = bytesToHex(sha256(JSON.stringify(payload)));
  return payload;
}

export function buildDeltaPayload(featureId: string, state: SuperIslandState, diffObj: SuperIslandDiff): Record<string, unknown> {
  const changes: Record<string, unknown> = {};
  if (diffObj.paramV2Raw !== undefined) {
    changes['param_v2_raw'] = diffObj.paramV2Raw;
  }
  if (diffObj.picsChanged && Object.keys(diffObj.picsChanged).length > 0) {
    changes['pics'] = diffObj.picsChanged;
  }
  if (diffObj.picsRemoved && diffObj.picsRemoved.length > 0) {
    changes['pics_removed'] = diffObj.picsRemoved;
  }
  const payload: Record<string, unknown> = {
    packageName: state.packageName ?? '',
    appName: state.appName ?? '',
    time: state.time ?? 0,
    isLocked: state.isLocked ?? false,
    [SUPERISLAND_FEATURE_KEY]: featureId,
    changes,
  };
  payload.hash = bytesToHex(sha256(JSON.stringify(payload)));
  return payload;
}

export function buildEndPayload(featureId: string, state?: SuperIslandState): Record<string, unknown> {
  const payload: Record<string, unknown> = {
    packageName: state?.packageName ?? '',
    appName: state?.appName ?? '',
    time: state?.time ?? 0,
    isLocked: state?.isLocked ?? false,
    terminateValue: SUPERISLAND_TERMINATE_VALUE,
    [SUPERISLAND_FEATURE_KEY]: featureId,
  };
  payload.hash = bytesToHex(sha256(JSON.stringify(payload)));
  return payload;
}

export class SuperIslandSendManager {
  private lastState: Map<string, Map<string, SuperIslandState>> = new Map();
  private forceFull: Map<string, Set<string>> = new Map();

  updateAndGetPayload(deviceUuid: string, featureId: string, newState: SuperIslandState, forceFull?: boolean): {
    isFull: boolean;
    payload: Record<string, unknown> | null;
  } {
    if (!this.lastState.has(deviceUuid)) {
      this.lastState.set(deviceUuid, new Map());
    }
    if (!this.forceFull.has(deviceUuid)) {
      this.forceFull.set(deviceUuid, new Set());
    }

    const deviceStates = this.lastState.get(deviceUuid)!;
    const forced = forceFull || this.forceFull.get(deviceUuid)!.has(featureId);
    const oldState = deviceStates.get(featureId);

    if (!oldState || forced) {
      deviceStates.set(featureId, { ...newState });
      if (forced) {
        this.forceFull.get(deviceUuid)!.delete(featureId);
      }
      return { isFull: true, payload: buildFullPayload(featureId, newState) };
    }

    const diffResult = diff(oldState, newState);
    if (!diffResult) {
      return { isFull: false, payload: null };
    }

    deviceStates.set(featureId, { ...newState });
    return { isFull: false, payload: buildDeltaPayload(featureId, newState, diffResult) };
  }

  markForceFull(deviceUuid: string, featureId: string): void {
    if (!this.forceFull.has(deviceUuid)) {
      this.forceFull.set(deviceUuid, new Set());
    }
    this.forceFull.get(deviceUuid)!.add(featureId);
  }

  ackReceived(deviceUuid: string, featureId: string): void {
    if (this.forceFull.has(deviceUuid)) {
      this.forceFull.get(deviceUuid)!.delete(featureId);
    }
  }
}
