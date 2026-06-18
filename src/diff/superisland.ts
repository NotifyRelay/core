import type { SuperIslandState, SuperIslandDiff } from '../types/notification';
import { SUPERISLAND_TERMINATE_VALUE, SUPERISLAND_FEATURE_KEY } from '../types/notification';
import { sha1 } from '@noble/hashes/sha1';

export function computeFeatureId(superPkg: string, paramV2: string, instanceId?: string): string {
  const input = instanceId ? `${superPkg}|${paramV2}|${instanceId}` : `${superPkg}|${paramV2}`;
  const hash = sha1(input);
  let hex = '';
  for (let i = 0; i < 16; i++) {
    hex += hash[i].toString(16).padStart(2, '0');
  }
  return hex;
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
  return { [SUPERISLAND_FEATURE_KEY]: featureId, state: { ...state } };
}

export function buildDeltaPayload(featureId: string, diffObj: SuperIslandDiff): Record<string, unknown> {
  return { [SUPERISLAND_FEATURE_KEY]: featureId, changes: { ...diffObj } };
}

export function buildEndPayload(featureId: string): Record<string, unknown> {
  return { [SUPERISLAND_FEATURE_KEY]: featureId, terminateValue: SUPERISLAND_TERMINATE_VALUE };
}

export class SuperIslandSendManager {
  private lastState: Map<string, Map<string, SuperIslandState>> = new Map();
  private forceFull: Map<string, Set<string>> = new Map();

  updateAndGetPayload(deviceUuid: string, featureId: string, newState: SuperIslandState, forceFull?: boolean): {
    isFull: boolean;
    payload: Record<string, unknown>;
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
      return { isFull: true, payload: buildFullPayload(featureId, newState) };
    }

    deviceStates.set(featureId, { ...newState });
    return { isFull: false, payload: buildDeltaPayload(featureId, diffResult) };
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
