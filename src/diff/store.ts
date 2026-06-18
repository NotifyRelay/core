import type { SuperIslandState } from '../types/notification';
import { SUPERISLAND_TERMINATE_VALUE } from '../types/notification';

export class RemoteStore {
  private store: Map<string, Map<string, SuperIslandState>> = new Map();

  applyIncoming(deviceUuid: string, featureId: string, rawData: Record<string, unknown>): SuperIslandState | null {
    if (rawData['terminateValue'] === SUPERISLAND_TERMINATE_VALUE) {
      const deviceStates = this.store.get(deviceUuid);
      if (deviceStates) {
        deviceStates.delete(featureId);
        if (deviceStates.size === 0) {
          this.store.delete(deviceUuid);
        }
      }
      return null;
    }

    let newState: SuperIslandState;

    if ('changes' in rawData) {
      const oldState = this.getState(deviceUuid, featureId) || {};
      newState = this.applyDelta(oldState, rawData['changes'] as Record<string, unknown>);
    } else {
      const state: SuperIslandState = {};
      if (rawData['packageName'] !== undefined) state.packageName = rawData['packageName'] as string;
      if (rawData['appName'] !== undefined) state.appName = rawData['appName'] as string;
      if (rawData['time'] !== undefined) state.time = rawData['time'] as number;
      if (rawData['isLocked'] !== undefined) state.isLocked = rawData['isLocked'] as boolean;
      if (rawData['title'] !== undefined) state.title = rawData['title'] as string;
      if (rawData['text'] !== undefined) state.text = rawData['text'] as string;
      if (rawData['param_v2_raw'] !== undefined) state.paramV2Raw = rawData['param_v2_raw'] as string;
      if (rawData['pics'] !== undefined) state.pics = rawData['pics'] as Record<string, string>;
      newState = state;
    }

    if (!this.store.has(deviceUuid)) {
      this.store.set(deviceUuid, new Map());
    }
    this.store.get(deviceUuid)!.set(featureId, newState);

    return newState;
  }

  applyDelta(oldState: SuperIslandState, changes: Record<string, unknown>): SuperIslandState {
    const result: SuperIslandState = { ...oldState };

    if (changes['param_v2_raw'] !== undefined && changes['param_v2_raw'] !== null) {
      result.paramV2Raw = changes['param_v2_raw'] as string;
    }

    const pics = changes['pics'] as Record<string, string> | undefined;
    const picsRemoved = changes['pics_removed'] as string[] | undefined;

    if (pics || picsRemoved) {
      const mergedPics = { ...(oldState.pics || {}) };
      if (pics) {
        for (const key of Object.keys(pics)) {
          mergedPics[key] = pics[key];
        }
      }
      if (picsRemoved) {
        for (const key of picsRemoved) {
          delete mergedPics[key];
        }
      }
      result.pics = mergedPics;
    }

    return result;
  }

  removeByDeviceAndPkgPrefix(prefix: string): void {
    for (const [deviceUuid, deviceStates] of this.store.entries()) {
      for (const featureId of deviceStates.keys()) {
        if (featureId.startsWith(prefix)) {
          deviceStates.delete(featureId);
        }
      }
      if (deviceStates.size === 0) {
        this.store.delete(deviceUuid);
      }
    }
  }

  getState(deviceUuid: string, featureId: string): SuperIslandState | undefined {
    return this.store.get(deviceUuid)?.get(featureId);
  }

  getAllStates(): Map<string, Map<string, SuperIslandState>> {
    return this.store;
  }
}
