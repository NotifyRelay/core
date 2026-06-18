import type { SuperIslandState, SuperIslandDiff } from '../types/notification';
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
      newState = this.applyDelta(oldState, rawData['changes'] as unknown as SuperIslandDiff);
    } else {
      newState = (rawData['state'] as SuperIslandState) || {};
    }

    if (!this.store.has(deviceUuid)) {
      this.store.set(deviceUuid, new Map());
    }
    this.store.get(deviceUuid)!.set(featureId, newState);

    return newState;
  }

  applyDelta(oldState: SuperIslandState, changes: SuperIslandDiff): SuperIslandState {
    const result: SuperIslandState = { ...oldState };

    if (changes.title !== undefined && changes.title !== null) {
      result.title = changes.title;
    }
    if (changes.text !== undefined && changes.text !== null) {
      result.text = changes.text;
    }
    if (changes.paramV2Raw !== undefined && changes.paramV2Raw !== null) {
      result.paramV2Raw = changes.paramV2Raw;
    }

    if (changes.picsChanged || changes.picsRemoved) {
      const mergedPics = { ...(oldState.pics || {}) };
      if (changes.picsChanged) {
        for (const key of Object.keys(changes.picsChanged)) {
          mergedPics[key] = changes.picsChanged[key];
        }
      }
      if (changes.picsRemoved) {
        for (const key of changes.picsRemoved) {
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
