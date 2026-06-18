import type { MediaPlayState, MediaPlayDiff } from '../types/notification';
import { SUPERISLAND_TERMINATE_VALUE } from '../types/notification';

export function diffMediaPlay(oldState: MediaPlayState, newState: MediaPlayState): MediaPlayDiff | null {
  const result: MediaPlayDiff = {};
  let changed = false;

  if (newState.title !== oldState.title) {
    result.title = newState.title;
    changed = true;
  }
  if (newState.text !== oldState.text) {
    result.text = newState.text;
    changed = true;
  }
  if (newState.coverUrl !== oldState.coverUrl) {
    result.coverUrl = newState.coverUrl;
    changed = true;
  }

  return changed ? result : null;
}

export function shouldSendFull(oldState: MediaPlayState | null, newState: MediaPlayState, lastSentTime: number): boolean {
  if (!oldState) return true;
  if (oldState.coverUrl !== newState.coverUrl) return true;
  if (Date.now() - lastSentTime > 6000) return true;
  return false;
}

export function buildMediaPlayFull(state: MediaPlayState): Record<string, unknown> {
  return {
    type: 'FULL',
    title: state.title,
    text: state.text,
    packageName: state.packageName,
    coverUrl: state.coverUrl,
    sentTime: state.sentTime,
  };
}

export function buildMediaPlayDelta(diff: MediaPlayDiff): Record<string, unknown> {
  return { type: 'DIFF', ...diff };
}

export function buildMediaPlayEnd(): Record<string, unknown> {
  return {
    type: 'END',
    mediaType: 'END',
    terminateValue: SUPERISLAND_TERMINATE_VALUE,
    featureKeyValue: 'media_island_global',
  };
}
