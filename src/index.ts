import { computeFeatureId, diff as diffStates, buildFullPayload, buildDeltaPayload, buildEndPayload, SuperIslandSendManager } from './diff/superisland';
import { diffMediaPlay, shouldSendFull, buildMediaPlayFull, buildMediaPlayDelta, buildMediaPlayEnd } from './diff/mediaplay';
import { RemoteStore } from './diff/store';
import { ROUTE_TABLE, isDataHeader, isLinePrefix } from './protocol/constants';
import { parseLine, parseDataLine, parseHandshake, parseHeartbeat, encodeMessage, decodeMessage } from './protocol/codec';
import { ProtocolRouter } from './protocol/router';
import { ProtocolSender } from './protocol/sender';
import { classifyNotification, processNotification, extractMetadata, computeDedupKey } from './notification/processor';
import { FilterEngine } from './notification/filter';
import { CoreEngine } from './engine/CoreEngine';
import type { LocalDeviceInfo } from './engine/CoreEngine';

export const diff = {
  superIsland: {
    computeFeatureId,
    diff: diffStates,
    buildFullPayload,
    buildDeltaPayload,
    buildEndPayload,
    SuperIslandSendManager,
  },
  mediaPlay: {
    diffMediaPlay,
    shouldSendFull,
    buildMediaPlayFull,
    buildMediaPlayDelta,
    buildMediaPlayEnd,
  },
  RemoteStore,
};

export const protocol = {
  ROUTE_TABLE,
  isDataHeader,
  isLinePrefix,
  parseLine,
  parseDataLine,
  parseHandshake,
  parseHeartbeat,
  encodeMessage,
  decodeMessage,
  ProtocolRouter,
  ProtocolSender,
};

export const notification = {
  classifyNotification,
  processNotification,
  extractMetadata,
  computeDedupKey,
  FilterEngine,
};

export { CoreEngine };
export type { LocalDeviceInfo };
