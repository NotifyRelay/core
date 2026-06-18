import type { ParsedLine, RawDataMessage, RawMessageType } from '../types/message'
import type { HandshakePayload, HeartbeatPayload } from '../types/device'
import type { DeviceType } from '../types/protocol'
import { isDataHeader } from './constants'

export function parseLine(line: string): ParsedLine {
  const colonIndex = line.indexOf(':')
  const type = colonIndex === -1 ? line : line.substring(0, colonIndex)

  if (type === 'HANDSHAKE') {
    const payload = parseHandshake(line)
    return { type: 'HANDSHAKE', ...payload }
  }

  if (type === 'HEARTBEAT_TCP') {
    const parts = line.split(':')
    return {
      type: 'HEARTBEAT_TCP',
      uuid: parts[1],
      displayName: atob(parts[2]),
      port: parseInt(parts[3], 10),
      batteryStatus: parts[4],
      deviceType: parts[5],
    }
  }

  if (type === 'ACCEPT') {
    const parts = line.split(':')
    const batteryStatus = parts[4] || '0'
    const isCharging = batteryStatus.startsWith('+')
    const rawLevel = parseInt(isCharging ? batteryStatus.substring(1) : batteryStatus, 10)
    const batteryLevel = isNaN(rawLevel) ? 0 : Math.max(0, Math.min(100, rawLevel))
    return {
      type: 'ACCEPT',
      uuid: parts[1],
      publicKey: parts[2],
      ipAddress: parts[3],
      batteryLevel,
      isCharging,
      deviceType: parts[5] as DeviceType,
    } as any
  }

  if (type === 'REJECT') {
    const parts = line.split(':')
    return { type: 'REJECT', uuid: parts[1] }
  }

  if (type === 'NOTIFYRELAY_DISCOVER') {
    const parts = line.split(':')
    return {
      type: 'NOTIFYRELAY_DISCOVER',
      uuid: parts[1],
      displayName: parts[2],
      port: parseInt(parts[3], 10),
    } as any
  }

  if (type === 'NOTIFYRELAY_DISCOVER_MANUAL') {
    const encrypted = line.substring(line.indexOf(':') + 1)
    return { type: 'NOTIFYRELAY_DISCOVER_MANUAL', encrypted } as any
  }

  if (isDataHeader(type)) {
    const raw = parseDataLine(line)
    return { type: 'ENCRYPTED_DATA', ...raw }
  }

  throw new Error(`Unknown line type: ${type}`)
}

export function parseDataLine(line: string): RawDataMessage {
  const parts = line.split(':')
  return {
    header: parts[0] as RawMessageType,
    senderUuid: parts[1],
    senderPubKey: parts[2],
    encryptedPayload: parts.slice(3).join(':'),
  }
}

export function parseHandshake(payload: string): HandshakePayload {
  const parts = payload.split(':')
  const batteryStatus = parts[4] || '0'
  const isCharging = batteryStatus.startsWith('+')
  const rawLevel = parseInt(isCharging ? batteryStatus.substring(1) : batteryStatus, 10)
  const batteryLevel = isNaN(rawLevel) ? 0 : Math.max(0, Math.min(100, rawLevel))
  return {
    uuid: parts[1],
    publicKey: parts[2],
    ipAddress: parts[3],
    batteryLevel,
    isCharging,
    deviceType: parts[5] as DeviceType,
  }
}

export function parseHeartbeat(line: string): HeartbeatPayload {
  const parts = line.split(':')
  const batteryStatus = parts[4]
  const isCharging = batteryStatus.startsWith('+')
  const rawLevel = parseInt(batteryStatus.substring(1), 10)
  const batteryLevel = isNaN(rawLevel) ? 0 : Math.max(0, Math.min(100, rawLevel))
  return {
    uuid: parts[1],
    displayName: parts[2],
    port: parseInt(parts[3], 10),
    batteryLevel,
    deviceType: parts[5] as DeviceType,
    isCharging,
  }
}

export function encodeMessage(obj: unknown): string {
  return JSON.stringify(obj)
}

export function decodeMessage<T>(str: string): T {
  return JSON.parse(str) as T
}
