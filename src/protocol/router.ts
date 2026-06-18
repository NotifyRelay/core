import type { RouterHandlerMap, MessageHandler } from '../types/message'
import type { HandshakePayload, HandshakeResponse, HeartbeatPayload } from '../types/device'
import type { DeviceType } from '../types/protocol'
import { parseBatteryStatus } from '../types/device'
import { parseLine, decodeMessage } from './codec'
import { ROUTE_TABLE } from './constants'

interface RouterHandlers extends RouterHandlerMap {
  onHandshake?: MessageHandler<HandshakePayload>
  onAuthResponse?: MessageHandler<HandshakeResponse>
  onHeartbeat?: MessageHandler<HeartbeatPayload>
}

export class ProtocolRouter {
  private handlers: RouterHandlers

  constructor(handlers: RouterHandlers) {
    this.handlers = handlers
  }

  routeLine(line: string): void | Promise<void> {
    const parsed = parseLine(line)

    switch (parsed.type) {
      case 'HANDSHAKE': {
        const handler = this.handlers.onHandshake
        if (handler) return handler(parsed as HandshakePayload, parsed.uuid)
        return
      }
      case 'ACCEPT':
      case 'REJECT': {
        const handler = this.handlers.onAuthResponse
        if (handler) return handler(parsed as unknown as HandshakeResponse, parsed.uuid)
        return
      }
      case 'HEARTBEAT_TCP': {
        const handler = this.handlers.onHeartbeat
        if (handler) {
          const battery = parseBatteryStatus(parsed.batteryStatus)
          const payload: HeartbeatPayload = {
            uuid: parsed.uuid,
            displayName: parsed.displayName,
            port: parsed.port,
            batteryLevel: battery.level,
            deviceType: parsed.deviceType as DeviceType,
            isCharging: battery.isCharging,
          }
          return handler(payload, parsed.uuid)
        }
        return
      }
      case 'ENCRYPTED_DATA':
        return this.routeData(parsed.header, parsed.encryptedPayload, parsed.senderUuid)
    }
  }

  routeData(header: string, payload: string, senderUuid: string): void | Promise<void> {
    const handlerName = ROUTE_TABLE[header]
    if (!handlerName) return
    const handler = this.handlers[handlerName] as MessageHandler | undefined
    if (!handler) return
    const message = decodeMessage(payload)
    return handler(message, senderUuid)
  }

  setHandler<K extends keyof RouterHandlerMap>(key: K, handler: RouterHandlerMap[K]): void {
    this.handlers[key] = handler
  }

  removeHandler(key: keyof RouterHandlerMap): void {
    delete this.handlers[key]
  }
}
