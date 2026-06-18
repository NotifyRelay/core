export interface SendTask {
  id: string
  header: string
  payload: string
  priority: number
  timestamp: number
  retryCount: number
}

export class ProtocolSender {
  private sendCallback: (message: string) => void | Promise<void>

  constructor(sendCallback: (message: string) => void | Promise<void>) {
    this.sendCallback = sendCallback
  }

  send(header: string, senderUuid: string, senderPubKey: string, encryptedPayload: string): void | Promise<void> {
    const message = this.buildMessage(header, senderUuid, senderPubKey, encryptedPayload)
    return this.sendCallback(message)
  }

  buildMessage(header: string, senderUuid: string, senderPubKey: string, encryptedPayload: string): string {
    return `${header}:${senderUuid}:${senderPubKey}:${encryptedPayload}\n`
  }

  setSendCallback(callback: (message: string) => void | Promise<void>): void {
    this.sendCallback = callback
  }
}
