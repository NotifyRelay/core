import type { DeviceType } from './protocol';

export interface DeviceInfo {
  uuid: string;
  displayName: string;
  deviceType: DeviceType;
  publicKey: string;
  ipAddress: string;
  port: number;
  batteryLevel: number;
  isCharging: boolean;
  osVersion?: string;
  appVersion?: string;
}

export interface AuthInfo {
  deviceUuid: string;
  publicKey: string;
  authedAt: number;
  label?: string;
}

export interface HandshakePayload {
  uuid: string;
  publicKey: string;
  ipAddress: string;
  batteryLevel: number;
  isCharging: boolean;
  deviceType: DeviceType;
}

export interface HandshakeResponse {
  uuid: string;
  publicKey: string;
  ipAddress: string;
  batteryLevel: number;
  isCharging: boolean;
  deviceType: DeviceType;
  accepted: boolean;
  rejectReason?: string;
}

export interface HeartbeatPayload {
  uuid: string;
  displayName: string;
  port: number;
  batteryLevel: number;
  deviceType: DeviceType;
  isCharging: boolean;
}

export interface BatteryStatus {
  level: number;
  isCharging: boolean;
}

export function formatBatteryStatus(status: BatteryStatus): string {
  return status.isCharging ? `+${status.level}` : `-${status.level}`;
}

export function parseBatteryStatus(raw: string): BatteryStatus {
  const isCharging = raw.startsWith('+');
  const level = parseInt(raw.substring(1), 10);
  return { level: isNaN(level) ? 0 : level, isCharging };
}
