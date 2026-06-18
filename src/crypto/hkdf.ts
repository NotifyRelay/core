import { hmac } from '@noble/hashes/hmac';
import { sha256 } from '@noble/hashes/sha256';

export function hkdfDerive(localKey: string, remoteKey: string): string {
  const [a, b] = [localKey, remoteKey].sort();
  const ikmBytes = new TextEncoder().encode(a + b);

  const saltBytes = new Uint8Array(32);

  const prk = hmac(sha256, saltBytes, ikmBytes);

  const infoBytes = new TextEncoder().encode("shared-secret");
  const okmInput = new Uint8Array(infoBytes.length + 1);
  okmInput.set(infoBytes, 0);
  okmInput[infoBytes.length] = 0x01;
  const okm = hmac(sha256, prk, okmInput);

  return btoa(String.fromCharCode(...okm));
}
