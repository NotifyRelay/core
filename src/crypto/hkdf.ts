import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';

function base64Decode(s: string): Uint8Array {
  return Uint8Array.from(atob(s), c => c.charCodeAt(0));
}

function base64Encode(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes));
}

export function hkdfDerive(
  ikm: string,
  salt: string,
  info: string,
  length: number
): string {
  const ikmBytes = base64Decode(ikm);
  const saltBytes = new TextEncoder().encode(salt);
  const infoBytes = new TextEncoder().encode(info);
  const derived = hkdf(sha256, ikmBytes, saltBytes, infoBytes, length);
  return base64Encode(derived);
}
