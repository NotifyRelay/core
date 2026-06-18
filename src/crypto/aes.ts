import { gcm } from '@noble/ciphers/aes';
import { randomBytes } from '@noble/ciphers/webcrypto';

const IV_LENGTH = 12;

function base64Decode(s: string): Uint8Array {
  return Uint8Array.from(atob(s), c => c.charCodeAt(0));
}

function base64Encode(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes));
}

function getIv(): Uint8Array {
  if (typeof crypto !== 'undefined' && typeof crypto.getRandomValues === 'function') {
    return crypto.getRandomValues(new Uint8Array(IV_LENGTH));
  }
  return randomBytes(IV_LENGTH);
}

export function encrypt(plaintext: string, key: string): string {
  const keyBytes = base64Decode(key);
  const ivBytes = getIv();
  const plainBytes = new TextEncoder().encode(plaintext);
  const aes = gcm(keyBytes, ivBytes);
  const combined = aes.encrypt(plainBytes);
  const result = new Uint8Array(ivBytes.length + combined.length);
  result.set(ivBytes, 0);
  result.set(combined, ivBytes.length);
  return base64Encode(result);
}

export function decrypt(data: string, key: string): string {
  const keyBytes = base64Decode(key);
  const raw = base64Decode(data);
  const ivBytes = raw.slice(0, IV_LENGTH);
  const combined = raw.slice(IV_LENGTH);
  const aes = gcm(keyBytes, ivBytes);
  const plainBytes = aes.decrypt(combined);
  return new TextDecoder().decode(plainBytes);
}
