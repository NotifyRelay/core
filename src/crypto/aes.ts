import { gcm } from '@noble/ciphers/aes';
import { randomBytes } from '@noble/ciphers/webcrypto';

const IV_LENGTH = 12;
const TAG_LENGTH = 16;

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

export interface AesEncryptResult {
  ciphertext: string;
  iv: string;
  tag: string;
}

export function encrypt(
  plaintext: string,
  key: string
): AesEncryptResult {
  const keyBytes = base64Decode(key);
  const ivBytes = getIv();
  const plainBytes = new TextEncoder().encode(plaintext);
  const aes = gcm(keyBytes, ivBytes);
  const combined = aes.encrypt(plainBytes);
  const ct = combined.slice(0, combined.length - TAG_LENGTH);
  const tag = combined.slice(combined.length - TAG_LENGTH);
  return {
    ciphertext: base64Encode(ct),
    iv: base64Encode(ivBytes),
    tag: base64Encode(tag),
  };
}

export function decrypt(
  ciphertext: string,
  key: string,
  iv: string,
  tag: string
): string {
  const keyBytes = base64Decode(key);
  const ivBytes = base64Decode(iv);
  const ctBytes = base64Decode(ciphertext);
  const tagBytes = base64Decode(tag);
  const combined = new Uint8Array(ctBytes.length + tagBytes.length);
  combined.set(ctBytes, 0);
  combined.set(tagBytes, ctBytes.length);
  const aes = gcm(keyBytes, ivBytes);
  const plainBytes = aes.decrypt(combined);
  return new TextDecoder().decode(plainBytes);
}
