import { secp256r1 } from '@noble/curves/p256';

function base64Encode(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes));
}

function base64Decode(s: string): Uint8Array {
  return Uint8Array.from(atob(s), c => c.charCodeAt(0));
}

export function generateKeyPair(): { publicKey: string; privateKey: string } {
  const privateKey = secp256r1.utils.randomPrivateKey();
  const publicKey = secp256r1.getPublicKey(privateKey, false);
  return {
    publicKey: base64Encode(publicKey),
    privateKey: base64Encode(privateKey),
  };
}

export function computeSharedSecret(privateKey: string, publicKey: string): string {
  const priv = base64Decode(privateKey);
  const pub = base64Decode(publicKey);
  const shared = secp256r1.getSharedSecret(priv, pub);
  const sharedX = shared.slice(1, 33);
  return base64Encode(sharedX);
}
