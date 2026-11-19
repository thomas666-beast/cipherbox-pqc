import init, * as pqc from '../pqc/cipherbox_pqc_wasm.js'
import { b64ToBytes, bytesToB64 } from './crypto.js'

let initPromise
export function initPqc() {
  initPromise ??= init().catch((error) => {
    initPromise = undefined
    throw error
  })
  return initPromise
}

function pairForKem(secret, publicKey) {
  if (secret.length !== 34) return pqc.MlKemKeyPair.importKeys(secret, publicKey)
  const pair = pqc.HybridKeyPair.fromSecret(secret)
  const actual = pair.publicKey()
  if (actual.length !== publicKey.length || actual.some((value, i) => value !== publicKey[i])) {
    pair.free()
    throw new Error('Stored KEM key does not match the public key.')
  }
  return pair
}

function roomKey(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9+/]{43}=$/.test(value)) {
    throw new Error('Invalid room key.')
  }
  const raw = b64ToBytes(value)
  if (raw.length !== 32 || bytesToB64(raw) !== value) throw new Error('Invalid room key.')
  return value
}

export async function wrapRoomKey(publicKeyB64, key) {
  await initPqc()
  return pqc.wrap_room_key_for_user(publicKeyB64, roomKey(key))
}

// Original clients used unversioned raw-secret AES-GCM. Explicit Rust v1
// used ChaCha20-Poly1305; hardened clients write Rust v2. No retry across formats.
async function unwrapWith(envelope, pair) {
  if (!envelope || typeof envelope !== 'object' || Array.isArray(envelope)) throw new Error('Invalid room envelope.')
  const { v, ct, iv, enc_aes: ciphertext } = envelope
  if ([ct, iv, ciphertext].some((field) => typeof field !== 'string')) throw new Error('Invalid room envelope.')
  if (v === 1 || v === 2) return roomKey(pair.unwrapRoomKey(v, ct, iv, ciphertext))
  if (v !== undefined) throw new Error('Unsupported room envelope version.')
  const shared = pair.decapsulate(b64ToBytes(ct))
  try {
    const key = await globalThis.crypto.subtle.importKey('raw', shared, 'AES-GCM', false, ['decrypt'])
    const data = await globalThis.crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64ToBytes(iv) }, key, b64ToBytes(ciphertext))
    return roomKey(new TextDecoder('utf-8', { fatal: true }).decode(data))
  } finally {
    shared.fill(0)
  }
}

export async function unwrapRoomKey(payload, stored, passphrase) {
  await initPqc()
  const envelope = JSON.parse(payload)
  const secret = pqc.decrypt_private_key(stored.encrypted_kem_dk, passphrase)
  let pair
  try {
    pair = pairForKem(secret, stored.kem_public_key)
    return await unwrapWith(envelope, pair)
  } finally {
    secret.fill(0)
    pair?.free()
  }
}

export async function generateIdentity(passphrase) {
  await initPqc()
  const dsa = new pqc.MlDsa87KeyPair()
  let kem, dsaSecret, kemSecret
  try {
    kem = new pqc.HybridKeyPair(1024)
    const [seed, publicKey] = dsa.exportKeys()
    dsaSecret = seed
    kemSecret = kem.exportSecret()
    return {
      encrypted_dsa_sk: pqc.encrypt_private_key(dsaSecret, passphrase),
      dsa_public_key: publicKey,
      encrypted_kem_dk: pqc.encrypt_private_key(kemSecret, passphrase),
      kem_public_key: kem.publicKey(),
    }
  } finally {
    dsaSecret?.fill(0)
    kemSecret?.fill(0)
    dsa.free()
    kem?.free()
  }
}

export async function signChallenge(stored, passphrase, nonce) {
  await initPqc()
  const seed = pqc.decrypt_private_key(stored.encrypted_dsa_sk, passphrase)
  let pair
  try {
    const size = stored.dsa_public_key.length
    const Type = size === 1952 ? pqc.MlDsaKeyPair : size === 2592 ? pqc.MlDsa87KeyPair : null
    if (!Type) throw new Error('Unsupported signing identity.')
    pair = Type.importKeys(seed, stored.dsa_public_key)
    return bytesToB64(pair.sign(b64ToBytes(nonce)))
  } finally {
    seed.fill(0)
    pair?.free()
  }
}
