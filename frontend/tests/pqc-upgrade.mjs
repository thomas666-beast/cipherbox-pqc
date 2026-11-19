import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { webcrypto, randomBytes } from 'node:crypto'
import init, * as wasm from '../src/pqc/cipherbox_pqc_wasm.js'
import { generateIdentity, signChallenge, unwrapRoomKey, wrapRoomKey } from '../src/core/pqc.js'
import { b64ToBytes, bytesToB64, decryptMessage, encryptMessage, generateAesKey, importAesKey } from '../src/core/crypto.js'

globalThis.crypto ??= webcrypto
await init({ module_or_path: await readFile(new URL('../src/pqc/cipherbox_pqc_wasm_bg.wasm', import.meta.url)) })
const pass = 'synthetic test passphrase'
const modern = await generateIdentity(pass)
const kem = new wasm.MlKemKeyPair()
const dsa = new wasm.MlDsaKeyPair()
const [kemSeed, kemPub] = kem.exportKeys()
const [dsaSeed, dsaPub] = dsa.exportKeys()
const legacy = {
  kem_public_key: kemPub,
  encrypted_kem_dk: wasm.encrypt_private_key(kemSeed, pass),
  dsa_public_key: dsaPub,
  encrypted_dsa_sk: wasm.encrypt_private_key(dsaSeed, pass),
}
const roomKey = await generateAesKey()
const [ct, shared] = kem.encapsulate()
const iv = webcrypto.getRandomValues(new Uint8Array(12))
const legacyKey = await webcrypto.subtle.importKey('raw', shared, 'AES-GCM', false, ['encrypt'])
const data = await webcrypto.subtle.encrypt({ name: 'AES-GCM', iv }, legacyKey, new TextEncoder().encode(roomKey))
const oldEnvelope = JSON.stringify({ ct: bytesToB64(ct), iv: bytesToB64(iv), enc_aes: bytesToB64(new Uint8Array(data)) })
assert.equal(await unwrapRoomKey(oldEnvelope, legacy, pass), roomKey)
for (const identity of [legacy, modern]) {
  const wrapped = await wrapRoomKey(bytesToB64(identity.kem_public_key), roomKey)
  assert.equal(JSON.parse(wrapped).v, 2)
  assert.equal(await unwrapRoomKey(wrapped, identity, pass), roomKey)
  await assert.rejects(unwrapRoomKey(wrapped, identity, 'wrong passphrase'))
  const challenge = bytesToB64(randomBytes(32))
  assert(wasm.ml_dsa_verify(identity.dsa_public_key, b64ToBytes(challenge),
    b64ToBytes(await signChallenge(identity, pass, challenge))))
}
await assert.rejects(unwrapRoomKey(oldEnvelope.replace('{', '{"v":2,'), legacy, pass))
kem.free()
dsa.free()
console.log('Passed: legacy AES envelope, hardened v2 wrapping, legacy/modern identities and wrong-passphrase handling.')

const base = process.argv[2]
if (base) {
  assert.match(base, /^http:\/\/127\.0\.0\.1:\d+\/?$/, 'Use a disposable local server only')
  const tag = randomBytes(4).toString('hex')
  async function api(route, { token, body, status = 200, method = body ? 'POST' : 'GET' } = {}) {
    const response = await fetch(new URL(`/api${route}`, base), {
      method,
      headers: {
        ...(body && { 'Content-Type': 'application/json' }),
        ...(token && { Authorization: `Bearer ${token}` }),
      },
      body: body && JSON.stringify(body),
    })
    const raw = await response.text()
    assert.equal(response.status, status, `${method} ${route}: ${raw.slice(0, 500)}`)
    return { body: JSON.parse(raw), response }
  }
  async function register(name, identity) {
    return (await api('/auth/register', { body: {
      username: name,
      dilithium_public_key: bytesToB64(identity.dsa_public_key),
      kyber_public_key: bytesToB64(identity.kem_public_key),
    } })).body
  }
  const owner = await register(`owner_${tag}`, modern)
  const member = await register(`member_${tag}`, legacy)
  await api('/auth/pqc/challenge', { body: [], status: 400 })
  await api('/auth/register', { body: { username: `invalid_${tag}` }, status: 400 })
  for (const [account, identity] of [[owner, modern], [member, legacy]]) {
    const { body: { nonce } } = await api('/auth/pqc/challenge', { body: { username: account.username } })
    const signature = await signChallenge(identity, pass, nonce)
    const options = { body: { username: account.username, signature } }
    // Two in-flight requests must never both receive a login session.
    const race = await Promise.all([1, 2].map(() => fetch(new URL('/api/auth/pqc/verify', base), {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(options.body),
    })))
    assert.equal(race.filter(response => response.status === 200).length, 1)
    assert(race.every(response => [200, 400, 401].includes(response.status)))
    const cookie = race.find(response => response.status === 200).headers.get('set-cookie')
    assert.match(cookie, /cipherbox_token=/)
    await api('/auth/pqc/verify', { ...options, status: 400 })
  }

  const ownerWrap = await wrapRoomKey(bytesToB64(modern.kem_public_key), roomKey)
  const { body: { room } } = await api('/rooms', { token: owner.token, body: {
    name: `PQC fixture ${tag}`, is_invite_only: true, owner_kyber_ciphertext: ownerWrap,
  } })
  const privateRoom = `/rooms/${room.public_hash}`
  await api(`${privateRoom}/key`, { token: member.token, status: 403 })
  const memberWrap = await wrapRoomKey(bytesToB64(legacy.kem_public_key), roomKey)
  await api(`${privateRoom}/invite`, { token: owner.token, body: {
    user_id: member.id, target_kyber_ciphertext: memberWrap,
  } })
  const { body: envelope } = await api(`${privateRoom}/key`, { token: member.token })
  const receivedKey = await unwrapRoomKey(envelope.kyber_ciphertext, legacy, pass)
  assert.equal(receivedKey, roomKey)
  const cipher = await importAesKey(receivedKey)

  const { body: { token: wsToken } } = await api('/ws-token', { token: owner.token })
  const wsUrl = new URL(`/chat?token=${encodeURIComponent(wsToken)}`, base)
  wsUrl.protocol = 'ws:'
  const socket = new WebSocket(wsUrl)
  const wait = (event, predicate = () => true) => new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      socket.removeEventListener(event, handler)
      reject(new Error(`Timed out waiting for WebSocket ${event}`))
    }, 5000)
    const handler = (item) => {
      const value = event === 'message' ? JSON.parse(item.data) : item
      if (!predicate(value)) return
      socket.removeEventListener(event, handler)
      clearTimeout(timer)
      resolve(value)
    }
    socket.addEventListener(event, handler)
  })
  try {
    await wait('open')
    const joined = wait('message', m => m.t === 3)
    socket.send(JSON.stringify({ t: 3, r: room.id }))
    await joined
    for (const message of ['first fixture', 'second fixture']) {
      const enc = await encryptMessage(cipher, message)
      const stored = wait('message', m => m.t === 1)
      socket.send(JSON.stringify({ t: 0, r: room.id, c: enc.ct, i: enc.iv, g: enc.tag }))
      await stored
    }
  } finally {
    socket.close()
  }
  const { body: latest } = await api(`${privateRoom}/messages?limit=1`, { token: member.token })
  assert.equal(latest.messages.length, 1)
  const [message] = latest.messages
  assert.equal(await decryptMessage(cipher, message.ct, message.iv, message.tag), 'second fixture')
  const { body: earlier } = await api(`${privateRoom}/messages?limit=1&before=${message.id}`, { token: member.token })
  assert.equal(earlier.messages.length, 1)
  assert.notEqual(earlier.messages[0].id, message.id)
  await api(`${privateRoom}/messages?limit=no`, { token: member.token, status: 400 })
  const { body: homes } = await api('/rooms', { token: member.token })
  assert.equal(homes.rooms.find(r => r.id === room.id).last_message_id, message.id)

  for (const size of [128, 1024 * 1024]) {
    const data = randomBytes(size)
    const pasteKey = await generateAesKey()
    const wrapped = await encryptMessage(cipher, pasteKey)
    const fileIv = randomBytes(12)
    const encrypted = Buffer.from(await webcrypto.subtle.encrypt(
      { name: 'AES-GCM', iv: fileIv }, await importAesKey(pasteKey), data,
    ))
    const blob = new Blob([fileIv, encrypted.subarray(-16), encrypted.subarray(0, -16)])
    const form = new FormData()
    form.append('title', 'Encrypted fixture')
    form.append('file_name', 'fixture.bin')
    form.append('file', blob, 'fixture.bin')
    form.append('wrapped_key_ct', wrapped.ct)
    form.append('wrapped_key_iv', wrapped.iv)
    form.append('wrapped_key_tag', wrapped.tag)
    const upload = await fetch(new URL(`/api${privateRoom}/pastes`, base), {
      method: 'POST', headers: { Authorization: `Bearer ${owner.token}` }, body: form,
    })
    const uploaded = await upload.text()
    assert.equal(upload.status, 200, uploaded.slice(0, 500))
    const pastePath = `/pastes/${JSON.parse(uploaded).paste.public_hash}`
    const { body: { paste } } = await api(`${pastePath}/open`, { token: member.token, method: 'POST' })
    const downloaded = await fetch(new URL(`/api${pastePath}/download`, base), {
      headers: { Authorization: `Bearer ${member.token}` },
    })
    assert.equal(downloaded.status, 200)
    const stored = Buffer.from(await downloaded.arrayBuffer())
    const fileKey = await decryptMessage(cipher, paste.wrapped_key_encrypted, paste.wrapped_key_iv, paste.wrapped_key_tag)
    const decrypted = await webcrypto.subtle.decrypt({ name: 'AES-GCM', iv: stored.subarray(0, 12) },
      await importAesKey(fileKey), Buffer.concat([stored.subarray(28), stored.subarray(12, 28)]))
    assert.deepEqual(Buffer.from(decrypted), data)
  }

  const publicKey = await generateAesKey()
  const { body: { room: publicRoom } } = await api('/rooms', { token: owner.token, body: {
    name: `Public fixture ${tag}`, plaintext_room_key: publicKey,
  } })
  const publicPath = `/rooms/${publicRoom.public_hash}`
  await api(`${publicPath}/key`, { token: member.token, status: 403 })
  await api(`${publicPath}/join`, { token: member.token, body: {} })
  const { body: visible } = await api(`${publicPath}/key`, { token: member.token })
  assert.equal(visible.plaintext_room_key, publicKey)
  console.log('Passed: Perl/Rust PQC login (both levels, concurrent replay), room invite/unlock, encrypted WebSocket chat, pagination, encrypted attachments, public join.')
}
