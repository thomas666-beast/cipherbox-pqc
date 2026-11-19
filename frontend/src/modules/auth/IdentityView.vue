<script setup>
import { ref } from 'vue'
import { bytesToB64 } from '../../core/crypto.js'
import { generateIdentity, initPqc } from '../../core/pqc.js'
import { saveIdentity, loadIdentity } from '../../core/pqc-db.js'
import api from '../../core/api'

const wasmLoaded = ref(false)
const status = ref('Initializing WASM...')
const passphrase = ref('')
const hasStoredKey = ref(false)

initPqc().then(async () => {
  wasmLoaded.value = true
  status.value = 'WASM Ready.'
  await checkStoredKey()
}).catch(() => {
  status.value = 'Unable to load browser cryptography or local identity.'
})

async function checkStoredKey() {
  const stored = await loadIdentity('pqc_identity')
  if (stored) {
    hasStoredKey.value = true
    status.value = 'Found existing PQC identity in IndexedDB.'
  }
}

async function generateAndSave() {
  if (!passphrase.value) {
    status.value = 'Please enter a passphrase first.'
    return
  }

  if (hasStoredKey.value) {
    const confirmOverwrite = confirm(
      "WARNING: This device already has a PQC identity stored.\n\n" +
      "If you continue, your current private keys will be permanently overwritten, and you will lose access to any encrypted rooms you have joined.\n\n" +
      "Do you really want to generate new keys?"
    )
    if (!confirmOverwrite) return
  }
  
  status.value = 'Generating and protecting identity keys...'
  try {
    const identity = await generateIdentity(passphrase.value)
    status.value = 'Saving public keys to server...'
    await api.post('/auth/pqc/keys', {
      dilithium_public_key: bytesToB64(identity.dsa_public_key),
      kyber_public_key: bytesToB64(identity.kem_public_key),
    })

    status.value = 'Saving to IndexedDB...'
    await saveIdentity('pqc_identity', identity)

    hasStoredKey.value = true
    status.value = 'Success! Both keys generated, encrypted, stored, and synced.'
    passphrase.value = ''
    
  } catch (err) {
    console.error(err)
    status.value = 'Error: ' + err.message
  }
}
</script>

<template>
  <div class="font-mono w-full">
    <h2 class="text-2xl font-bold text-white mb-2">
      <span class="text-emerald-400">&gt;</span> PQC Identity Settings
    </h2>
    <p class="text-sm text-gray-400 mb-6">
      Manage your Post-Quantum Cryptography (PQC) identity. Your private keys are encrypted with your passphrase and stored locally in your browser's IndexedDB. The server <strong>never</strong> sees your private keys or passphrase.
    </p>

    <!-- Info Box: Changing Passphrase -->
    <div class="bg-gray-900 border border-cyan-500/30 rounded-lg p-4 mb-6">
      <h3 class="text-cyan-400 text-sm font-bold mb-2">💡 What happens if I change my passphrase?</h3>
      <p class="text-xs text-gray-300 mb-2">
        Your passphrase is <strong>only</strong> used to lock/unlock your local private keys on this specific device. It is not tied to your account on the server.
      </p>
      <ul class="text-xs text-gray-400 list-disc list-inside space-y-1">
        <li><strong>If you just want to change it:</strong> You must export your current identity, generate a new one with the new passphrase, and re-import it.</li>
        <li><strong>Old messages:</strong> Changing your passphrase does <strong>not</strong> affect your ability to read old messages, as long as you keep the <em>same</em> ML-KEM (Kyber) private key. The passphrase just encrypts that key locally.</li>
        <li><strong>If you generate a completely new identity:</strong> You will lose access to all existing encrypted rooms because the new ML-KEM key will not match the rooms' encrypted history.</li>
      </ul>
    </div>

    <div class="bg-gray-900 border border-gray-800 rounded-lg p-6">
      <div class="text-xs text-emerald-400 mb-4">{{ status }}</div>
      
      <div class="flex flex-col gap-3">
        <label class="block">
          <span class="text-xs text-gray-400">$ passphrase (to encrypt local keys)</span>
          <input 
            v-model="passphrase" 
            type="password" 
            placeholder="enter a strong passphrase" 
            class="mt-1 w-full bg-gray-950 border border-gray-800 text-gray-100 px-3 py-2 rounded-md text-sm focus:outline-none focus:border-emerald-500"
          />
        </label>
        
        <button 
          @click="generateAndSave" 
          :disabled="!wasmLoaded"
          class="bg-emerald-600 hover:bg-emerald-500 text-gray-950 font-bold py-2 rounded-md text-sm disabled:bg-gray-700 transition-colors"
        >
          {{ hasStoredKey ? 'Regenerate & Overwrite Identity' : 'Generate & Save Identity' }}
        </button>
        
        <p class="text-xs text-gray-500 mt-2">
          Note: If you lose this passphrase, you cannot log in with PQC, and you will lose access to all encrypted rooms. There is no "password reset" because the server cannot read your keys.
        </p>
      </div>
    </div>
  </div>
</template>
