<script setup>
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { useAuthStore } from '../../core/auth'
import api from '../../core/api'
import { bytesToB64 } from '../../core/crypto.js'
import { generateIdentity } from '../../core/pqc.js'
import { saveIdentity } from '../../core/pqc-db.js'

const auth = useAuthStore()
const router = useRouter()

const username = ref('')
const passphrase = ref('')
const error = ref('')
const loading = ref(false)

async function submit() {
  error.value = ''
  if (!username.value || !passphrase.value) {
    error.value = 'Please fill in all fields.'
    return
  }
  
  loading.value = true
  try {
    const identity = await generateIdentity(passphrase.value)
    await api.post('/auth/register', {
      username: username.value,
      dilithium_public_key: bytesToB64(identity.dsa_public_key),
      kyber_public_key: bytesToB64(identity.kem_public_key),
    })
    await saveIdentity('pqc_identity', identity)

    // 7. Update auth store and redirect
    await auth.fetchMe()
    router.push('/rooms')
    
  } catch (e) {
    error.value = e.response?.data?.error || e.message || 'Registration failed'
  } finally {
    loading.value = false
  }
}
</script>

<template>
  <div class="bg-gray-900/80 backdrop-blur border border-gray-800 rounded-lg p-6 shadow-2xl shadow-cyan-500/5 font-mono">
    <div class="flex items-center justify-between mb-5">
      <div class="flex gap-1.5">
        <span class="w-3 h-3 rounded-full bg-red-500/70"></span>
        <span class="w-3 h-3 rounded-full bg-yellow-500/70"></span>
        <span class="w-3 h-3 rounded-full bg-cyan-500/70"></span>
      </div>
      <span class="font-mono text-xs text-gray-500 ml-2">register.sh</span>
    </div>

    <form @submit.prevent="submit" class="flex flex-col gap-3">
      <label class="block">
        <span class="text-xs text-gray-400">$ new_username</span>
        <input 
          v-model="username" 
          autocomplete="username" 
          spellcheck="false"
          class="mt-1 w-full bg-gray-950 border border-gray-800 text-cyan-300 px-3 py-2 rounded-md font-mono text-sm focus:outline-none focus:border-cyan-500 placeholder-gray-600" 
          placeholder="choose username"
        />
      </label>

      <label class="block">
        <span class="text-xs text-gray-400">$ passphrase (encrypts your private keys)</span>
        <input 
          v-model="passphrase" 
          type="password" 
          class="mt-1 w-full bg-gray-950 border border-gray-800 text-cyan-300 px-3 py-2 rounded-md font-mono text-sm focus:outline-none focus:border-cyan-500 placeholder-gray-600" 
          placeholder="enter a strong passphrase"
        />
        <p class="text-[10px] text-gray-500 mt-1">If you lose this, you lose access to your account.</p>
      </label>

      <button 
        type="submit" 
        :disabled="loading" 
        class="mt-3 bg-cyan-600 hover:bg-cyan-500 text-gray-950 font-bold py-2 rounded-md font-mono text-sm transition-colors disabled:bg-gray-700 disabled:text-gray-500"
      >
        {{ loading ? '> generating keys...' : '> create_account' }}
      </button>

      <p v-if="error" class="text-xs text-red-400 font-mono mt-1">
        <span class="text-red-500">✗</span> {{ error }}
      </p>
    </form>

    <div class="mt-5 pt-4 border-t border-gray-800 text-center font-mono text-xs text-gray-500">
      already have an identity?
      <router-link to="/pqc-login" class="text-cyan-400 hover:text-cyan-300 hover:underline">
        login()
      </router-link>
    </div>
  </div>
</template>
