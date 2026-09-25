import type { IdentityTier, TxState } from './stellar'

const CHECKPOINT_STORAGE_KEY = 'harpocrates:evidence-checkpoint'
const CHECKPOINT_VERSION = 1
const PBKDF2_ITERATIONS = 600000

export type SilentWitnessProofData = {
  credentialRoot: string
  nullifier: string
  proof: string
  publicInputs: string
  proofBytes: number
  publicInputBytes: number
}

export type EvidenceStateData = {
  stage: 'idle' | 'hashing' | 'embedding' | 'proving' | 'ready' | 'registering' | 'registered' | 'error'
  tier: IdentityTier
  fileName?: string
  sourceHash?: string
  videoHash?: string
  metadataHash?: string
  proofId?: string
  timestamp?: string
  silentWitness?: SilentWitnessProofData
  txHash?: string
  txStatus?: TxState
  error?: string
  updatedAt: number
}

export interface CheckpointEnvelope {
  v: number
  salt: string
  iv: string
  ct: string
}

function bufToHex(buffer: ArrayBuffer): string {
  return [...new Uint8Array(buffer)].map((b) => b.toString(16).padStart(2, '0')).join('')
}

function hexToBuf(hex: string): Uint8Array<ArrayBuffer> {
  const bytes = new Uint8Array(Math.ceil(hex.length / 2))
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16)
  }
  return bytes
}

async function deriveKey(password: string, salt: ArrayBuffer): Promise<CryptoKey> {
  const enc = new TextEncoder()
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    enc.encode(password),
    { name: 'PBKDF2' },
    false,
    ['deriveBits', 'deriveKey']
  )
  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: PBKDF2_ITERATIONS,
      hash: 'SHA-256',
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false, // extractable
    ['encrypt', 'decrypt']
  )
}

export class CheckpointStorage {
  static hasCheckpoint(): boolean {
    return !!window.localStorage.getItem(CHECKPOINT_STORAGE_KEY)
  }

  static async save(password: string, state: EvidenceStateData): Promise<void> {
    const salt = crypto.getRandomValues(new Uint8Array(16))
    const key = await deriveKey(password, salt as unknown as ArrayBuffer)

    const iv = crypto.getRandomValues(new Uint8Array(12))
    const enc = new TextEncoder()
    const pt = enc.encode(JSON.stringify(state))

    const ct = await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: iv as unknown as ArrayBuffer,
      },
      key,
      pt
    )

    const envelope: CheckpointEnvelope = {
      v: CHECKPOINT_VERSION,
      salt: bufToHex(salt as unknown as ArrayBuffer),
      iv: bufToHex(iv as unknown as ArrayBuffer),
      ct: bufToHex(ct),
    }

    window.localStorage.setItem(CHECKPOINT_STORAGE_KEY, JSON.stringify(envelope))
  }

  static async load(password: string, maxAgeMs = 24 * 60 * 60 * 1000): Promise<EvidenceStateData | null> {
    const stored = window.localStorage.getItem(CHECKPOINT_STORAGE_KEY)
    if (!stored) return null

    let envelope: CheckpointEnvelope
    try {
      envelope = JSON.parse(stored)
    } catch {
      this.clear()
      throw new Error('Checkpoint corrupted')
    }

    if (envelope.v !== CHECKPOINT_VERSION) {
      this.clear()
      throw new Error(`Unsupported checkpoint version: ${envelope.v}`)
    }

    const salt = hexToBuf(envelope.salt)
    const iv = hexToBuf(envelope.iv)
    const ct = hexToBuf(envelope.ct)

    try {
      const key = await deriveKey(password, salt as unknown as ArrayBuffer)
      const pt = await crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: iv as unknown as ArrayBuffer,
        },
        key,
        ct as unknown as ArrayBuffer
      )

      const dec = new TextDecoder()
      const state = JSON.parse(dec.decode(pt)) as EvidenceStateData

      if (Date.now() - state.updatedAt > maxAgeMs) {
        this.clear()
        return null // Expired
      }

      return state
    } catch (e) {
      throw new Error('Invalid checkpoint password')
    }
  }

  static clear(): void {
    window.localStorage.removeItem(CHECKPOINT_STORAGE_KEY)
  }
}
