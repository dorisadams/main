import { UltraHonkBackend } from '@aztec/bb.js'
import { Noir } from '@noir-lang/noir_js'
import type { CompiledCircuit } from '@noir-lang/types'
import { encodeFieldToBytes32Hex, encodePublicInputs } from './verifierInputs'

type SilentWitnessProof = {
  credentialRoot: string
  nullifier: string
  /** Domain tag as a 32-byte hex string (no 0x prefix). */
  domainTag: string
  proof: string
  /** Hex-encoded public inputs: 5 × 32 bytes = 160 bytes (320 hex chars). */
  publicInputs: string
  proofBytes: number
  publicInputBytes: number
}

type AggregatedProof = {
  protocol: string
  version: number
  type: string
  batchId: string
  batchSize: number
  maxBatchSize: number
  videoHashes: string[]
  proof: string
  publicInputs: string
  proofBytes: number
  publicInputBytes: number
}

type GenerateSilentWitnessInput = {
  videoHash: string
  credentialSecret: string
  nullifierSecret: string
  /** Scope field element (BN254). Pass '0' for global/unscoped. */
  verifierScope?: string
  /** Epoch number. Pass 0 for unscoped or legacy proofs. */
  epoch?: number
}

type GenerateAggregatedProofInput = {
  videoHashes: string[]
  credentialSecret: string
  nullifierSecret: string
}

let helperCircuitPromise: Promise<CompiledCircuit> | null = null
let mainCircuitPromise: Promise<CompiledCircuit> | null = null
let aggregatorCircuitPromise: Promise<CompiledCircuit> | null = null
let aggregatorHelperCircuitPromise: Promise<CompiledCircuit> | null = null

/**
 * Generate a Silent Witness Noir/UltraHonk proof.
 *
 * The helper circuit computes (credential_root, nullifier, domain_tag) from
 * the private inputs so the browser never needs to reproduce the Pedersen
 * hash in JavaScript.  domain_tag binds the proof to the Harpocrates protocol
 * version and network embedded in the circuit constants — a proof generated
 * for testnet will fail the in-circuit assert if submitted to a mainnet
 * verifier with different embedded constants.
 */
export async function generateSilentWitnessProof({
  videoHash,
  credentialSecret,
  nullifierSecret,
  verifierScope = '0',
  epoch = 0,
}: GenerateSilentWitnessInput): Promise<SilentWitnessProof> {
  const [helperCircuit, mainCircuit] = await Promise.all([loadHelperCircuit(), loadMainCircuit()])

  const video_hash_hi = BigInt(`0x${videoHash.slice(0, 32)}`).toString(10)
  const video_hash_lo = BigInt(`0x${videoHash.slice(32)}`).toString(10)
  const scope_field = BigInt(verifierScope).toString(10)
  const epoch_field = BigInt(epoch).toString(10)
  const privateInputs = {
    credential_secret: credentialSecret,
    nullifier_secret: nullifierSecret,
    video_hash_hi,
    video_hash_lo,
    verifier_scope: scope_field,
    epoch: epoch_field,
  }

  // Helper returns (credential_root, nullifier, domain_tag).
  const helperResult = await new Noir(helperCircuit).execute(privateInputs)
  const [credentialRoot, nullifier, domainTag] = helperResult.returnValue as string[]

  const publicInputs = {
    credential_root: credentialRoot,
    nullifier,
    verifier_scope: scope_field,
    epoch: epoch_field,
  }

  const { witness } = await new Noir(mainCircuit).execute({
    ...privateInputs,
    ...publicInputs,
  })

  const backend = new UltraHonkBackend(mainCircuit.bytecode)
  try {
    const proofData = await backend.generateProof(witness, { keccak: true })
    const proofHex = bytesToHex(proofData.proof)

    // Public inputs in on-chain ordering:
    //   [0] video_hash_hi, [1] video_hash_lo, [2] credential_root,
    //   [3] nullifier,     [4] domain_tag
    const publicInputHex = encodePublicInputs(proofData.publicInputs, [
      'video_hash_hi',
      'video_hash_lo',
      'credential_root',
      'nullifier',
      'domain_tag',
    ])
    return {
      credentialRoot: encodeFieldToBytes32Hex(credentialRoot, 'credential_root'),
      nullifier: encodeFieldToBytes32Hex(nullifier, 'nullifier'),
      domainTag: encodeFieldToBytes32Hex(domainTag, 'domain_tag'),
      proof: proofHex,
      publicInputs: publicInputHex,
      proofBytes: proofData.proof.length,
      publicInputBytes: publicInputHex.length / 2,
    }
  } finally {
    await backend.destroy()
  }
}

const MAX_AGGREGATION_SIZE = 8

/**
 * Generate a bounded aggregated proof for multiple video hashes under the
 * same credential identity.
 *
 * Uses the `silent_witness_aggregator` circuit which can bundle up to
 * ``MAX_AGGREGATION_SIZE`` (8) individual Silent Witness proofs into a
 * single UltraHonk proof.
 *
 * @throws {Error} If the batch size exceeds MAX_AGGREGATION_SIZE or if any
 *   video hash is invalid.
 */
export async function generateAggregatedProof({
  videoHashes,
  credentialSecret,
  nullifierSecret,
}: GenerateAggregatedProofInput): Promise<AggregatedProof> {
  const batchSize = videoHashes.length
  if (batchSize < 1 || batchSize > MAX_AGGREGATION_SIZE) {
    throw new Error(
      `Batch size must be between 1 and ${MAX_AGGREGATION_SIZE} (got ${batchSize})`
    )
  }

  for (const vh of videoHashes) {
    if (!/^[0-9a-fA-F]{64}$/.test(vh)) {
      throw new Error(`Invalid video hash: ${vh}`)
    }
  }

  const [helperCircuit, aggCircuit] = await Promise.all([
    loadAggregatorHelperCircuit(),
    loadAggregatorCircuit(),
  ])

  // Build helper circuit inputs
  const helperInputs: Record<string, string> = {
    credential_secret: credentialSecret,
    nullifier_secret: nullifierSecret,
  }
  for (let i = 0; i < MAX_AGGREGATION_SIZE; i++) {
    if (i < batchSize) {
      const vh = videoHashes[i]
      helperInputs[`video_hash_hi_${i}`] = BigInt(`0x${vh.slice(0, 32)}`).toString(10)
      helperInputs[`video_hash_lo_${i}`] = BigInt(`0x${vh.slice(32)}`).toString(10)
    } else {
      helperInputs[`video_hash_hi_${i}`] = '0'
      helperInputs[`video_hash_lo_${i}`] = '0'
    }
  }

  // Run helper circuit to derive batch public inputs
  const helperResult = await new Noir(helperCircuit).execute(helperInputs)
  const batchResults = helperResult.returnValue as [string, string][]

  // Build aggregator circuit inputs
  const aggInputs: Record<string, string> = {
    credential_secret: credentialSecret,
    nullifier_secret: nullifierSecret,
  }
  for (let i = 0; i < MAX_AGGREGATION_SIZE; i++) {
    const vh = i < batchSize ? videoHashes[i] : '0000000000000000000000000000000000000000000000000000000000000000'
    const credentialRoot = batchResults[i][0]
    const nullifier = batchResults[i][1]

    aggInputs[`video_hash_hi_${i}`] = BigInt(`0x${vh.slice(0, 32)}`).toString(10)
    aggInputs[`video_hash_lo_${i}`] = BigInt(`0x${vh.slice(32)}`).toString(10)
    aggInputs[`credential_root_${i}`] = credentialRoot
    aggInputs[`nullifier_${i}`] = nullifier
  }

  // Generate the aggregated UltraHonk proof
  const { witness } = await new Noir(aggCircuit).execute(aggInputs)

  const backend = new UltraHonkBackend(aggCircuit.bytecode)
  try {
    const proofData = await backend.generateProof(witness, { keccak: true })
    const proofHex = bytesToHex(proofData.proof)
    const publicInputHex = proofData.publicInputs.map((v) => encodeFieldToBytes32Hex(v)).join('')

    // Generate deterministic batch ID from the video hashes
    const batchId = await sha256(videoHashes.join(':'))

    return {
      protocol: 'harpocrates',
      version: 1,
      type: 'aggregated_batch',
      batchId,
      batchSize,
      maxBatchSize: MAX_AGGREGATION_SIZE,
      videoHashes: videoHashes.map((vh) => vh.toLowerCase()),
      proof: proofHex,
      publicInputs: publicInputHex,
      proofBytes: proofData.proof.length,
      publicInputBytes: publicInputHex.length / 2,
    }
  } finally {
    await backend.destroy()
  }
}

async function loadHelperCircuit() {
  helperCircuitPromise ??= loadCircuit('/noir/silent_witness_helper.json')
  return helperCircuitPromise
}

async function loadMainCircuit() {
  mainCircuitPromise ??= loadCircuit('/noir/silent_witness.json')
  return mainCircuitPromise
}

async function loadAggregatorCircuit() {
  aggregatorCircuitPromise ??= loadCircuit('/noir/silent_witness_aggregator.json')
  return aggregatorCircuitPromise
}

async function loadAggregatorHelperCircuit() {
  aggregatorHelperCircuitPromise ??= loadCircuit('/noir/silent_witness_aggregator_helper.json')
  return aggregatorHelperCircuitPromise
}

async function loadCircuit(path: string) {
  const response = await fetch(path)
  if (!response.ok) {
    throw new Error(`Unable to load Noir circuit artifact: ${path}`)
  }
  return (await response.json()) as CompiledCircuit
}

function bytesToHex(bytes: Uint8Array) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('')
}

async function sha256(input: string): Promise<string> {
  const bytes = new TextEncoder().encode(input)
  const hash = await crypto.subtle.digest('SHA-256', bytes)
  return bytesToHex(new Uint8Array(hash))
}
