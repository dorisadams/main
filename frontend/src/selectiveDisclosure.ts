import { Barretenberg, UltraHonkBackend, Fr } from '@aztec/bb.js'
import { Noir } from '@noir-lang/noir_js'
import type { CompiledCircuit } from '@noir-lang/types'
import type {
  Predicate,
  SelectiveDisclosureInput,
  SelectiveDisclosureProof,
} from './types/schema'
import { SCHEMA_CONSTANTS } from './types/schema'
import { encodePublicInputs } from './verifierInputs'

let circuitPromise: Promise<CompiledCircuit> | null = null
let bbPromise: Promise<Barretenberg> | null = null

async function getBB(): Promise<Barretenberg> {
  bbPromise ??= Barretenberg.new()
  return bbPromise
}

async function pedersenHash(inputs: bigint[]): Promise<bigint> {
  const bb = await getBB()
  // bb.js 0.87 hashes Fr-typed inputs with an explicit domain index and
  // returns a Fr; unwrap it back to the bigint domain the callers use.
  const result = await bb.pedersenHash(inputs.map((v) => new Fr(v)), 0)
  return BigInt(result.toString())
}

function padPredicates(predicates: Predicate[]): Predicate[] {
  const padded = [...predicates]
  while (padded.length < SCHEMA_CONSTANTS.MAX_PREDICATES) {
    padded.push({
      predicateType: 'Equality',
      attrIndex: 0,
      publicValue: '0',
      setValues: Array(SCHEMA_CONSTANTS.MAX_SET_MEMBERS).fill('0'),
      setLen: 0,
      lowerBound: '0',
      upperBound: '0',
    })
  }
  return padded
}

function padArray<T>(arr: T[], len: number, fill: T): T[] {
  const padded = [...arr]
  while (padded.length < len) {
    padded.push(fill)
  }
  return padded
}

async function computePredicateCommitment(predicates: Predicate[]): Promise<string> {
  const padded = padPredicates(predicates)
  let current = BigInt(0)
  for (let i = 0; i < padded.length; i++) {
    const p = padded[i]
    const predType = BigInt(p.predicateType === 'Equality' ? 0 : p.predicateType === 'SetMembership' ? 1 : 2)
    const attrIndex = BigInt(i < predicates.length ? p.attrIndex : 0)
    const publicValue = BigInt(i < predicates.length ? (p.publicValue ?? '0') : '0')
    current = await pedersenHash([current, predType, attrIndex, publicValue])
  }
  return current.toString()
}

function toBigInt(value: string): bigint {
  const hex = value.startsWith('0x') ? value : '0x' + value
  return BigInt(hex)
}

export async function computeNullifier(
  credentialRoot: string,
  videoHashHi: string,
  videoHashLo: string,
  evidenceDigest: string,
): Promise<string> {
  const result = await pedersenHash([
    toBigInt(credentialRoot),
    toBigInt(videoHashHi),
    toBigInt(videoHashLo),
    toBigInt(evidenceDigest),
  ])
  return result.toString()
}

export async function generateSelectiveDisclosureProof(
  input: SelectiveDisclosureInput,
): Promise<SelectiveDisclosureProof> {
  const circuit = await loadCircuit()

  const paddedAttrs = padArray(input.attrValues, SCHEMA_CONSTANTS.MAX_ATTRIBUTES, '0')
  const paddedBlindings = padArray(input.attrBlindings, SCHEMA_CONSTANTS.MAX_ATTRIBUTES, '0')
  const paddedPredicates = padPredicates(input.predicates)

  const witnessInputs = {
    schema_hash: toBigInt(input.schemaHash).toString(10),
    issuer_namespace: toBigInt(input.issuerNamespace).toString(10),
    schema_version: input.schemaVersion.toString(),
    credential_root: toBigInt(input.credentialRoot).toString(10),
    nullifier: toBigInt(input.nullifier).toString(10),
    video_hash_hi: toBigInt(input.videoHashHi).toString(10),
    video_hash_lo: toBigInt(input.videoHashLo).toString(10),
    verifier_digest: toBigInt(input.verifierDigest).toString(10),
    circuit_version: input.circuitVersion.toString(),
    evidence_digest: toBigInt(input.evidenceDigest).toString(10),
    predicate_commitment: toBigInt(await computePredicateCommitment(input.predicates)).toString(10),
    num_attributes: input.numAttributes.toString(),
    attr_values: paddedAttrs.map((v) => toBigInt(v).toString(10)),
    attr_blindings: paddedBlindings.map((v) => toBigInt(v).toString(10)),
    num_predicates: input.numPredicates.toString(),
    predicates: paddedPredicates.map((p) => ({
      predicate_type: p.predicateType === 'Equality' ? '0' : p.predicateType === 'SetMembership' ? '1' : '2',
      attr_index: p.attrIndex.toString(),
      public_value: toBigInt(p.publicValue ?? '0').toString(10),
      set_values: padArray(p.setValues ?? [], SCHEMA_CONSTANTS.MAX_SET_MEMBERS, '0').map((v) => toBigInt(v).toString(10)),
      set_len: (p.setLen ?? 0).toString(),
      lower_bound: toBigInt(p.lowerBound ?? '0').toString(10),
      upper_bound: toBigInt(p.upperBound ?? '0').toString(10),
    })),
  }

  const { witness } = await new Noir(circuit).execute(witnessInputs)

  const backend = new UltraHonkBackend(circuit.bytecode)
  try {
    const proofData = await backend.generateProof(witness, { keccak: true })
    const proofHex = bytesToHex(proofData.proof)
    const publicInputHex = encodePublicInputs(proofData.publicInputs)

    return {
      proof: proofHex,
      publicInputs: publicInputHex,
    }
  } finally {
    await backend.destroy()
  }
}

async function loadCircuit() {
  circuitPromise ??= fetchCircuit('/noir/selective_disclosure.json')
  return circuitPromise
}

async function fetchCircuit(path: string) {
  const response = await fetch(path)
  if (!response.ok) {
    throw new Error(`Unable to load Noir circuit artifact: ${path}`)
  }
  return (await response.json()) as CompiledCircuit
}

function bytesToHex(bytes: Uint8Array) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('')
}
