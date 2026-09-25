/**
 * offlineVerification — local-only verification for the Verification Portal.
 *
 * Verifies a received video entirely in the browser with zero network calls:
 *   - local SHA-256 of the received file,
 *   - local stego envelope extraction (the same loader that `verificationFlow`
 *     and the batch workspace use — never a second protocol truth),
 *   - structural validation of the embedded metadata, mirroring the backend
 *     envelope grammar (protocol / version / tier / sourceHash / proofId /
 *     timestamp),
 *   - file→metadata binding when the embedded metadata carries a video hash;
 *     otherwise the binding is reported as *unavailable*, never assumed.
 *
 * Trust boundary: offline local verification NEVER yields a confirmed trust
 * decision or a shareable receipt. On-chain status (revocation / expiry /
 * nullifier replay), NeonDB presence, and Silent Witness proof bytes live
 * behind network boundaries and are reported as not checked. See
 * THREAT_MODEL.md (§5 Trust Boundaries) and frontend/ACCESSIBILITY.md
 * (Local Verification Workflow).
 *
 * Privacy guarantees: no media bytes, video hashes, proof material, seeds,
 * or private keys are ever written to logs or surfaced in messages. Embedded
 * metadata that carries secret-shaped keys is rejected up-front and rendered
 * as `null` so hostile artifacts are never replayed to the UI or AT.
 */

import { MalformedEvidenceError } from './stego'

export const OFFLINE_FILE_SIZE_LIMIT_BYTES = 100 * 1024 * 1024
export const OFFLINE_SUPPORTED_PREFIX = 'video/'

export type OfflineErrorCode =
  | 'EMPTY_INPUT'
  | 'UNSUPPORTED_ARTIFACT'
  | 'OVERSIZED_ARTIFACT'
  | 'INVALID_EVIDENCE'
  | 'DEPENDENCY_UNAVAILABLE'
  | 'CANCELLED'

export type MetadataExtractor = (file: File, signal?: AbortSignal) => Promise<unknown>

const DEFAULT_EXTRACTOR: MetadataExtractor = async (file, signal) => {
  if (signal?.aborted) throw abortError()
  const { extractMetadata } = await import('./stego')
  return extractMetadata(file)
}

/** Top-level metadata keys that must never be present in an offline envelope. */
const FORBIDDEN_METADATA_KEY = /seed|secret|witness|nullifier|credential|publicinputs|proofbytes|private/i

const ALLOWED_TIERS = new Set(['silent', 'source', 'seal'])
const HEX_32 = /^[0-9a-fA-F]{64}$/
const TZ_AWARE_ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/i

export type OfflineCheckOutcome = 'ok' | 'failed'
export type OfflineBindingOutcome = 'bound' | 'tampered' | 'unavailable'

export type OfflineChecks = {
  /** Local stego envelope extraction (magic + size + body checksum + JSON). */
  envelope: OfflineCheckOutcome
  /** Structural validation of the embedded metadata. */
  structure: OfflineCheckOutcome
  /** File→metadata binding. `unavailable` when the envelope carries no hash. */
  binding: OfflineBindingOutcome
  /** True when the envelope carried secret-shaped keys and was rejected. */
  secretsPresent: boolean
}

export type OfflineVerificationOutcome =
  | 'verified-local'
  | 'malformed'
  | 'rejected'
  | 'dependency-unavailable'
  | 'cancelled'

/** Redacted view of the validated metadata — public fields only. */
export type RedactedOfflineMetadata = {
  tier: string | null
  version: number | null
  timestamp: string | null
}

export type OfflineVerificationResult = {
  outcome: OfflineVerificationOutcome
  errorCode: OfflineErrorCode | null
  /** Lowercase SHA-256 hex of the received file; empty when input was rejected. */
  fileHash: string
  /** Stable, privacy-safe copy. Never carries file names, hashes, or secrets. */
  message: string
  checks: OfflineChecks
  metadata: RedactedOfflineMetadata | null
}

const MESSAGES: Record<OfflineErrorCode, string> = {
  EMPTY_INPUT: 'No file provided. Choose a video to verify.',
  UNSUPPORTED_ARTIFACT: 'Unsupported file type. Provide an MP4, WebM, or MOV video.',
  OVERSIZED_ARTIFACT: 'File exceeds the size limit (100 MB). Choose a smaller artifact.',
  INVALID_EVIDENCE: 'No valid embedded Harpocrates metadata was found in this artifact.',
  DEPENDENCY_UNAVAILABLE: 'Offline verification is unavailable in this browser. No trust decision was made.',
  CANCELLED: 'Verification cancelled.',
}

const STRUCTURE_MESSAGE =
  'Invalid evidence: the embedded Harpocrates metadata failed local validation.'
const BINDING_MESSAGE =
  'Invalid evidence: the file does not match its embedded Harpocrates metadata.'

const VERIFIED_BOUND_MESSAGE =
  'Locally verified: the file matches its embedded Harpocrates metadata. On-chain and registry status were not checked (offline). Treat this as a local check only, not as confirmed evidence.'
const VERIFIED_UNBOUND_MESSAGE =
  'Locally verified: the artifact carries a valid Harpocrates metadata envelope. On-chain and registry status were not checked (offline), and this envelope does not bind a file hash. Treat this as a local check only, not as confirmed evidence.'

function abortError(): DOMException {
  return new DOMException('Aborted', 'AbortError')
}

function isAbort(error: unknown, signal?: AbortSignal): boolean {
  if (signal?.aborted) return true
  return (
    error instanceof DOMException && error.name === 'AbortError' ||
    (error instanceof Error &&
      (error.name === 'AbortError' || error.name === 'FlowCancelledError' || /aborted|cancelled/i.test(error.message)))
  )
}

function abortIfNeeded(signal?: AbortSignal): void {
  if (signal?.aborted) throw abortError()
}

type FileRejection = { outcome: 'rejected'; errorCode: OfflineErrorCode }

function rejectFile(file: File): FileRejection | null {
  if (!file || file.size === 0) return { outcome: 'rejected', errorCode: 'EMPTY_INPUT' }
  if (file.size > OFFLINE_FILE_SIZE_LIMIT_BYTES) return { outcome: 'rejected', errorCode: 'OVERSIZED_ARTIFACT' }
  if (file.type && !file.type.startsWith(OFFLINE_SUPPORTED_PREFIX)) {
    return { outcome: 'rejected', errorCode: 'UNSUPPORTED_ARTIFACT' }
  }
  return null
}

/**
 * Locally verify a received video. No network, storage, or logging writes.
 *
 * `options.extractor` is injectable for deterministic tests; it defaults to
 * the same `stego.extractMetadata` loader used everywhere else in the app.
 */
export async function verifyOffline(
  file: File,
  options?: { signal?: AbortSignal; extractor?: MetadataExtractor },
): Promise<OfflineVerificationResult> {
  const signal = options?.signal
  const extractor = options?.extractor ?? DEFAULT_EXTRACTOR

  const inputRejection = rejectFile(file)
  if (inputRejection) {
    return {
      outcome: inputRejection.outcome,
      errorCode: inputRejection.errorCode,
      fileHash: '',
      message: MESSAGES[inputRejection.errorCode],
      checks: { envelope: 'failed', structure: 'failed', binding: 'unavailable', secretsPresent: false },
      metadata: null,
    }
  }

  let fileHash = ''
  try {
    abortIfNeeded(signal)
    const buffer = await file.arrayBuffer()
    abortIfNeeded(signal)
    fileHash = await sha256Hex(buffer)
    abortIfNeeded(signal)

    let extracted: unknown
    try {
      extracted = await extractor(file, signal)
    } catch (error) {
      if (isAbort(error, signal)) {
        return cancelledResult(fileHash)
      }
      // Absent or malformed envelope (stego rejects) and hard environment
      // failures are kept distinct: only dependency failures map to
      // DEPENDENCY_UNAVAILABLE so the UI can stay precise.
      if (error instanceof MalformedEvidenceError) {
        return invalidResult(fileHash)
      }
      return {
        outcome: 'dependency-unavailable',
        errorCode: 'DEPENDENCY_UNAVAILABLE',
        fileHash,
        message: MESSAGES.DEPENDENCY_UNAVAILABLE,
        checks: { envelope: 'failed', structure: 'failed', binding: 'unavailable', secretsPresent: false },
        metadata: null,
      }
    }

    // Envelope present but no usable object payload.
    if (extracted === null || typeof extracted !== 'object' || Array.isArray(extracted)) {
      abortIfNeeded(signal)
      return invalidResult(fileHash)
    }
    const metadata = extracted as Record<string, unknown>

    // Privacy guard: reject secret-shaped envelopes before any field is read.
    const forbiddenKey = Object.keys(metadata).find((key) => FORBIDDEN_METADATA_KEY.test(key))
    if (forbiddenKey !== undefined) {
      return {
        outcome: 'malformed',
        errorCode: 'INVALID_EVIDENCE',
        fileHash,
        message: STRUCTURE_MESSAGE,
        checks: { envelope: 'ok', structure: 'failed', binding: 'unavailable', secretsPresent: true },
        metadata: null,
      }
    }

    const structure = validateMetadataStructure(metadata)
    if (!structure.ok) {
      abortIfNeeded(signal)
      return {
        outcome: 'malformed',
        errorCode: 'INVALID_EVIDENCE',
        fileHash,
        message: STRUCTURE_MESSAGE,
        checks: { envelope: 'ok', structure: 'failed', binding: 'unavailable', secretsPresent: false },
        metadata: null,
      }
    }

    let binding: OfflineBindingOutcome = 'unavailable'
    if (typeof metadata.videoHash === 'string' && metadata.videoHash.length > 0) {
      binding = fileHash.toLowerCase() === metadata.videoHash.toLowerCase() ? 'bound' : 'tampered'
      if (binding === 'tampered') {
        abortIfNeeded(signal)
        return {
          outcome: 'malformed',
          errorCode: 'INVALID_EVIDENCE',
          fileHash,
          message: BINDING_MESSAGE,
          checks: { envelope: 'ok', structure: 'ok', binding, secretsPresent: false },
          metadata: null,
        }
      }
    }

    abortIfNeeded(signal)
    return {
      outcome: 'verified-local',
      errorCode: null,
      fileHash,
      message: binding === 'bound' ? VERIFIED_BOUND_MESSAGE : VERIFIED_UNBOUND_MESSAGE,
      checks: { envelope: 'ok', structure: 'ok', binding, secretsPresent: false },
      metadata: {
        tier: typeof metadata.tier === 'string' ? metadata.tier : null,
        version: typeof metadata.version === 'number' ? metadata.version : null,
        timestamp: typeof metadata.timestamp === 'string' ? metadata.timestamp : null,
      },
    }
  } catch (error) {
    if (isAbort(error, signal)) return cancelledResult(fileHash)
    throw error
  }
}

function cancelledResult(fileHash: string): OfflineVerificationResult {
  return {
    outcome: 'cancelled',
    errorCode: 'CANCELLED',
    fileHash,
    message: MESSAGES.CANCELLED,
    checks: { envelope: 'failed', structure: 'failed', binding: 'unavailable', secretsPresent: false },
    metadata: null,
  }
}

function invalidResult(fileHash: string): OfflineVerificationResult {
  return {
    outcome: 'malformed',
    errorCode: 'INVALID_EVIDENCE',
    fileHash,
    message: MESSAGES.INVALID_EVIDENCE,
    checks: { envelope: 'ok', structure: 'failed', binding: 'unavailable', secretsPresent: false },
    metadata: null,
  }
}

/**
 * Structural validation of an extracted metadata object. Mirrors the backend
 * envelope grammar (`backend/envelope.py validate_v1/validate_v2`): required
 * protocol/version/tier/sourceHash/proofId/timestamp, allowed tier set, and
 * a timezone-aware ISO-8601 timestamp.
 */
export function validateMetadataStructure(
  metadata: Record<string, unknown>,
): { ok: true } | { ok: false } {
  if (metadata.protocol !== 'harpocrates') return { ok: false }
  if (typeof metadata.version !== 'number' || (metadata.version !== 1 && metadata.version !== 2)) {
    return { ok: false }
  }
  if (typeof metadata.tier !== 'string' || !ALLOWED_TIERS.has(metadata.tier)) return { ok: false }
  if (!is32ByteHex(metadata.sourceHash)) return { ok: false }
  if (!is32ByteHex(metadata.proofId)) return { ok: false }
  if (!isTzAwareIsoTimestamp(metadata.timestamp)) return { ok: false }

  if (typeof metadata.videoHash === 'string' && metadata.videoHash.length > 0 && !is32ByteHex(metadata.videoHash)) {
    return { ok: false }
  }
  return { ok: true }
}

function is32ByteHex(value: unknown): value is string {
  return typeof value === 'string' && HEX_32.test(value)
}

function isTzAwareIsoTimestamp(value: unknown): value is string {
  if (typeof value !== 'string' || value.trim() === '') return false
  const candidate = value.trim().replace(/Z$/i, '+00:00')
  if (!TZ_AWARE_ISO.test(candidate)) return false
  return !Number.isNaN(Date.parse(candidate))
}

async function sha256Hex(buffer: ArrayBuffer): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', buffer)
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, '0')).join('')
}