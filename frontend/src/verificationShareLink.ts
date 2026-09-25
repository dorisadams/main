/**
 * Shareable verification links — privacy-preserving deep-link *generation*
 * for the Verify portal.
 *
 * Trust boundary: payloads carry only public registry identifiers (hashes,
 * proof id, network passphrase, contract id, optional tx ref / tier). They
 * never embed media, stego blobs, seeds, witness values, nullifiers,
 * credential roots, or private keys.
 *
 * URL shape (hash-routed, compatible with App `initialView`):
 *   `{origin}{pathname}#verify?p=<base64url(canonical-json)>`
 *
 * Compatibility: protocol `harpocrates-verification-link` version 1.
 * Older clients that ignore unknown hash query params keep working.
 * Rollback: remove the generator UI; existing `#verify` navigation is unchanged.
 */

import type { IdentityTier } from './stellarTypes'

export const SHARE_LINK_PROTOCOL = 'harpocrates-verification-link' as const
export const SHARE_LINK_VERSION = 1 as const

/** Soft cap so links stay paste/QR friendly without truncating digests. */
export const MAX_SHARE_PAYLOAD_BYTES = 2_048
export const MAX_SHARE_URL_BYTES = 4_096

export type VerificationSharePayload = {
  protocol: typeof SHARE_LINK_PROTOCOL
  version: typeof SHARE_LINK_VERSION
  videoHash: string
  proofId: string
  metadataHash: string
  network: string
  contractId: string
  transactionRef?: string
  tier?: IdentityTier
}

export type VerificationShareLinkInput = {
  videoHash: string
  proofId: string
  metadataHash: string
  network: string
  contractId: string
  transactionRef?: string
  tier?: IdentityTier
}

export type ShareLinkErrorCode =
  | 'MALFORMED_INPUT'
  | 'INVALID_DIGEST'
  | 'MISSING_FIELD'
  | 'OVERSIZED_PAYLOAD'
  | 'OVERSIZED_URL'
  | 'UNSUPPORTED_PROTOCOL'
  | 'MALFORMED_URL'
  | 'MISSING_PAYLOAD'
  | 'INVALID_FIELD'

export type ShareLinkCreateResult =
  | { ok: true; url: string; payload: VerificationSharePayload; encoded: string }
  | { ok: false; code: ShareLinkErrorCode; message: string }

export type ShareLinkParseResult =
  | { ok: true; payload: VerificationSharePayload }
  | { ok: false; code: ShareLinkErrorCode; message: string }

const SAFE_MESSAGES: Record<ShareLinkErrorCode, string> = {
  MALFORMED_INPUT: 'Share link input is incomplete or malformed.',
  INVALID_DIGEST: 'Share link digests must be 32-byte hex strings.',
  MISSING_FIELD: 'Share link is missing a required public field.',
  OVERSIZED_PAYLOAD: 'Share link payload exceeds the size limit.',
  OVERSIZED_URL: 'Share link URL exceeds the size limit.',
  UNSUPPORTED_PROTOCOL: 'Unsupported share link protocol or version.',
  MALFORMED_URL: 'Share link URL could not be parsed.',
  MISSING_PAYLOAD: 'Share link is missing a verification payload.',
  INVALID_FIELD: 'Share link contains an invalid public field.',
}

/**
 * Build a versioned, public-only verification share payload.
 * Rejects secret-looking keys and invalid digests with stable error codes.
 */
export function createVerificationSharePayload(
  input: VerificationShareLinkInput,
): { ok: true; payload: VerificationSharePayload } | { ok: false; code: ShareLinkErrorCode; message: string } {
  if (!input || typeof input !== 'object') {
    return fail('MALFORMED_INPUT')
  }

  const videoHash = normalizeHex32(input.videoHash)
  const proofId = normalizeHex32(input.proofId)
  const metadataHash = normalizeHex32(input.metadataHash)
  if (!videoHash || !proofId || !metadataHash) {
    return fail('INVALID_DIGEST')
  }

  const network = trimRequired(input.network)
  const contractId = trimRequired(input.contractId)
  if (!network || !contractId) {
    return fail('MISSING_FIELD')
  }

  const payload: VerificationSharePayload = {
    protocol: SHARE_LINK_PROTOCOL,
    version: SHARE_LINK_VERSION,
    videoHash,
    proofId,
    metadataHash,
    network,
    contractId,
  }

  if (input.transactionRef !== undefined && input.transactionRef !== null && input.transactionRef !== '') {
    const tx = normalizeHex32(input.transactionRef)
    if (!tx) return fail('INVALID_DIGEST')
    payload.transactionRef = tx
  }

  if (input.tier !== undefined && input.tier !== null && (input.tier as string) !== '') {
    if (!isTier(input.tier)) return fail('INVALID_FIELD')
    payload.tier = input.tier
  }

  const bytes = utf8(canonicalize(payload)).byteLength
  if (bytes > MAX_SHARE_PAYLOAD_BYTES) {
    return fail('OVERSIZED_PAYLOAD')
  }

  return { ok: true, payload }
}

/** Deterministic JSON (sorted keys) for stable encoding. */
export function serializeVerificationSharePayload(payload: VerificationSharePayload): string {
  return canonicalize(payload)
}

/** Encode payload as URL-safe base64 for the `p` hash query param. */
export function encodeVerificationSharePayload(payload: VerificationSharePayload): string {
  const encoded = base64UrlEncode(utf8(serializeVerificationSharePayload(payload)))
  if (utf8(encoded).byteLength > MAX_SHARE_PAYLOAD_BYTES) {
    throw new Error(SAFE_MESSAGES.OVERSIZED_PAYLOAD)
  }
  return encoded
}

export function decodeVerificationSharePayload(encoded: string): ShareLinkParseResult {
  if (typeof encoded !== 'string' || !encoded) {
    return fail('MISSING_PAYLOAD')
  }
  if (utf8(encoded).byteLength > MAX_SHARE_PAYLOAD_BYTES) {
    return fail('OVERSIZED_PAYLOAD')
  }
  try {
    const json = new TextDecoder().decode(base64UrlDecode(encoded))
    if (utf8(json).byteLength > MAX_SHARE_PAYLOAD_BYTES) {
      return fail('OVERSIZED_PAYLOAD')
    }
    const parsed = JSON.parse(json) as unknown
    return validatePayload(parsed)
  } catch {
    return fail('MALFORMED_INPUT')
  }
}

/**
 * Generate a shareable verification URL for the current origin (or override).
 * Does not mutate location; callers copy/share the returned string.
 */
export function createVerificationShareLink(
  input: VerificationShareLinkInput,
  options?: { baseUrl?: string },
): ShareLinkCreateResult {
  const created = createVerificationSharePayload(input)
  if (!created.ok) return created

  let encoded: string
  try {
    encoded = encodeVerificationSharePayload(created.payload)
  } catch {
    return fail('OVERSIZED_PAYLOAD')
  }

  const base = resolveBaseUrl(options?.baseUrl)
  if (!base) {
    return fail('MALFORMED_URL')
  }

  // Keep view token first so existing `#verify` routing continues to work.
  const url = `${base}#verify?p=${encoded}`
  if (utf8(url).byteLength > MAX_SHARE_URL_BYTES) {
    return fail('OVERSIZED_URL')
  }

  return { ok: true, url, payload: created.payload, encoded }
}

/** Parse a full URL or bare hash fragment into a validated payload. */
export function parseVerificationShareLink(urlOrHash: string): ShareLinkParseResult {
  if (typeof urlOrHash !== 'string' || !urlOrHash.trim()) {
    return fail('MALFORMED_URL')
  }
  if (utf8(urlOrHash).byteLength > MAX_SHARE_URL_BYTES) {
    return fail('OVERSIZED_URL')
  }

  let hash = urlOrHash.trim()
  try {
    if (/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(hash) || hash.startsWith('/') || hash.startsWith('?')) {
      // Absolute or path-like — extract hash via URL when possible
      const asUrl = hash.includes('://')
        ? new URL(hash)
        : new URL(hash, 'https://harpocrates.local/')
      hash = asUrl.hash || hash
    }
  } catch {
    return fail('MALFORMED_URL')
  }

  if (hash.startsWith('#')) hash = hash.slice(1)
  // Accept `verify?p=...` or `verify&p=...` (defensive)
  const qIndex = hash.indexOf('?')
  const view = (qIndex >= 0 ? hash.slice(0, qIndex) : hash).replace(/^\//, '')
  if (view && view !== 'verify') {
    // Not a verification share link — treat as missing payload rather than hard fail
    // when callers probe arbitrary hashes.
    if (!hash.includes('p=')) return fail('MISSING_PAYLOAD')
  }

  const query = qIndex >= 0 ? hash.slice(qIndex + 1) : ''
  let encoded: string | null = null
  try {
    const params = new URLSearchParams(query)
    encoded = params.get('p')
  } catch {
    return fail('MALFORMED_URL')
  }

  if (!encoded) return fail('MISSING_PAYLOAD')
  return decodeVerificationSharePayload(encoded)
}

export function shareLinkErrorMessage(code: ShareLinkErrorCode): string {
  return SAFE_MESSAGES[code]
}

function validatePayload(value: unknown): ShareLinkParseResult {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return fail('MALFORMED_INPUT')
  }
  const record = value as Record<string, unknown>

  // Reject secret-looking keys immediately (privacy-safe parse failures).
  for (const key of Object.keys(record)) {
    if (/(seed|secret|witness|nullifier|credential|private|proofBytes|publicInputs)/i.test(key)) {
      return fail('INVALID_FIELD')
    }
  }

  if (record.protocol !== SHARE_LINK_PROTOCOL || record.version !== SHARE_LINK_VERSION) {
    return fail('UNSUPPORTED_PROTOCOL')
  }

  const videoHash = normalizeHex32(record.videoHash)
  const proofId = normalizeHex32(record.proofId)
  const metadataHash = normalizeHex32(record.metadataHash)
  if (!videoHash || !proofId || !metadataHash) return fail('INVALID_DIGEST')

  const network = typeof record.network === 'string' ? trimRequired(record.network) : null
  const contractId = typeof record.contractId === 'string' ? trimRequired(record.contractId) : null
  if (!network || !contractId) return fail('MISSING_FIELD')

  const payload: VerificationSharePayload = {
    protocol: SHARE_LINK_PROTOCOL,
    version: SHARE_LINK_VERSION,
    videoHash,
    proofId,
    metadataHash,
    network,
    contractId,
  }

  if (record.transactionRef !== undefined && record.transactionRef !== null && record.transactionRef !== '') {
    const tx = normalizeHex32(record.transactionRef)
    if (!tx) return fail('INVALID_DIGEST')
    payload.transactionRef = tx
  }

  if (record.tier !== undefined && record.tier !== null && record.tier !== '') {
    if (!isTier(record.tier)) return fail('INVALID_FIELD')
    payload.tier = record.tier
  }

  const bytes = utf8(canonicalize(payload)).byteLength
  if (bytes > MAX_SHARE_PAYLOAD_BYTES) return fail('OVERSIZED_PAYLOAD')

  return { ok: true, payload }
}

function fail(code: ShareLinkErrorCode): { ok: false; code: ShareLinkErrorCode; message: string } {
  return { ok: false, code, message: SAFE_MESSAGES[code] }
}

function resolveBaseUrl(override?: string): string | null {
  if (override !== undefined) {
    const trimmed = override.trim().replace(/\/$/, '')
    if (!trimmed) return null
    try {
      // Validate absolute URL
      const u = new URL(trimmed)
      return `${u.origin}${u.pathname === '/' ? '' : u.pathname.replace(/\/$/, '')}`
    } catch {
      return null
    }
  }
  if (typeof window !== 'undefined' && window.location) {
    const { origin, pathname } = window.location
    const path = pathname === '/' ? '' : pathname.replace(/\/$/, '')
    return `${origin}${path}`
  }
  return null
}

function normalizeHex32(value: unknown): string | null {
  if (typeof value !== 'string') return null
  const trimmed = value.trim().toLowerCase()
  if (!/^[0-9a-f]{64}$/.test(trimmed)) return null
  return trimmed
}

function trimRequired(value: string): string | null {
  const trimmed = value.trim()
  return trimmed.length > 0 ? trimmed : null
}

function isTier(value: unknown): value is IdentityTier {
  return value === 'silent' || value === 'source' || value === 'seal'
}

function canonicalize(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value)
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`
  const record = value as Record<string, unknown>
  return `{${Object.keys(record)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalize(record[key])}`)
    .join(',')}}`
}

function utf8(value: string): Uint8Array {
  return new TextEncoder().encode(value)
}

function base64UrlEncode(bytes: Uint8Array): string {
  let binary = ''
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '')
}

function base64UrlDecode(value: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) throw new Error('invalid base64url data')
  const padded = value.replaceAll('-', '+').replaceAll('_', '/') + '='.repeat((4 - (value.length % 4)) % 4)
  const binary = atob(padded)
  return Uint8Array.from(binary, (character) => character.charCodeAt(0))
}
