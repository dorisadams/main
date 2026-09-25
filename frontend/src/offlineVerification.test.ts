/**
 * Tests for offlineVerification — local-only verification.
 * Uses synthetic evidence only, no real media or secrets.
 */

import { describe, it, expect, vi } from 'vitest'
import { verifyOffline, validateMetadataStructure, OFFLINE_FILE_SIZE_LIMIT_BYTES } from './offlineVerification'
import { MalformedEvidenceError } from './stego'

function makeVideoFile(name = 'evidence.mp4', type = 'video/mp4', size = 3) {
  const buf = new Uint8Array(size)
  // fill deterministically
  for (let i = 0; i < size; i++) buf[i] = i % 256
  return new File([buf], name, { type })
}

function validMetadata(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    protocol: 'harpocrates',
    version: 1,
    tier: 'silent',
    sourceHash: 'a'.repeat(64),
    proofId: 'b'.repeat(64),
    timestamp: '2026-01-01T00:00:00.000Z',
    ...overrides,
  }
}

function extractorReturning(value: unknown) {
  return vi.fn(async () => value)
}

async function sha256HexBuffer(buffer: ArrayBuffer): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', buffer)
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, '0')).join('')
}

// ── happy paths ───────────────────────────────────────────────────────────

describe('verifyOffline – valid envelopes', () => {
  it('v1 envelope (no video hash) verifies locally with binding unavailable', async () => {
    const file = makeVideoFile()
    const result = await verifyOffline(file, { extractor: extractorReturning(validMetadata()) })

    expect(result.outcome).toBe('verified-local')
    expect(result.errorCode).toBeNull()
    expect(result.fileHash).toHaveLength(64)
    expect(result.checks).toEqual({
      envelope: 'ok',
      structure: 'ok',
      binding: 'unavailable',
      secretsPresent: false,
    })
    expect(result.metadata).toMatchObject({ tier: 'silent', version: 1 })
    expect(result.message).toMatch(/Locally verified/i)
    expect(result.message).toMatch(/not checked/i)
    // never an affirmative confirm / shareable framing (copy says "not as
    // confirmed evidence", which is the guarantee we assert on)
    expect(result.message).not.toMatch(/^Confirmed/i)
  })

  it('v2 envelope with matching video hash reports bound binding', async () => {
    const file = makeVideoFile()
    const fileHash = await sha256HexBuffer(await file.arrayBuffer())
    const metadata = validMetadata({ version: 2, videoHash: fileHash })

    const result = await verifyOffline(file, { extractor: extractorReturning(metadata) })

    expect(result.outcome).toBe('verified-local')
    expect(result.checks.binding).toBe('bound')
    expect(result.message).toMatch(/matches its embedded Harpocrates metadata/i)
  })

  it('accepts a file at exactly the max size', async () => {
    const file = makeVideoFile('edge.mp4', 'video/mp4', 10)
    Object.defineProperty(file, 'size', { value: OFFLINE_FILE_SIZE_LIMIT_BYTES })
    const result = await verifyOffline(file, { extractor: extractorReturning(validMetadata()) })
    expect(result.outcome).toBe('verified-local')
  })
})

// ── binding / structure failures ──────────────────────────────────────────

describe('verifyOffline – tampered and malformed evidence', () => {
  it('mismatched video hash fails as tampered binding', async () => {
    const file = makeVideoFile()
    const result = await verifyOffline(file, {
      extractor: extractorReturning(validMetadata({ version: 2, videoHash: 'f'.repeat(64) })),
    })

    expect(result.outcome).toBe('malformed')
    expect(result.errorCode).toBe('INVALID_EVIDENCE')
    expect(result.checks).toEqual({
      envelope: 'ok',
      structure: 'ok',
      binding: 'tampered',
      secretsPresent: false,
    })
    expect(result.metadata).toBeNull()
    expect(result.message).toMatch(/does not match/i)
  })

  it('missing envelope rejects with stable invalid-evidence copy', async () => {
    const file = makeVideoFile()
    const result = await verifyOffline(file, { extractor: vi.fn(async () => null) })
    expect(result.outcome).toBe('malformed')
    expect(result.errorCode).toBe('INVALID_EVIDENCE')
    expect(result.message).toMatch(/No valid embedded Harpocrates metadata/i)
  })

  it('maps a stego MalformedEvidenceError to malformed (absent/invalid envelope)', async () => {
    const file = makeVideoFile()
    const extractor = vi.fn(async () => {
      throw new MalformedEvidenceError('no metadata found')
    })
    const result = await verifyOffline(file, { extractor })
    expect(result.outcome).toBe('malformed')
    expect(result.errorCode).toBe('INVALID_EVIDENCE')
  })

  it('non-object extraction payload rejects as invalid evidence', async () => {
    const file = makeVideoFile()
    const result = await verifyOffline(file, { extractor: extractorReturning(['not', 'object']) })
    expect(result.outcome).toBe('malformed')
    expect(result.errorCode).toBe('INVALID_EVIDENCE')
  })

  it.each([
    ['wrong protocol', { protocol: 'harpocrotes' }],
    ['unsupported version', { version: 3 }],
    ['unknown tier', { tier: 'zygote' }],
    ['short sourceHash', { sourceHash: 'abcd' }],
    ['short proofId', { proofId: 'abcd' }],
    ['naive timestamp without offset', { timestamp: '2026-01-01T00:00:00' }],
    ['non-string timestamp', { timestamp: 12345 }],
    ['invalid videoHash length', { version: 2, videoHash: 'xy' }],
  ])('rejects %s structurally', async (_label, overrides) => {
    const file = makeVideoFile()
    const result = await verifyOffline(file, { extractor: extractorReturning(validMetadata(overrides)) })
    expect(result.outcome).toBe('malformed')
    expect(result.errorCode).toBe('INVALID_EVIDENCE')
    expect(result.checks.structure).toBe('failed')
    expect(result.metadata).toBeNull()
  })
})

// ── privacy guard ─────────────────────────────────────────────────────────

describe('verifyOffline – privacy guard', () => {
  it.each(['credentialRoot', 'nullifierSecret', 'witness', 'proofBytes', 'privateKey'])(
    'rejects envelope carrying secret-shaped key %s and redacts metadata',
    async (key) => {
      const file = makeVideoFile()
      const result = await verifyOffline(file, {
        extractor: extractorReturning(validMetadata({ [key]: 'x'.repeat(64) })),
      })
      expect(result.outcome).toBe('malformed')
      expect(result.errorCode).toBe('INVALID_EVIDENCE')
      expect(result.checks.secretsPresent).toBe(true)
      expect(result.checks.envelope).toBe('ok')
      expect(result.metadata).toBeNull()
    },
  )

  it('never leaks file names, hashes, or secrets in any message', async () => {
    const file = makeVideoFile('private-witness.mp4')
    const secret = 'super-secret-witness-value-123'
    const tampered = makeVideoFile()
    const cases = [
      verifyOffline(new File([], 'empty.mp4', { type: 'video/mp4' })),
      verifyOffline(file, { extractor: extractorReturning(validMetadata({ credentialRoot: secret })) }),
      verifyOffline(tampered, {
        extractor: extractorReturning(validMetadata({ version: 2, videoHash: 'f'.repeat(64) })),
      }),
      verifyOffline(file, { extractor: vi.fn(async () => { throw new Error(secret) }) }),
    ]
    for (const promise of cases) {
      const result = await promise
      expect(result.message).not.toContain('private-witness.mp4')
      expect(result.message).not.toContain(secret)
      expect(result.message).not.toMatch(/[0-9a-fA-F]{64}/)
    }
  })
})

// ── dependency / cancellation ─────────────────────────────────────────────

describe('verifyOffline – dependency and cancellation', () => {
  it('extractor environment failure maps to DEPENDENCY_UNAVAILABLE with no trust decision', async () => {
    const file = makeVideoFile()
    const result = await verifyOffline(file, {
      extractor: vi.fn(async () => { throw new Error('video decode unavailable') }),
    })
    expect(result.outcome).toBe('dependency-unavailable')
    expect(result.errorCode).toBe('DEPENDENCY_UNAVAILABLE')
    expect(result.message).toMatch(/No trust decision was made/i)
  })

  it('propagates mid-flight abort from the extractor as cancelled', async () => {
    const file = makeVideoFile()
    const controller = new AbortController()
    const result = await verifyOffline(file, {
      signal: controller.signal,
      extractor: vi.fn(async () => {
        controller.abort()
        throw new DOMException('Aborted', 'AbortError')
      }),
    })
    expect(result.outcome).toBe('cancelled')
    expect(result.errorCode).toBe('CANCELLED')
  })

  it('pre-aborted signal yields CANCELLED with a stable message', async () => {
    const file = makeVideoFile()
    const controller = new AbortController()
    controller.abort()
    const result = await verifyOffline(file, {
      signal: controller.signal,
      extractor: extractorReturning(validMetadata()),
    })
    expect(result.outcome).toBe('cancelled')
    expect(result.errorCode).toBe('CANCELLED')
    expect(result.message).toBe('Verification cancelled.')
  })

  it('abort raised by extractor is treated as cancelled', async () => {
    const file = makeVideoFile()
    const result = await verifyOffline(file, {
      extractor: vi.fn(async () => {
        throw new DOMException('Aborted', 'AbortError')
      }),
    })
    expect(result.outcome).toBe('cancelled')
    expect(result.errorCode).toBe('CANCELLED')
  })
})

// ── input rejects ─────────────────────────────────────────────────────────

describe('verifyOffline – input validation', () => {
  it('rejects empty file with EMPTY_INPUT', async () => {
    const file = new File([], 'empty.mp4', { type: 'video/mp4' })
    const result = await verifyOffline(file, { extractor: extractorReturning(validMetadata()) })
    expect(result.outcome).toBe('rejected')
    expect(result.errorCode).toBe('EMPTY_INPUT')
    expect(result.fileHash).toBe('')
    expect(result.message).toMatch(/No file/i)
  })

  it('rejects unsupported artifact type', async () => {
    const file = makeVideoFile('evidence.png', 'image/png')
    const result = await verifyOffline(file, { extractor: extractorReturning(validMetadata()) })
    expect(result.outcome).toBe('rejected')
    expect(result.errorCode).toBe('UNSUPPORTED_ARTIFACT')
  })

  it('rejects oversized artifact', async () => {
    const file = makeVideoFile('big.mp4', 'video/mp4', 10)
    Object.defineProperty(file, 'size', { value: OFFLINE_FILE_SIZE_LIMIT_BYTES + 1 })
    const result = await verifyOffline(file, { extractor: extractorReturning(validMetadata()) })
    expect(result.outcome).toBe('rejected')
    expect(result.errorCode).toBe('OVERSIZED_ARTIFACT')
    expect(result.message).toMatch(/size limit/i)
  })

  it('does not call the extractor for rejected input', async () => {
    const extractor = extractorReturning(validMetadata())
    await verifyOffline(new File([], 'nope.mp4', { type: 'video/mp4' }), { extractor })
    expect(extractor).not.toHaveBeenCalled()
  })
})

// ── structural validator ──────────────────────────────────────────────────

describe('validateMetadataStructure', () => {
  it('accepts canonical v1 and v2 metadata', () => {
    expect(validateMetadataStructure(validMetadata())).toEqual({ ok: true })
    expect(
      validateMetadataStructure(validMetadata({ version: 2, videoHash: 'c'.repeat(64) })),
    ).toEqual({ ok: true })
  })

  it.each([
    ['no protocol', { protocol: undefined }],
    ['no tier', { tier: undefined }],
    ['no sourceHash', { sourceHash: undefined }],
    ['no proofId', { proofId: undefined }],
    ['no timestamp', { timestamp: undefined }],
  ])('rejects missing %s', (_label, overrides) => {
    expect(validateMetadataStructure(validMetadata(overrides))).toEqual({ ok: false })
  })

  it('accepts uppercase timestamp UTC marker', () => {
    expect(validateMetadataStructure(validMetadata({ timestamp: '2026-01-01T00:00:00Z' }))).toEqual({ ok: true })
  })

  it('accepts offset timestamps', () => {
    expect(validateMetadataStructure(validMetadata({ timestamp: '2026-01-01T09:30:00+02:00' }))).toEqual({ ok: true })
  })

  it('rejects impossible dates', () => {
    expect(validateMetadataStructure(validMetadata({ timestamp: '2026-13-99T00:00:00Z' }))).toEqual({ ok: false })
  })
})