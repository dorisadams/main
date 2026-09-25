/**
 * Tests for useVerification hook — mobile-hardened flow.
 * Uses synthetic evidence only, no real media or secrets.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { renderHook, act } from '@testing-library/react'
import { useVerification } from './useVerification'

// We stub the verificationService and evidenceService dynamic imports
vi.mock('../services/verificationService', () => ({
  extractMetadata: vi.fn(),
  fetchProofEventsByVideo: vi.fn(),
  getOnChainProof: vi.fn(),
}))

vi.mock('../services/evidenceService', () => ({
  fetchRecentEvents: vi.fn(),
}))

// Offline mode extracts via the local stego loader; in jsdom the real video
// decode never settles, so stub it deterministically.
vi.mock('../stego', () => ({
  extractMetadata: vi.fn(),
  MalformedEvidenceError: class MalformedEvidenceError extends Error {},
}))

async function getVerifMock() {
  const mod = await import('../services/verificationService')
  return mod as unknown as {
    extractMetadata: ReturnType<typeof vi.fn>
    fetchProofEventsByVideo: ReturnType<typeof vi.fn>
    getOnChainProof: ReturnType<typeof vi.fn>
  }
}

async function getEvidMock() {
  const mod = await import('../services/evidenceService')
  return mod as unknown as { fetchRecentEvents: ReturnType<typeof vi.fn> }
}

function makeVideoFile(name = 'evidence.mp4', type = 'video/mp4', size = 3) {
  const buf = new Uint8Array(size)
  // fill deterministically
  for (let i = 0; i < size; i++) buf[i] = i % 256
  return new File([buf], name, { type })
}

beforeEach(async () => {
  vi.clearAllMocks()
  const vm = await getVerifMock()
  vm.extractMetadata.mockResolvedValue({ hasHarpocratesMetadata: true })
  vm.fetchProofEventsByVideo.mockResolvedValue([])
  vm.getOnChainProof.mockResolvedValue(null)
})

afterEach(() => {
  vi.clearAllMocks()
})

// ── verifyEvidence – positive path ────────────────────────────────────────

describe('useVerification.verifyEvidence – harpocrates metadata found', () => {
  it('sets verifyResult to metadata-only when not fully corroborated', async () => {
    const { result } = renderHook(() => useVerification())
    const file = makeVideoFile()

    await act(async () => {
      await result.current.verifyEvidence(file)
    })

    expect(result.current.verifyResult).toMatch(/Metadata only/i)
    expect(result.current.status).toBe('success')
  })

  it('populates verifyHash with a 64-char hex string', async () => {
    const { result } = renderHook(() => useVerification())

    await act(async () => {
      await result.current.verifyEvidence(makeVideoFile())
    })

    expect(result.current.verifyHash).toHaveLength(64)
    expect(result.current.verifyHash).toMatch(/^[0-9a-f]+$/)
  })

  it('stores db events when returned', async () => {
    const vm = await getVerifMock()
    vm.fetchProofEventsByVideo.mockResolvedValue([
      { id: 1, event_type: 'registered', file_name: null, video_hash: null, proof_id: null, tier: null, created_at: '' },
      { id: 2, event_type: 'registered', file_name: null, video_hash: null, proof_id: null, tier: null, created_at: '' },
    ])

    const { result } = renderHook(() => useVerification())

    await act(async () => {
      await result.current.verifyEvidence(makeVideoFile())
    })

    expect(result.current.events).toHaveLength(2)
  })

  it('shows confirmed when on-chain proof and db corroborate metadata', async () => {
    const vm = await getVerifMock()
    vm.fetchProofEventsByVideo.mockResolvedValue([
      { id: 1, event_type: 'registered', file_name: null, video_hash: null, proof_id: null, tier: null, created_at: '' },
    ])
    vm.getOnChainProof.mockResolvedValue({
      videoHash: 'a'.repeat(64),
      metadataHash: 'b'.repeat(64),
      tier: 1,
      status: 1,
      createdAt: '1000',
      source: null,
      issuer: null,
    })

    const { result } = renderHook(() => useVerification())

    await act(async () => {
      await result.current.verifyEvidence(makeVideoFile())
    })

    expect(result.current.verifyResult).toMatch(/confirmed/i)
    expect(result.current.verifyResult).toMatch(/corroborated/i)
    expect(result.current.chainProof).not.toBeNull()
    expect(result.current.status).toBe('success')
    expect(result.current.errorCode).toBeNull()
  })

  it('existing compatible evidence still succeeds', async () => {
    const vm = await getVerifMock()
    vm.fetchProofEventsByVideo.mockResolvedValue([
      { id: 1, event_type: 'registered', file_name: 'old.mp4', video_hash: 'a'.repeat(64), proof_id: 'c'.repeat(64), tier: 'source', created_at: '2026-01-01T00:00:00Z' },
    ])
    vm.getOnChainProof.mockResolvedValue({
      videoHash: 'a'.repeat(64),
      metadataHash: 'b'.repeat(64),
      tier: 1,
      status: 1,
      createdAt: '1000',
      source: null,
      issuer: null,
    })
    const { result } = renderHook(() => useVerification())
    await act(async () => {
      await result.current.verifyEvidence(makeVideoFile('old.mp4'))
    })
    expect(result.current.status).toBe('success')
    expect(result.current.verifyResult).toMatch(/confirmed/i)
  })
})

// ── no metadata path ────────────────────────────────────

describe('useVerification.verifyEvidence – no harpocrates metadata', () => {
  it('reports database-only or unverified when metadata missing', async () => {
    const vm = await getVerifMock()
    vm.extractMetadata.mockResolvedValue({ hasHarpocratesMetadata: false })

    const { result } = renderHook(() => useVerification())

    await act(async () => {
      await result.current.verifyEvidence(makeVideoFile())
    })

    expect(result.current.verifyResult).toMatch(/No verification evidence found|Database record only/i)
    expect(result.current.status).toBe('success')
  })

  it('reports database-only when db has records but no metadata', async () => {
    const vm = await getVerifMock()
    vm.extractMetadata.mockResolvedValue({ hasHarpocratesMetadata: false })
    vm.fetchProofEventsByVideo.mockResolvedValue([
      { id: 1, event_type: 'registered', file_name: null, video_hash: null, proof_id: null, tier: null, created_at: '' },
    ])
    const { result } = renderHook(() => useVerification())
    await act(async () => {
      await result.current.verifyEvidence(makeVideoFile())
    })
    expect(result.current.verifyResult).toMatch(/Database record only/i)
  })
})

// ── revoked / expired ────────────────────────────────────

describe('useVerification – revoked and expired handling', () => {
  it('marks revoked chain record with REVOKED_EVIDENCE', async () => {
    const vm = await getVerifMock()
    vm.fetchProofEventsByVideo.mockResolvedValue([{ id: 1, event_type: 'registered', file_name: null, video_hash: null, proof_id: null, tier: null, created_at: '' }])
    vm.getOnChainProof.mockResolvedValue({
      videoHash: 'a'.repeat(64), metadataHash: 'b'.repeat(64), tier: 1, status: 2, createdAt: '1000', source: null, issuer: null,
    })
    const { result } = renderHook(() => useVerification())
    await act(async () => { await result.current.verifyEvidence(makeVideoFile()) })
    expect(result.current.status).toBe('error')
    expect(result.current.errorCode).toBe('REVOKED_EVIDENCE')
    expect(result.current.verifyResult).toMatch(/Revoked/i)
    expect(result.current.chainProof).not.toBeNull()
  })

  it('marks expired chain record with EXPIRED_EVIDENCE', async () => {
    const vm = await getVerifMock()
    vm.getOnChainProof.mockResolvedValue({
      videoHash: 'a'.repeat(64), metadataHash: 'b'.repeat(64), tier: 1, status: 3, createdAt: '1000', source: null, issuer: null,
    })
    const { result } = renderHook(() => useVerification())
    await act(async () => { await result.current.verifyEvidence(makeVideoFile()) })
    expect(result.current.status).toBe('error')
    expect(result.current.errorCode).toBe('EXPIRED_EVIDENCE')
    expect(result.current.verifyResult).toMatch(/Expired/i)
  })
})

// ── untrusted input validation ────────────────────────────────────

describe('useVerification – input validation', () => {
  it('rejects empty file with EMPTY_INPUT', async () => {
    const { result } = renderHook(() => useVerification())
    const empty = new File([], 'empty.mp4', { type: 'video/mp4' })
    await act(async () => { await result.current.verifyEvidence(empty) })
    expect(result.current.status).toBe('error')
    expect(result.current.errorCode).toBe('EMPTY_INPUT')
    expect(result.current.verifyResult).toMatch(/No file/i)
  })

  it('rejects unsupported artifact type', async () => {
    const { result } = renderHook(() => useVerification())
    const bad = makeVideoFile('evidence.png', 'image/png')
    await act(async () => { await result.current.verifyEvidence(bad) })
    expect(result.current.status).toBe('error')
    expect(result.current.errorCode).toBe('UNSUPPORTED_ARTIFACT')
  })

  it('rejects oversized artifact', async () => {
    const { result } = renderHook(() => useVerification())
    // Create a file mock with oversized size without allocating huge buffer
    const f = makeVideoFile('big.mp4', 'video/mp4', 10)
    Object.defineProperty(f, 'size', { value: 101 * 1024 * 1024 })
    await act(async () => { await result.current.verifyEvidence(f) })
    expect(result.current.status).toBe('error')
    expect(result.current.errorCode).toBe('OVERSIZED_ARTIFACT')
    expect(result.current.verifyResult).toMatch(/size limit/i)
  })

  it('accepts file at exactly max size', async () => {
    const vm = await getVerifMock()
    const f = makeVideoFile('edge.mp4', 'video/mp4', 10)
    Object.defineProperty(f, 'size', { value: 100 * 1024 * 1024 })
    const { result } = renderHook(() => useVerification())
    await act(async () => { await result.current.verifyEvidence(f) })
    // Should not be oversized — either success or metadata-only depending on mocks
    expect(result.current.errorCode).not.toBe('OVERSIZED_ARTIFACT')
    // Verify mocks were called (validation passed)
    expect(vm.extractMetadata).toHaveBeenCalled()
  })

  it('falls back to generic message when error is not an Error instance still maps to DEPENDENCY_UNAVAILABLE', async () => {
    const vm = await getVerifMock()
    vm.extractMetadata.mockRejectedValue('something weird')
    const { result } = renderHook(() => useVerification())
    await act(async () => { await result.current.verifyEvidence(makeVideoFile()) })
    expect(result.current.status).toBe('error')
    expect(result.current.errorCode).toBe('DEPENDENCY_UNAVAILABLE')
    expect(result.current.verifyResult).toMatch(/unavailable/i)
  })
})

// ── service failure ─────────────────────────────────────

describe('useVerification.verifyEvidence – service unavailable', () => {
  it('maps extraction failure to DEPENDENCY_UNAVAILABLE with safe message', async () => {
    const vm = await getVerifMock()
    vm.extractMetadata.mockRejectedValue(new Error('Extraction service is unavailable.'))
    const { result } = renderHook(() => useVerification())
    await act(async () => { await result.current.verifyEvidence(makeVideoFile()) })
    expect(result.current.status).toBe('error')
    expect(result.current.errorCode).toBe('DEPENDENCY_UNAVAILABLE')
    expect(result.current.verifyResult).toMatch(/unavailable/i)
    // privacy: must not contain raw evidence or witness
    expect(result.current.verifyResult).not.toMatch(/evidence\.mp4/i)
  })

  it('maps db failure to DEPENDENCY_UNAVAILABLE', async () => {
    const vm = await getVerifMock()
    vm.fetchProofEventsByVideo.mockRejectedValue(new Error('Database lookup failed.'))
    const { result } = renderHook(() => useVerification())
    await act(async () => { await result.current.verifyEvidence(makeVideoFile()) })
    expect(result.current.errorCode).toBe('DEPENDENCY_UNAVAILABLE')
  })

  it('maps wallet failure to WALLET_UNAVAILABLE', async () => {
    const vm = await getVerifMock()
    vm.getOnChainProof.mockRejectedValue(new Error('wallet unavailable: connect Freighter'))
    const { result } = renderHook(() => useVerification())
    await act(async () => { await result.current.verifyEvidence(makeVideoFile()) })
    expect(result.current.errorCode).toBe('WALLET_UNAVAILABLE')
    expect(result.current.verifyResult).toMatch(/Wallet/i)
  })

  it('privacy: error does not leak file content or secrets', async () => {
    const vm = await getVerifMock()
    const secret = 'super-secret-witness-value-123'
    vm.extractMetadata.mockRejectedValue(new Error(secret))
    const { result } = renderHook(() => useVerification())
    await act(async () => { await result.current.verifyEvidence(makeVideoFile()) })
    expect(result.current.verifyResult).not.toContain(secret)
    expect(result.current.errorCode).toBe('DEPENDENCY_UNAVAILABLE')
  })
})

// ── cancellation and stale guard ───────────────────────────────────

describe('useVerification – cancellation and race handling', () => {
  it('cancel sets CANCELLED and isVerifying false', async () => {
    const vm = await getVerifMock()
    // Make extract hang until we cancel
    let resolveExtract: (v: unknown) => void
    vm.extractMetadata.mockReturnValue(new Promise(res => { resolveExtract = res as any }))
    vm.fetchProofEventsByVideo.mockResolvedValue([])
    vm.getOnChainProof.mockResolvedValue(null)

    const { result } = renderHook(() => useVerification())
    let p: Promise<void>
    act(() => { p = result.current.verifyEvidence(makeVideoFile()) })
    // allow hashing -> verifying transition
    await act(async () => { await new Promise(r => setTimeout(r, 10)) })
    // should be verifying now (or at least not idle)
    expect(['hashing', 'verifying', 'validating']).toContain(result.current.status)

    await act(async () => { result.current.cancel() })
    // Resolve hanging extract with abort already signalled — should be ignored
    await act(async () => { resolveExtract!({ hasHarpocratesMetadata: true }) })
    await act(async () => { await p!.catch(() => {}) })

    expect(result.current.status).toBe('cancelled')
    expect(result.current.errorCode).toBe('CANCELLED')
    expect(result.current.isVerifying).toBe(false)
  })

  it('repeated verification does not let stale result overwrite newer', async () => {
    const vm = await getVerifMock()
    let firstExtractResolve: (v: unknown) => void
    let firstDbResolve: (v: unknown) => void
    vm.extractMetadata.mockImplementationOnce(() => new Promise(res => { firstExtractResolve = res as any }))
    vm.fetchProofEventsByVideo.mockImplementationOnce(() => new Promise(res => { firstDbResolve = res as any }))
    vm.getOnChainProof.mockResolvedValueOnce(null)
    // Second call: fast, will set different outcome
    const fastMeta = { hasHarpocratesMetadata: false }
    vm.extractMetadata.mockImplementationOnce(async () => fastMeta)
    vm.fetchProofEventsByVideo.mockResolvedValueOnce([])
    vm.getOnChainProof.mockResolvedValueOnce(null)

    const { result } = renderHook(() => useVerification())
    const f1 = makeVideoFile('first.mp4')
    const f2 = makeVideoFile('second.mp4')

    // Start first verification without awaiting (holds pending)
    let p1: Promise<void>
    act(() => { p1 = result.current.verifyEvidence(f1) })
    await act(async () => { await new Promise(r => setTimeout(r, 10)) })
    // Start second while first is pending — should abort first and adopt second
    await act(async () => { await result.current.verifyEvidence(f2) })
    // Now resolve first's pending promises — they should be ignored due to abort/stale guard
    await act(async () => { firstExtractResolve!({ hasHarpocratesMetadata: true }) })
    await act(async () => { firstDbResolve!([{ id: 1, event_type: 'a', file_name: null, video_hash: null, proof_id: null, tier: null, created_at: '' }]) })
    await act(async () => { await p1!.catch(() => {}) })

    // Final state should reflect second file (no metadata) not first
    expect(result.current.verifyResult).toMatch(/No verification evidence found|Database record only/i)
    expect(result.current.status).toBe('success')
  })

  it('retry re-runs last verification', async () => {
    const vm = await getVerifMock()
    vm.extractMetadata.mockResolvedValueOnce({ hasHarpocratesMetadata: true })
    vm.fetchProofEventsByVideo.mockResolvedValueOnce([])
    vm.getOnChainProof.mockResolvedValueOnce(null)
    // retry will call again
    vm.extractMetadata.mockResolvedValueOnce({ hasHarpocratesMetadata: true })
    vm.fetchProofEventsByVideo.mockResolvedValueOnce([{ id: 9, event_type: 'registered', file_name: null, video_hash: null, proof_id: null, tier: null, created_at: '' } as any])
    const { result } = renderHook(() => useVerification())
    await act(async () => { await result.current.verifyEvidence(makeVideoFile()) })
    expect(result.current.events).toHaveLength(0)
    await act(async () => { await result.current.retry() })
    expect(result.current.events).toHaveLength(1)
  })

  it('clear resets state', async () => {
    const { result } = renderHook(() => useVerification())
    await act(async () => { await result.current.verifyEvidence(makeVideoFile()) })
    expect(result.current.verifyHash).not.toBe('')
    await act(async () => { result.current.clear() })
    expect(result.current.verifyHash).toBe('')
    expect(result.current.verifyResult).toBe('')
    expect(result.current.status).toBe('idle')
    expect(result.current.errorCode).toBeNull()
  })
})

// ── verifyEvidence – null file ────────────────────────────────────────────

describe('useVerification.verifyEvidence – null file', () => {
  it('does nothing when called with null', async () => {
    const { result } = renderHook(() => useVerification())

    await act(async () => {
      await result.current.verifyEvidence(null)
    })

    expect(result.current.verifyResult).toBe('')
    expect(result.current.verifyHash).toBe('')
    expect(result.current.status).toBe('idle')
  })
})

// ── loadEvents ────────────────────────────────────────────────────────────

describe('useVerification.loadEvents', () => {
  it('populates events from fetchRecentEvents', async () => {
    const em = await getEvidMock()
    em.fetchRecentEvents.mockResolvedValue([
      { id: 1, event_type: 'registered', file_name: null, video_hash: null, proof_id: null, tier: null, created_at: '' },
    ])

    const { result } = renderHook(() => useVerification())

    await act(async () => {
      await result.current.loadEvents()
    })

    expect(result.current.events).toHaveLength(1)
  })
})

// ── mobile viewport / boundary ───────────────────────────────────────────

describe('useVerification – mobile viewport behavior', () => {
  it('does not overflow on long error messages', async () => {
    const vm = await getVerifMock()
    vm.extractMetadata.mockRejectedValue(new Error('A'.repeat(1000)))
    const { result } = renderHook(() => useVerification())
    await act(async () => { await result.current.verifyEvidence(makeVideoFile()) })
    // Safe message is truncated/stable, not 1000 chars
    expect(result.current.verifyResult.length).toBeLessThan(500)
    expect(result.current.verifyResult).not.toContain('A'.repeat(100))
  })
})

// ── offline mode ───────────────────────────────────────────────────────

function validEmbeddedMetadata(overrides: Record<string, unknown> = {}): Record<string, unknown> {
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

describe('useVerification – offline mode', () => {
  async function getStegoMock() {
    const mod = await import('../stego')
    return mod as unknown as { extractMetadata: ReturnType<typeof vi.fn> }
  }

  beforeEach(async () => {
    const sm = await getStegoMock()
    sm.extractMetadata.mockReset()
    sm.extractMetadata.mockResolvedValue(validEmbeddedMetadata())
  })

  it('defaults to online mode', () => {
    const { result } = renderHook(() => useVerification())
    expect(result.current.offline).toBe(false)
  })

  it('setOffline toggles the mode flag', () => {
    const { result } = renderHook(() => useVerification())
    act(() => { result.current.setOffline(true) })
    expect(result.current.offline).toBe(true)
    act(() => { result.current.setOffline(false) })
    expect(result.current.offline).toBe(false)
  })

  it('verifies locally and never touches network services', async () => {
    const vm = await getVerifMock()
    const { result } = renderHook(() => useVerification())
    act(() => { result.current.setOffline(true) })

    await act(async () => {
      await result.current.verifyEvidence(makeVideoFile())
    })

    expect(result.current.status).toBe('success')
    expect(result.current.errorCode).toBeNull()
    expect(result.current.verifyResult).toMatch(/Locally verified/i)
    expect(result.current.verifyResult).toMatch(/not checked/i)
    expect(result.current.verifyHash).toHaveLength(64)
    expect(result.current.chainProof).toBeNull()
    expect(result.current.events).toHaveLength(0)
    // No backend stego API / NeonDB / RPC calls
    expect(vm.extractMetadata).not.toHaveBeenCalled()
    expect(vm.fetchProofEventsByVideo).not.toHaveBeenCalled()
    expect(vm.getOnChainProof).not.toHaveBeenCalled()
  })

  it('reports tampered binding as invalid evidence in offline mode', async () => {
    const sm = await getStegoMock()
    sm.extractMetadata.mockResolvedValue(validEmbeddedMetadata({ version: 2, videoHash: 'f'.repeat(64) }))
    const vm = await getVerifMock()
    const { result } = renderHook(() => useVerification())
    act(() => { result.current.setOffline(true) })

    await act(async () => {
      await result.current.verifyEvidence(makeVideoFile())
    })

    expect(result.current.status).toBe('error')
    expect(result.current.errorCode).toBe('INVALID_EVIDENCE')
    expect(result.current.verifyResult).toMatch(/does not match/i)
    expect(vm.getOnChainProof).not.toHaveBeenCalled()
  })

  it('reports invalid structures as invalid evidence in offline mode', async () => {
    const sm = await getStegoMock()
    sm.extractMetadata.mockResolvedValue(validEmbeddedMetadata({ protocol: 'not-harpocrates' }))
    const { result } = renderHook(() => useVerification())
    act(() => { result.current.setOffline(true) })

    await act(async () => {
      await result.current.verifyEvidence(makeVideoFile())
    })

    expect(result.current.status).toBe('error')
    expect(result.current.errorCode).toBe('INVALID_EVIDENCE')
    expect(result.current.verifyResult).toMatch(/failed local validation/i)
  })

  it('applies input rejection in offline mode without network calls', async () => {
    const vm = await getVerifMock()
    const { result } = renderHook(() => useVerification())
    act(() => { result.current.setOffline(true) })

    const empty = new File([], 'empty.mp4', { type: 'video/mp4' })
    await act(async () => { await result.current.verifyEvidence(empty) })

    expect(result.current.status).toBe('error')
    expect(result.current.errorCode).toBe('EMPTY_INPUT')
    expect(vm.getOnChainProof).not.toHaveBeenCalled()
  })

  it('maps offline dependency failures to DEPENDENCY_UNAVAILABLE', async () => {
    const sm = await getStegoMock()
    sm.extractMetadata.mockRejectedValue(new Error('decode unavailable in this browser'))
    const vm = await getVerifMock()
    const { result } = renderHook(() => useVerification())
    act(() => { result.current.setOffline(true) })

    await act(async () => {
      await result.current.verifyEvidence(makeVideoFile())
    })

    expect(result.current.status).toBe('error')
    expect(result.current.errorCode).toBe('DEPENDENCY_UNAVAILABLE')
    expect(result.current.verifyResult).toMatch(/No trust decision was made/i)
    expect(vm.getOnChainProof).not.toHaveBeenCalled()
  })

  it('retry keeps offline mode', async () => {
    const vm = await getVerifMock()
    const { result } = renderHook(() => useVerification())
    act(() => { result.current.setOffline(true) })

    await act(async () => { await result.current.verifyEvidence(makeVideoFile()) })
    expect(result.current.verifyResult).toMatch(/Locally verified/i)

    await act(async () => { await result.current.retry() })
    expect(result.current.verifyResult).toMatch(/Locally verified/i)
    expect(vm.getOnChainProof).not.toHaveBeenCalled()
  })

  it('loadEvents does not fetch when offline', async () => {
    const em = await getEvidMock()
    const { result } = renderHook(() => useVerification())
    act(() => { result.current.setOffline(true) })

    await act(async () => { await result.current.loadEvents() })

    expect(em.fetchRecentEvents).not.toHaveBeenCalled()
    expect(result.current.events).toHaveLength(0)
  })

  it('switching back to online uses the network path again', async () => {
    const vm = await getVerifMock()
    const { result } = renderHook(() => useVerification())

    act(() => { result.current.setOffline(true) })
    await act(async () => { await result.current.verifyEvidence(makeVideoFile()) })
    expect(vm.getOnChainProof).not.toHaveBeenCalled()

    act(() => { result.current.setOffline(false) })
    await act(async () => { await result.current.verifyEvidence(makeVideoFile()) })

    expect(vm.extractMetadata).toHaveBeenCalled()
  })

  it('privacy: offline result messages never leak file names or hashes', async () => {
    const sm = await getStegoMock()
    sm.extractMetadata.mockRejectedValue(new Error('witness-secret-x'))
    const { result } = renderHook(() => useVerification())
    act(() => { result.current.setOffline(true) })

    await act(async () => {
      await result.current.verifyEvidence(makeVideoFile('evidence.mp4'))
    })

    expect(result.current.verifyResult).not.toContain('evidence.mp4')
    expect(result.current.verifyResult).not.toContain('witness-secret-x')
  })
})
