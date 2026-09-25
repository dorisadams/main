/**
 * useVerification — manages the verification portal flow:
 * local hash → stego extract → NeonDB lookup → on-chain query (online),
 * or a fully local, offline-safe equivalent (offline mode).
 *
 * Offline mode makes ZERO network calls: it hashes and extracts locally and
 * performs structural/binding checks only. It never yields a confirmed trust
 * decision — chain/registry status is reported as not checked. See
 * `offlineVerification.ts`.
 *
 * Mobile-hardened: input validation, AbortController cancellation, stale-result
 * guard, and privacy-safe error codes. No raw evidence, media, or secrets are
 * written to logs or user-facing errors beyond stable categories.
 */

import { useCallback, useEffect, useRef, useState } from 'react'
import type { ChainProofRecord } from '../stellarTypes'
import type { ProofEvent } from '../types'
import { ApiClientError, toVerificationErrorCode } from '../services/apiError'

export type VerificationStatus = 'idle' | 'validating' | 'hashing' | 'verifying' | 'success' | 'error' | 'cancelled'

export type VerificationErrorCode =
  | 'EMPTY_INPUT'
  | 'UNSUPPORTED_ARTIFACT'
  | 'OVERSIZED_ARTIFACT'
  | 'INVALID_EVIDENCE'
  | 'EXPIRED_EVIDENCE'
  | 'REVOKED_EVIDENCE'
  | 'VERIFICATION_FAILED'
  | 'DEPENDENCY_UNAVAILABLE'
  | 'CANCELLED'
  | 'WALLET_UNAVAILABLE'

// 100 MB — frontend guard, consistent with batchVerifier DEFAULT_BATCH_CONFIG
// (100 MB per-file) and within backend MAX_VIDEO_BYTES (250 MB, backend/config.py).
// Do not raise above backend limit; see docs/streaming-uploads.md UPLOAD_MAX_BYTES.
const MAX_VERIFY_FILE_BYTES = 100 * 1024 * 1024

const SAFE_MESSAGES: Record<VerificationErrorCode, string> = {
  EMPTY_INPUT: 'No file provided. Choose a video to verify.',
  UNSUPPORTED_ARTIFACT: 'Unsupported file type. Provide an MP4, WebM, or MOV video.',
  OVERSIZED_ARTIFACT: 'File exceeds the size limit (100 MB). Choose a smaller artifact.',
  INVALID_EVIDENCE: 'Invalid evidence: the file could not be verified as Harpocrates evidence.',
  EXPIRED_EVIDENCE: 'Expired: the chain record for this artifact has expired. Do not treat it as valid evidence.',
  REVOKED_EVIDENCE: 'Revoked: the chain record for this artifact has been revoked. Do not trust it as valid evidence.',
  VERIFICATION_FAILED: 'Verification failed. No trust decision was made.',
  DEPENDENCY_UNAVAILABLE: 'Verification services are unavailable. No trust decision was made.',
  CANCELLED: 'Verification cancelled.',
  WALLET_UNAVAILABLE: 'Wallet unavailable. Connect a wallet or try again without wallet lookup.',
}

function isAbortError(error: unknown): boolean {
  return (
    error instanceof DOMException && error.name === 'AbortError' ||
    (error instanceof Error && (error.name === 'AbortError' || /aborted|cancelled/i.test(error.message)))
  )
}

function mapChainStatus(status: number): VerificationErrorCode | null {
  if (status === 2) return 'REVOKED_EVIDENCE'
  if (status === 3) return 'EXPIRED_EVIDENCE'
  return null
}

function validateFile(file: File): { ok: true } | { ok: false; code: VerificationErrorCode } {
  if (file.size === 0) return { ok: false, code: 'EMPTY_INPUT' }
  if (file.size > MAX_VERIFY_FILE_BYTES) return { ok: false, code: 'OVERSIZED_ARTIFACT' }
  // Allow empty type (some mobile browsers omit it) but reject clearly unsupported types
  if (file.type && !file.type.startsWith('video/')) {
    return { ok: false, code: 'UNSUPPORTED_ARTIFACT' }
  }
  return { ok: true }
}

export type UseVerificationReturn = {
  verifyHash: string
  verifyResult: string
  events: ProofEvent[]
  chainProof: ChainProofRecord | null
  status: VerificationStatus
  errorCode: VerificationErrorCode | null
  isVerifying: boolean
  /** True when verification runs fully offline (no network calls). */
  offline: boolean
  setOffline: (next: boolean) => void
  verifyEvidence: (file: File | null, walletAddress?: string) => Promise<void>
  loadEvents: () => Promise<void>
  cancel: () => void
  retry: () => Promise<void>
  clear: () => void
}

export function useVerification(): UseVerificationReturn {
  const [verifyHash, setVerifyHash] = useState('')
  const [verifyResult, setVerifyResult] = useState('')
  const [events, setEvents] = useState<ProofEvent[]>([])
  const [chainProof, setChainProof] = useState<ChainProofRecord | null>(null)
  const [status, setStatus] = useState<VerificationStatus>('idle')
  const [errorCode, setErrorCode] = useState<VerificationErrorCode | null>(null)
  // Offline mode mirrors the user-visible toggle so retries/effect reads stay
  // consistent even when the toggle could change mid-flow.
  const [offline, setOfflineState] = useState(false)
  const offlineRef = useRef(false)
  const setOffline = useCallback((next: boolean) => {
    offlineRef.current = next
    setOfflineState(next)
  }, [])

  const seqRef = useRef(0)
  const abortRef = useRef<AbortController | null>(null)
  const lastFileRef = useRef<{ file: File; wallet?: string } | null>(null)

  const isVerifying = status === 'validating' || status === 'hashing' || status === 'verifying'

  const clear = useCallback(() => {
    abortRef.current?.abort()
    abortRef.current = null
    seqRef.current += 1
    setVerifyHash('')
    setVerifyResult('')
    setEvents([])
    setChainProof(null)
    setStatus('idle')
    setErrorCode(null)
    lastFileRef.current = null
  }, [])

  const cancel = useCallback(() => {
    abortRef.current?.abort()
    // Immediately reflect cancellation in UI so mobile user sees feedback, even if
    // in-flight mocks do not reject with AbortError
    setStatus('cancelled')
    setErrorCode('CANCELLED')
    setVerifyResult(SAFE_MESSAGES.CANCELLED)
  }, [])

  const loadEvents = useCallback(async () => {
    // Offline mode never reaches the NeonDB feed.
    if (offlineRef.current) return
    try {
      const { fetchRecentEvents } = await import('../services/evidenceService')
      const loaded = await fetchRecentEvents(6)
      setEvents(loaded)
    } catch {
      // keep existing events; surface no sensitive detail
    }
  }, [])

  const runVerify = useCallback(async (file: File, walletAddress: string | undefined, seq: number, signal: AbortSignal) => {
    // Validate synchronously before any expensive work
    const validated = validateFile(file)
    if (!validated.ok) {
      if (seq !== seqRef.current) return
      setStatus('error')
      setErrorCode(validated.code)
      setVerifyResult(SAFE_MESSAGES[validated.code])
      // keep hash empty so UI does not show stale hash for rejected input
      return
    }

    setStatus('hashing')
    setErrorCode(null)
    setVerifyResult('Hashing evidence locally…')
    setChainProof(null)
    setEvents([])

    let videoHash: string
    try {
      const { sha256 } = await import('../utils')
      // Allow early abort before reading
      if (signal.aborted) throw new DOMException('Aborted', 'AbortError')
      const buffer = await file.arrayBuffer()
      if (signal.aborted) throw new DOMException('Aborted', 'AbortError')
      videoHash = await sha256(buffer)
      if (signal.aborted) throw new DOMException('Aborted', 'AbortError')
      if (seq !== seqRef.current) return
      setVerifyHash(videoHash)
    } catch (error) {
      if (isAbortError(error) || signal.aborted) {
        if (seq !== seqRef.current) return
        setStatus('cancelled')
        setErrorCode('CANCELLED')
        setVerifyResult(SAFE_MESSAGES.CANCELLED)
        return
      }
      if (seq !== seqRef.current) return
      setStatus('error')
      setErrorCode('INVALID_EVIDENCE')
      setVerifyResult(SAFE_MESSAGES.INVALID_EVIDENCE)
      return
    }

    setStatus('verifying')
    setVerifyResult('Inspecting evidence…')

    try {
      const { extractMetadata, fetchProofEventsByVideo, getOnChainProof } = await import(
        '../services/verificationService'
      )

      if (signal.aborted) throw new DOMException('Aborted', 'AbortError')

      // Extract and DB lookup share the same abort signal; on-chain has no signal but we race it
      const extractP = extractMetadata(file, signal)
      const dbP = fetchProofEventsByVideo(videoHash, signal)
      const chainP = getOnChainProof(videoHash, walletAddress)

      // If signal aborts, chainP will still resolve but we will discard due to stale guard
      const [extractResult, dbMatches, onChain] = await Promise.all([extractP, dbP, chainP])

      if (seq !== seqRef.current) return
      if (signal.aborted) {
        setStatus('cancelled')
        setErrorCode('CANCELLED')
        setVerifyResult(SAFE_MESSAGES.CANCELLED)
        return
      }

      // Canonical revoked/expired handling takes precedence over metadata presence
      const chainCode = onChain ? mapChainStatus(onChain.status) : null
      if (chainCode) {
        setStatus('error')
        setErrorCode(chainCode)
        setVerifyResult(SAFE_MESSAGES[chainCode])
        setEvents(dbMatches)
        setChainProof(onChain)
        return
      }

      const hasMetadata = extractResult.hasHarpocratesMetadata
      // Privacy-safe, stable user messages — no file names, hashes, or raw proof data
      if (hasMetadata && dbMatches.length > 0 && onChain) {
        setVerifyResult(
          'Confirmed: embedded Harpocrates metadata is corroborated by database and active chain records.',
        )
      } else if (hasMetadata) {
        setVerifyResult(
          'Metadata only: embedded Harpocrates metadata lacks complete database and chain confirmation. Treat this artifact as unconfirmed.',
        )
      } else if (dbMatches.length > 0) {
        setVerifyResult(
          'Database record only: no valid embedded Harpocrates metadata or chain record was found. Treat this artifact as unconfirmed.',
        )
      } else {
        setVerifyResult(
          'No verification evidence found: metadata, database, and chain records did not confirm this artifact. Treat it as unverified.',
        )
      }
      setEvents(dbMatches)
      setChainProof(onChain)
      setStatus('success')
      setErrorCode(null)
    } catch (error) {
      if (isAbortError(error) || signal.aborted) {
        if (seq !== seqRef.current) return
        setStatus('cancelled')
        setErrorCode('CANCELLED')
        setVerifyResult(SAFE_MESSAGES.CANCELLED)
        return
      }
      if (seq !== seqRef.current) return
      // Map structured backend errors to actionable verification codes; keep wallet heuristic.
      const mapped = toVerificationErrorCode(error)
      if (mapped) {
        setStatus('error')
        setErrorCode(mapped)
        // Prefer actionable API message for oversized/unsupported/invalid; else stable copy.
        const apiMessage = error instanceof ApiClientError ? error.message : ''
        const useApiMessage =
          (mapped === 'OVERSIZED_ARTIFACT' ||
            mapped === 'UNSUPPORTED_ARTIFACT' ||
            mapped === 'INVALID_EVIDENCE') &&
          apiMessage.length > 0
        setVerifyResult(useApiMessage ? apiMessage : SAFE_MESSAGES[mapped])
        return
      }
      const msg = error instanceof Error ? error.message : ''
      const isWallet = /wallet|freighter|readonly|connect/i.test(msg)
      const code: VerificationErrorCode = isWallet ? 'WALLET_UNAVAILABLE' : 'DEPENDENCY_UNAVAILABLE'
      setStatus('error')
      setErrorCode(code)
      setVerifyResult(SAFE_MESSAGES[code])
    }
  }, [])

  /**
   * Local-only verification: hash + extract + structural/binding checks.
   * Never touches verificationService (no stego API, no NeonDB, no RPC), never
   * queries events or chain state, and never produces a trust confirmation.
   */
  const runOfflineVerify = useCallback(async (file: File, seq: number, signal: AbortSignal) => {
    // Validate synchronously before any expensive work
    const validated = validateFile(file)
    if (!validated.ok) {
      if (seq !== seqRef.current) return
      setStatus('error')
      setErrorCode(validated.code)
      setVerifyResult(SAFE_MESSAGES[validated.code])
      // keep hash empty so UI does not show stale hash for rejected input
      return
    }

    setStatus('hashing')
    setErrorCode(null)
    setVerifyResult('Hashing evidence locally…')
    setChainProof(null)
    setEvents([])

    let videoHash: string
    try {
      const { sha256 } = await import('../utils')
      // Allow early abort before reading
      if (signal.aborted) throw new DOMException('Aborted', 'AbortError')
      const buffer = await file.arrayBuffer()
      if (signal.aborted) throw new DOMException('Aborted', 'AbortError')
      videoHash = await sha256(buffer)
      if (signal.aborted) throw new DOMException('Aborted', 'AbortError')
      if (seq !== seqRef.current) return
      setVerifyHash(videoHash)
    } catch (error) {
      if (isAbortError(error) || signal.aborted) {
        if (seq !== seqRef.current) return
        setStatus('cancelled')
        setErrorCode('CANCELLED')
        setVerifyResult(SAFE_MESSAGES.CANCELLED)
        return
      }
      if (seq !== seqRef.current) return
      setStatus('error')
      setErrorCode('INVALID_EVIDENCE')
      setVerifyResult(SAFE_MESSAGES.INVALID_EVIDENCE)
      return
    }

    setStatus('verifying')
    setVerifyResult('Inspecting evidence locally…')

    try {
      const { verifyOffline } = await import('../offlineVerification')
      if (signal.aborted) throw new DOMException('Aborted', 'AbortError')
      const result = await verifyOffline(file, { signal })
      if (seq !== seqRef.current) return

      if (result.outcome === 'cancelled') {
        setStatus('cancelled')
        setErrorCode('CANCELLED')
        setVerifyResult(result.message)
        return
      }
      if (result.outcome === 'verified-local') {
        setStatus('success')
        setErrorCode(null)
        setVerifyResult(result.message)
        return
      }
      if (result.errorCode) {
        setStatus('error')
        setErrorCode(result.errorCode)
        setVerifyResult(result.message)
        return
      }
      setStatus('error')
      setErrorCode('VERIFICATION_FAILED')
      setVerifyResult(SAFE_MESSAGES.VERIFICATION_FAILED)
    } catch (error) {
      if (isAbortError(error) || signal.aborted) {
        if (seq !== seqRef.current) return
        setStatus('cancelled')
        setErrorCode('CANCELLED')
        setVerifyResult(SAFE_MESSAGES.CANCELLED)
        return
      }
      if (seq !== seqRef.current) return
      setStatus('error')
      setErrorCode('DEPENDENCY_UNAVAILABLE')
      setVerifyResult(SAFE_MESSAGES.DEPENDENCY_UNAVAILABLE)
    }
  }, [])

  const verifyEvidence = useCallback(async (file: File | null, walletAddress?: string) => {
    if (!file) return
    lastFileRef.current = { file, wallet: walletAddress }
    // Cancel any in-flight verification and bump sequence to ignore stale results
    abortRef.current?.abort()
    const controller = new AbortController()
    abortRef.current = controller
    seqRef.current += 1
    const seq = seqRef.current
    setStatus('validating')
    if (offlineRef.current) {
      await runOfflineVerify(file, seq, controller.signal)
    } else {
      await runVerify(file, walletAddress, seq, controller.signal)
    }
  }, [runVerify, runOfflineVerify])

  const retry = useCallback(async () => {
    const last = lastFileRef.current
    if (!last) return
    await verifyEvidence(last.file, last.wallet)
  }, [verifyEvidence])

  useEffect(() => {
    return () => {
      abortRef.current?.abort()
    }
  }, [])

  return {
    verifyHash,
    verifyResult,
    events,
    chainProof,
    status,
    errorCode,
    isVerifying,
    offline,
    setOffline,
    verifyEvidence,
    loadEvents,
    cancel,
    retry,
    clear,
  }
}
