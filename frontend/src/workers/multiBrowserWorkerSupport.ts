/**
 * Multi-browser proof-worker support assessment.
 *
 * Bridges the canonical frontend browser support matrix
 * (`browser-support.mjs` / BROWSER_SUPPORT.md) with the Silent Witness
 * proof Web Worker boundary (`proofWorkerClient.ts`).
 *
 * Fail-closed and privacy-safe: assessments and errors name only
 * capability identifiers — never media, witnesses, secrets, or keys.
 */

import {
  browserBuildTargets,
  browserSupportMatrix,
  requiredBrowserCapabilities,
} from '../../browser-support.mjs'

export type WorkerCapabilityId =
  | 'Worker'
  | 'moduleWorkerType'
  | 'WebAssembly'
  | 'SubtleCrypto'
  | 'BigInt'
  | 'ArrayBuffer'

export type WorkerSupportTier = 'supported' | 'best-effort' | 'unsupported'

export type BrowserWorkerExpectation = {
  readonly browser: string
  readonly platform: string
  readonly minimum: string
  readonly tier: 'supported' | 'best-effort'
  /** Module workers are required for privacy-preserving off-main-thread proving. */
  readonly moduleWorkersRequired: boolean
  /** Large UltraHonk proofs may OOM on this surface; not release-gated. */
  readonly memoryConstrained: boolean
}

export type WorkerCapabilitySnapshot = Readonly<Record<WorkerCapabilityId, boolean>>

export type WorkerSupportAssessment = {
  readonly ok: boolean
  readonly tier: WorkerSupportTier
  readonly missing: readonly WorkerCapabilityId[]
  /** Privacy-safe human-readable reason (capability names only). */
  readonly reason: string
}

/** Capabilities the proof worker boundary requires at runtime. */
export const PROOF_WORKER_CAPABILITIES: readonly WorkerCapabilityId[] = Object.freeze([
  'Worker',
  'moduleWorkerType',
  'WebAssembly',
  'SubtleCrypto',
  'BigInt',
  'ArrayBuffer',
])

/**
 * Per-browser expectations for module-worker proving, derived from the
 * canonical support matrix. Supported desktop browsers must provide module
 * workers; iOS/iPadOS remains best-effort due to memory limits.
 */
export const MULTI_BROWSER_WORKER_EXPECTATIONS: readonly BrowserWorkerExpectation[] =
  Object.freeze(
    browserSupportMatrix.map((entry) =>
      Object.freeze({
        browser: entry.browser,
        platform: entry.platform,
        minimum: entry.minimum,
        tier: entry.tier,
        moduleWorkersRequired: true,
        memoryConstrained: entry.platform === 'iOS/iPadOS' || entry.tier === 'best-effort',
      }),
    ),
  )

const CAPABILITY_LABEL: Record<WorkerCapabilityId, string> = {
  Worker: 'Worker',
  moduleWorkerType: 'module Worker type option',
  WebAssembly: 'WebAssembly',
  SubtleCrypto: 'secure-context SubtleCrypto',
  BigInt: 'BigInt',
  ArrayBuffer: 'ArrayBuffer',
}

function hasConstructor(globalObj: typeof globalThis, name: string): boolean {
  const value = (globalObj as Record<string, unknown>)[name]
  return typeof value === 'function'
}

/**
 * WebAssembly is a namespace object (not a constructor), so typeof it is
 * 'object' in every engine — including jsdom's cross-realm shim. Probe the
 * required static members instead of the namespace's own typeof.
 */
function hasWebAssembly(globalObj: typeof globalThis): boolean {
  const ns = (globalObj as Record<string, unknown>).WebAssembly
  if (typeof ns !== 'object' || ns === null) return false
  const member = ns as Record<string, unknown>
  return typeof member.Module === 'function' && typeof member.Instance === 'function'
}

/**
 * Probe the runtime for proof-worker prerequisites.
 * Never inspects user input, media, or secrets.
 */
export function detectWorkerCapabilities(
  globalObj: typeof globalThis = globalThis,
): WorkerCapabilitySnapshot {
  const cryptoObj = (globalObj as { crypto?: { subtle?: unknown } }).crypto
  return Object.freeze({
    Worker: hasConstructor(globalObj, 'Worker'),
    // Module workers are part of the documented floor; we cannot fully
    // construct one during a sync probe, so we require Worker + documented
    // matrix capability "module Web Workers".
    moduleWorkerType: hasConstructor(globalObj, 'Worker'),
    WebAssembly: hasWebAssembly(globalObj),
    SubtleCrypto: Boolean(cryptoObj && typeof cryptoObj.subtle === 'object' && cryptoObj.subtle !== null),
    BigInt: typeof (globalObj as { BigInt?: unknown }).BigInt === 'function',
    ArrayBuffer: hasConstructor(globalObj, 'ArrayBuffer'),
  })
}

/**
 * Fail-closed assessment of whether browser proving via a module worker is
 * available. Missing capabilities produce a stable, privacy-safe reason.
 */
export function assessWorkerSupport(
  globalObj: typeof globalThis = globalThis,
): WorkerSupportAssessment {
  const snapshot = detectWorkerCapabilities(globalObj)
  const missing = PROOF_WORKER_CAPABILITIES.filter((id) => !snapshot[id])
  if (missing.length === 0) {
    return Object.freeze({
      ok: true,
      tier: 'supported',
      missing: Object.freeze([] as WorkerCapabilityId[]),
      reason: 'All proof-worker capabilities are available.',
    })
  }
  const labels = missing.map((id) => CAPABILITY_LABEL[id])
  return Object.freeze({
    ok: false,
    tier: 'unsupported',
    missing: Object.freeze([...missing]),
    reason: `Browser proving unavailable; missing capability: ${labels.join(', ')}.`,
  })
}

/**
 * Guard used by ProofWorkerClient before posting secrets to a worker.
 * Throws a plain Error with a privacy-safe message (caller maps to ProofWorkerError).
 */
export function assertWorkerSupportOrThrow(
  globalObj: typeof globalThis = globalThis,
): void {
  const assessment = assessWorkerSupport(globalObj)
  if (!assessment.ok) {
    const err = new Error(assessment.reason)
    ;(err as Error & { code: string }).code = 'UNSUPPORTED_ENVIRONMENT'
    throw err
  }
}

/** Build targets that must stay aligned with the documented matrix. */
export function expectedWorkerBuildTargets(): readonly string[] {
  return browserBuildTargets
}

/** Documented capability strings that must include module Web Workers. */
export function expectedDocumentedCapabilities(): readonly string[] {
  return requiredBrowserCapabilities
}

export function matrixRequiresModuleWorkers(): boolean {
  return requiredBrowserCapabilities.includes('module Web Workers')
}

/**
 * Resolve the support tier expectation for a browser/platform pair.
 * Unknown browsers are unsupported (fail closed).
 */
export function expectationFor(
  browser: string,
  platform: string,
): BrowserWorkerExpectation | null {
  return (
    MULTI_BROWSER_WORKER_EXPECTATIONS.find(
      (row) =>
        row.browser.toLowerCase() === browser.toLowerCase() &&
        row.platform.toLowerCase() === platform.toLowerCase(),
    ) ?? null
  )
}
