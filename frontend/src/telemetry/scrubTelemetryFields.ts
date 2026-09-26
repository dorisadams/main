/**
 * Frontend telemetry field scrubber.
 *
 * Mirrors the backend analytics redaction categories so Evidence Studio,
 * verification portal, browser workers, and wallet flows never emit real
 * media, secrets, witnesses, proof payloads, or private keys into
 * console/telemetry sinks.
 *
 * Domain: harpocrates-frontend-telemetry-v1
 * Compatible with backend CRYPTO_DOMAIN_VERSION harpocrates-redaction-v1
 * categories; frontend markers are stable and privacy-safe.
 */

export const TELEMETRY_REDACTION_VERSION = 'harpocrates-frontend-telemetry-v1'

export const DEFAULT_MAX_DEPTH = 12
export const DEFAULT_MAX_NODES = 4096
export const DEFAULT_CAP_CHARS = 256

/** Categories aligned with backend/analytics/redaction.py */
export const SENSITIVE_FIELD_CATEGORIES: Readonly<Record<string, readonly string[]>> = {
  secret: [
    'secret', 'credential', 'password', 'passwd', 'pwd', 'token',
    'apikey', 'apisecret', 'privatekey', 'private_key', 'privkey',
    'mnemonic', 'seedphrase', 'seed_phrase', 'recoveryphrase',
    'recovery_phrase', 'access_key', 'accesskey', 'seed',
  ],
  witness: [
    'witness', 'witnessdata', 'witness_data', 'witness_input',
    'witnessinput', 'witnessvars', 'witness_vars', 'assignment',
    'assignments', 'witness_assignment',
  ],
  media: [
    'video', 'media', 'upload', 'uploaded_file', 'uploadedfile',
    'file_content', 'filecontent', 'blob', 'payload_content',
    'base64_content', 'base64content', 'binary', 'raw_bytes',
    'rawbytes', 'image', 'audio', 'recording', 'screenshot',
    'frame', 'frames', 'clip',
  ],
  proof: [
    'proof', 'proofdata', 'proof_data', 'proofpayload', 'proof_payload',
    'prooffile', 'proof_file', 'zkproof', 'zk_proof', 'circuitproof',
    'circuit_proof', 'verificationkey', 'verification_key', 'provingkey',
    'proving_key', 'public_inputs', 'publicinputs', 'private_inputs',
    'privateinputs', 'commitments', 'commitment', 'nullifier', 'nullifiers',
  ],
  wallet_sig: [
    'signature', 'sig', 'wallet_signature', 'walletsig',
    'stellar_signature', 'txsignature', 'tx_signature', 'xdr',
    'signedtx', 'signed_tx', 'transaction_envelope', 'auth_signature',
    'ed25519_signature',
  ],
  wallet_id: [
    'wallet', 'stellaraddress', 'stellar_address', 'privatekey',
    'keypair', 'secretkey', 'secret_key',
  ],
  pii: [
    'email', 'phone', 'dob', 'passport', 'governmentid', 'government_id',
    'ssn', 'idnumber', 'id_number', 'biometric', 'biometrics',
    'user_ip', 'client_ip',
  ],
}

/** Keys that are always safe to keep (correlation / ops only). */
export const SAFE_TELEMETRY_KEYS: ReadonlySet<string> = new Set([
  'correlation_id', 'request_id', 'trace_id', 'span_id', 'event_id',
  'log_id', 'session_id', 'message_hash', 'stack_trace_hash',
  'event', 'level', 'name', 'code', 'status', 'ok', 'type',
  'version', 'component', 'view', 'tier', 'duration_ms', 'ts',
  'timestamp', 'reason', 'remediation', 'action', 'retryable',
])

export type ScrubTelemetryOptions = {
  maxDepth?: number
  maxNodes?: number
  capChars?: number
}

export type ScrubTelemetryResult = {
  data: unknown
  redactionsApplied: number
  categoriesRedacted: string[]
  truncationsApplied: number
  nodesVisited: number
  depthReached: number
  stopped: boolean
  stopReason: 'ok' | 'max_depth' | 'max_nodes' | 'malformed' | null
  redactionVersion: string
}

type Tracker = {
  nodesVisited: number
  redactionsApplied: number
  truncationsApplied: number
  depthReached: number
  categoriesRedacted: Set<string>
  stopped: boolean
  stopReason: ScrubTelemetryResult['stopReason']
  maxDepth: number
  maxNodes: number
  capChars: number
}

function normalizeKey(key: string): string {
  return key.toLowerCase().replace(/[^a-z0-9]/g, '')
}

function classifyKey(key: string): string | null {
  if (SAFE_TELEMETRY_KEYS.has(key) || SAFE_TELEMETRY_KEYS.has(key.toLowerCase())) {
    return null
  }
  const norm = normalizeKey(key)
  for (const [category, hints] of Object.entries(SENSITIVE_FIELD_CATEGORIES)) {
    for (const hint of hints) {
      const hintNorm = normalizeKey(hint)
      if (norm === hintNorm || norm.includes(hintNorm)) {
        return category
      }
    }
  }
  return null
}

function markerFor(category: string): string {
  return `[REDACTED:${category}]`
}

function capString(value: string, cap: number, tracker: Tracker): string {
  if (value.length <= cap) return value
  tracker.truncationsApplied += 1
  return `${value.slice(0, cap)}…[truncated]`
}

function looksLikeSecretBlob(value: string): boolean {
  if (value.length < 48) return false
  // Long hex / base64-ish blobs that often carry proofs, seeds, or media.
  // The base64 shape must contain at least one non-pure-letter character
  // (digit, +, /, _ or =) so long plain words are truncated, not redacted.
  if (/^(0x)?[0-9a-fA-F]{64,}$/.test(value)) return true
  if (/^(?=[A-Za-z0-9+/_-]{80,}={0,2}$)(?=.*[0-9+/_=])[A-Za-z0-9+/_-]+={0,2}$/.test(value)) return true
  return false
}

function scrubAny(value: unknown, key: string | null, depth: number, tracker: Tracker): unknown {
  if (tracker.stopped) return markerFor('truncated')

  tracker.nodesVisited += 1
  if (tracker.nodesVisited > tracker.maxNodes) {
    tracker.stopped = true
    tracker.stopReason = 'max_nodes'
    return markerFor('truncated')
  }
  if (depth > tracker.depthReached) tracker.depthReached = depth
  if (depth > tracker.maxDepth) {
    tracker.stopped = true
    tracker.stopReason = 'max_depth'
    return markerFor('truncated')
  }

  const keyCategory = key ? classifyKey(key) : null
  if (keyCategory) {
    tracker.redactionsApplied += 1
    tracker.categoriesRedacted.add(keyCategory)
    return markerFor(keyCategory)
  }

  if (value === null || value === undefined) return value

  if (typeof value === 'string') {
    if (looksLikeSecretBlob(value)) {
      tracker.redactionsApplied += 1
      tracker.categoriesRedacted.add('secret')
      return markerFor('secret')
    }
    return capString(value, tracker.capChars, tracker)
  }

  if (typeof value === 'number' || typeof value === 'boolean') return value

  if (typeof value === 'bigint') return value.toString()

  if (typeof value === 'function' || typeof value === 'symbol') {
    tracker.redactionsApplied += 1
    tracker.categoriesRedacted.add('secret')
    return markerFor('secret')
  }

  if (ArrayBuffer.isView(value) || value instanceof ArrayBuffer) {
    tracker.redactionsApplied += 1
    tracker.categoriesRedacted.add('media')
    return markerFor('media')
  }

  if (Array.isArray(value)) {
    const out: unknown[] = []
    for (const item of value) {
      if (tracker.stopped) {
        out.push(markerFor('truncated'))
        break
      }
      out.push(scrubAny(item, null, depth + 1, tracker))
    }
    return out
  }

  if (typeof value === 'object') {
    try {
      const out: Record<string, unknown> = {}
      for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
        if (tracker.stopped) {
          out['__truncated__'] = markerFor('truncated')
          break
        }
        out[k] = scrubAny(v, k, depth + 1, tracker)
      }
      return out
    } catch {
      tracker.stopped = true
      tracker.stopReason = 'malformed'
      return markerFor('malformed')
    }
  }

  tracker.redactionsApplied += 1
  return markerFor('unserializable')
}

/**
 * Scrub a telemetry / diagnostic payload before it reaches console, analytics,
 * or any public boundary. Safe for malformed, oversized, and nested hostile input.
 */
export function scrubTelemetryFields(
  value: unknown,
  options: ScrubTelemetryOptions = {},
): ScrubTelemetryResult {
  const tracker: Tracker = {
    nodesVisited: 0,
    redactionsApplied: 0,
    truncationsApplied: 0,
    depthReached: 0,
    categoriesRedacted: new Set(),
    stopped: false,
    stopReason: null,
    maxDepth: options.maxDepth ?? DEFAULT_MAX_DEPTH,
    maxNodes: options.maxNodes ?? DEFAULT_MAX_NODES,
    capChars: options.capChars ?? DEFAULT_CAP_CHARS,
  }

  let data: unknown
  try {
    data = scrubAny(value, null, 0, tracker)
  } catch {
    tracker.stopped = true
    tracker.stopReason = 'malformed'
    data = markerFor('malformed')
  }

  return {
    data,
    redactionsApplied: tracker.redactionsApplied,
    categoriesRedacted: [...tracker.categoriesRedacted].sort(),
    truncationsApplied: tracker.truncationsApplied,
    nodesVisited: tracker.nodesVisited,
    depthReached: tracker.depthReached,
    stopped: tracker.stopped,
    stopReason: tracker.stopReason ?? 'ok',
    redactionVersion: TELEMETRY_REDACTION_VERSION,
  }
}

/**
 * Convenience: return only the scrubbed payload (drops metadata).
 */
export function scrubTelemetryPayload(
  value: unknown,
  options?: ScrubTelemetryOptions,
): unknown {
  return scrubTelemetryFields(value, options).data
}

/**
 * Privacy-safe console sink for frontend telemetry. Always scrub first.
 */
export function emitScrubbedTelemetry(
  level: 'debug' | 'info' | 'warn' | 'error',
  event: string,
  fields?: Record<string, unknown>,
): void {
  const scrubbed = scrubTelemetryFields({
    event,
    level,
    ts: new Date().toISOString(),
    ...(fields ?? {}),
  })
  const line = scrubbed.data
  const sink =
    level === 'error' ? console.error :
    level === 'warn' ? console.warn :
    level === 'debug' ? console.debug :
    console.info
  sink('[harpocrates:telemetry]', line)
}
