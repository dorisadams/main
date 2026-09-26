/**
 * Content Security Policy (CSP) builder.
 *
 * The policy is assembled at runtime so that environment-specific origins
 * (VITE_API_BASE, VITE_STELLAR_RPC_URL) can be injected without hard-coding
 * production URLs into the source tree.
 *
 * Design decisions
 * ────────────────
 * • script-src uses 'strict-dynamic' + a nonce on the entry-point <script>
 *   so that Vite-generated chunks (loaded via importScripts / dynamic import)
 *   are allowed without needing 'unsafe-inline' or a wildcard.
 *   'wasm-unsafe-eval' is required by @aztec/bb.js (UltraHonkBackend) which
 *   compiles WebAssembly at runtime.  No raw JS eval is needed.
 * • connect-src lists every fetch() target explicitly:
 *     – the backend API   (VITE_API_BASE)
 *     – the Stellar RPC   (VITE_STELLAR_RPC_URL)
 *     – Freighter's extension messaging uses postMessage, not fetch, so it
 *       does not need a connect-src entry; but its chrome-extension origin
 *       must be in connect-src when any future XHR/WS targets it.
 * • worker-src 'self' blob: — @aztec/bb.js spawns WASM workers via blob URLs.
 * • child-src  'self' blob: — same reasoning; belt-and-suspenders for older
 *   browser interpretations of worker-src.
 * • img-src 'self' data: — favicon SVG + inline data URIs used by the UI.
 * • frame-ancestors 'none' — the app must never be embedded as an iframe;
 *   this prevents clickjacking / credential-overlay attacks.
 * • base-uri 'self' — prevents a rogue <base> tag from hijacking relative URLs.
 * • form-action 'self' — no plain HTML form submissions leave the origin.
 * • object-src 'none' — disables Flash and other plugin types entirely.
 */

export type CspOptions = {
  /** Origin of the backend API, e.g. "https://api.example.com". No trailing slash. */
  apiBase: string
  /** Origin of the Stellar RPC server, e.g. "https://soroban-testnet.stellar.org". */
  stellarRpcUrl: string
  /**
   * HTML nonce placed on the entry-point <script> tag.  When provided the
   * policy includes "'nonce-<value>'" in script-src so that browsers accept
   * the bootstrapped module without 'unsafe-inline'.  Pass an empty string
   * (or omit) to omit the nonce directive (useful in unit tests / CSP-report
   * only mode).
   */
  nonce?: string
}

/**
 * Parse a URL string and return just its origin ("scheme://host[:port]").
 * Returns the input unchanged when it is already an origin or an unrecognised
 * value (the caller handles that via policy validation).
 */
export function extractOrigin(url: string): string {
  try {
    return new URL(url).origin
  } catch {
    return url
  }
}

/**
 * Build and return the Content-Security-Policy header value.
 *
 * @example
 * const policy = buildCsp({
 *   apiBase: 'https://api.harpocrates.example',
 *   stellarRpcUrl: 'https://soroban-testnet.stellar.org',
 *   nonce: 'abc123',
 * })
 * // use as: Content-Security-Policy: <policy>
 */
export function buildCsp({ apiBase, stellarRpcUrl, nonce }: CspOptions): string {
  const apiOrigin = extractOrigin(apiBase)
  const rpcOrigin = extractOrigin(stellarRpcUrl)

  const nonceToken = nonce ? ` 'nonce-${nonce}'` : ''

  const directives: Record<string, string> = {
    // Scripts: nonce on entry-point, strict-dynamic for Vite chunks, WASM eval only.
    'script-src': `'self'${nonceToken} 'strict-dynamic' 'wasm-unsafe-eval'`,

    // Styles: bundled CSS only — no external sheets, no inline style attributes.
    'style-src': "'self'",

    // Connections: backend API + Stellar RPC only; everything else is blocked.
    'connect-src': `'self' ${apiOrigin} ${rpcOrigin}`,

    // Workers: @aztec/bb.js launches WASM workers from blob: URLs.
    'worker-src': "'self' blob:",

    // belt-and-suspenders for older browsers that ignore worker-src.
    'child-src': "'self' blob:",

    // Images: favicon SVG (same-origin) and any data: URIs the UI generates.
    'img-src': "'self' data:",

    // Fonts: all fonts are self-hosted (bundled by Vite).
    'font-src': "'self'",

    // No plugins.
    'object-src': "'none'",

    // Prevents framing / clickjacking.
    'frame-ancestors': "'none'",

    // No iframes inside the app.
    'frame-src': "'none'",

    // Prevents base-tag hijacking.
    'base-uri': "'self'",

    // Plain form submissions stay on the same origin.
    'form-action': "'self'",
  }

  return Object.entries(directives)
    .map(([directive, value]) => `${directive} ${value}`)
    .join('; ')
}

/**
 * Validate a built policy string.  Returns an array of violation messages;
 * an empty array means the policy is considered safe.
 *
 * Checks performed:
 *  – No wildcard (*) in any directive value.
 *  – No 'unsafe-inline' (script/style).
 *  – No 'unsafe-eval' (only 'wasm-unsafe-eval' is allowed).
 *  – frame-ancestors is present.
 *  – object-src is 'none'.
 *  – connect-src does not fall back to the default-src wildcard.
 */
export function validateCsp(policy: string): string[] {
  const violations: string[] = []

  // Split on ";" and parse each directive.
  const directiveMap: Record<string, string[]> = {}
  for (const part of policy.split(';')) {
    const tokens = part.trim().split(/\s+/)
    if (tokens.length === 0 || !tokens[0]) continue
    directiveMap[tokens[0].toLowerCase()] = tokens.slice(1)
  }

  function values(name: string): string[] {
    return directiveMap[name] ?? []
  }

  // Wildcard check across all directives.
  for (const [directive, vals] of Object.entries(directiveMap)) {
    if (vals.includes('*')) {
      violations.push(`${directive} contains a wildcard (*)`)
    }
  }

  // unsafe-inline in script-src or style-src.
  if (values('script-src').includes("'unsafe-inline'")) {
    violations.push("script-src contains 'unsafe-inline'")
  }
  if (values('style-src').includes("'unsafe-inline'")) {
    violations.push("style-src contains 'unsafe-inline'")
  }

  // unsafe-eval (wasm-unsafe-eval is allowed; raw unsafe-eval is not).
  // The message must not contain the substring "wasm": callers distinguish
  // the forbidden raw 'unsafe-eval' token from the allowed 'wasm-unsafe-eval'
  // by scanning the message itself.
  if (values('script-src').includes("'unsafe-eval'")) {
    violations.push("script-src contains 'unsafe-eval'")
  }

  // frame-ancestors must be present.
  if (!directiveMap['frame-ancestors']) {
    violations.push("frame-ancestors directive is missing")
  }

  // object-src must be 'none'.
  const objectSrc = values('object-src')
  if (!objectSrc.includes("'none'")) {
    violations.push("object-src must be 'none'")
  }

  // connect-src must be present (no fallback to a permissive default-src).
  if (!directiveMap['connect-src']) {
    violations.push("connect-src directive is missing")
  }

  return violations
}

/**
 * Convenience wrapper: build the policy from `import.meta.env` values.
 * Intended for use inside the browser bundle (not in tests).
 */
export function buildCspFromEnv(nonce?: string): string {
  /* c8 ignore next 4 – covered by integration; unit tests call buildCsp directly */
  return buildCsp({
    apiBase: import.meta.env.VITE_API_BASE ?? 'http://127.0.0.1:5050',
    stellarRpcUrl: import.meta.env.VITE_STELLAR_RPC_URL ?? 'https://soroban-testnet.stellar.org',
    nonce,
  })
}
