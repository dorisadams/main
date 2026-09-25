
import React from 'react'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import App from './App'

vi.mock('./components/EvilEye', () => ({
  default: () => <div data-testid="evil-eye" />,
}))

// Offline mode extracts via the local stego loader; in jsdom the real video
// decode never settles, so stub it deterministically.
vi.mock('./stego', () => ({
  extractMetadata: vi.fn().mockResolvedValue({
    protocol: 'harpocrates',
    version: 1,
    tier: 'silent',
    sourceHash: 'a'.repeat(64),
    proofId: 'b'.repeat(64),
    timestamp: '2026-01-01T00:00:00.000Z',
  }),
  MalformedEvidenceError: class MalformedEvidenceError extends Error {},
}))

describe('App', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    Object.defineProperty(window, 'scrollTo', {
      configurable: true,
      value: vi.fn(),
    })
    window.history.replaceState(null, '', '/')
  })

  it('smoke renders the landing view without opening workspace panels', () => {
    render(<App />)

    expect(screen.getByRole('heading', { name: /evidence integrity for silent witnesses/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /begin evidence flow/i })).toBeInTheDocument()
    expect(screen.getByText(/stellar testnet/i)).toBeInTheDocument()
    expect(screen.queryByRole('heading', { name: /evidence studio/i })).not.toBeInTheDocument()
    expect(screen.queryByRole('heading', { name: /verify artifact/i })).not.toBeInTheDocument()
  })

  it('opens the evidence studio and updates identity tier controls', async () => {
    const user = userEvent.setup()

    render(<App />)
    await user.click(screen.getByRole('button', { name: /begin evidence flow/i }))

    expect(screen.getByRole('heading', { name: /evidence studio/i })).toBeInTheDocument()
    expect(screen.getByText(/upload evidence to begin/i)).toBeInTheDocument()
    expect(screen.getByLabelText(/credential seed/i)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /register proof/i })).toBeDisabled()

    await user.click(screen.getByRole('button', { name: /consistent source/i }))

    const studio = screen.getByRole('heading', { name: /evidence studio/i }).closest('section')
    expect(studio).not.toBeNull()
    expect(within(studio as HTMLElement).getByText(/freighter signature links evidence/i)).toBeInTheDocument()
    expect(screen.queryByLabelText(/credential seed/i)).not.toBeInTheDocument()
    expect(screen.queryByLabelText(/nullifier seed/i)).not.toBeInTheDocument()
  })

  it('shows the unavailable-services path when verify upload cannot reach the API', async () => {
    const user = userEvent.setup()
    vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('network unavailable'))

    render(<App />)
    await user.click(screen.getByRole('button', { name: /^verify$/i }))
    await user.upload(screen.getByLabelText(/drop or choose a received video/i), new File(['video'], 'clip.mp4', {
      type: 'video/mp4',
    }))

    expect(await screen.findByText(/verification services are unavailable/i)).toBeInTheDocument()
    await waitFor(() => expect(globalThis.fetch).toHaveBeenCalledWith('http://127.0.0.1:5050/api/stego/extract', expect.objectContaining({
      body: expect.any(FormData),
      method: 'POST',
    })))
    expect(screen.getByText(/chain status/i).nextElementSibling).toHaveTextContent(/not loaded/i)
  })

  it('handles a local verification hash failure without calling the API', async () => {
    const user = userEvent.setup()
    const fetch = vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('should not reach API'))
    vi.spyOn(globalThis.crypto.subtle, 'digest').mockRejectedValueOnce(new Error('digest unavailable'))

    render(<App />)
    await user.click(screen.getByRole('button', { name: /^verify$/i }))
    await user.upload(screen.getByLabelText(/drop or choose a received video/i), new File(['video'], 'clip.mp4', {
      type: 'video/mp4',
    }))

    expect(await screen.findByText(/Invalid evidence|verification services are unavailable/i)).toBeInTheDocument()
    expect(fetch).not.toHaveBeenCalled()
    expect(screen.getByText(/received hash/i).nextElementSibling).toHaveTextContent(/not generated/i)
  })

  it('opens the batch verification workspace from the navbar', async () => {
    const user = userEvent.setup()

    render(<App />)
    await user.click(screen.getByRole('button', { name: /batch workspace/i }))

    expect(screen.getByRole('heading', { level: 2, name: /evidence batch verification workspace/i })).toBeInTheDocument()
  })

  it('offline mode verifies locally with zero network calls', async () => {
    const user = userEvent.setup()
    const fetch = vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('must not fetch in offline mode'))

    render(<App />)
    await user.click(screen.getByRole('button', { name: /^verify$/i }))

    const toggle = screen.getByRole('button', { name: /offline local check/i })
    expect(toggle).toHaveAttribute('aria-pressed', 'false')

    await user.click(toggle)
    expect(toggle).toHaveAttribute('aria-pressed', 'true')
    expect(screen.getByText(/runs fully local/i)).toBeInTheDocument()
    expect(screen.getByText(/not checked \(offline\)/i)).toBeInTheDocument()
    expect(screen.getByText(/on-chain status was not checked in offline mode/i)).toBeInTheDocument()
    expect(screen.getByText(/neondb events were not queried in offline mode/i)).toBeInTheDocument()

    await user.upload(screen.getByLabelText(/drop or choose a received video/i), new File(['video'], 'clip.mp4', {
      type: 'video/mp4',
    }))

    expect(await screen.findByText(/locally verified/i)).toBeInTheDocument()
    expect(fetch).not.toHaveBeenCalled()
    expect(screen.getByText(/offline mode produces no shareable verification link/i)).toBeInTheDocument()
  })

  // ── Accessibility improvements ──────────────────────────────────────────────

  it('renders a skip-to-content link as the first focusable element', () => {
    render(<App />)
    const skipLink = screen.getByText('Skip to main content')
    expect(skipLink).toBeInTheDocument()
    expect(skipLink).toHaveClass('skip-link')
    expect(skipLink).toHaveAttribute('href', '#main-content')
  })

  it('renders polite and assertive sr-only aria-live regions', () => {
    render(<App />)
    const polite = screen.getByRole('status')
    expect(polite).toHaveClass('sr-only')
    expect(polite).toHaveAttribute('aria-live', 'polite')
    expect(polite).toHaveAttribute('aria-atomic', 'true')

    const assertive = screen.getByRole('alert')
    expect(assertive).toHaveClass('sr-only')
    expect(assertive).toHaveAttribute('aria-live', 'assertive')
    expect(assertive).toHaveAttribute('aria-atomic', 'true')
  })

  it('sets aria-current on the active nav button', async () => {
    const user = userEvent.setup()
    render(<App />)

    const evidenceBtn = screen.getByRole('button', { name: /^evidence$/i })
    const verifyBtn = screen.getByRole('button', { name: /^verify$/i })

    await user.click(evidenceBtn)
    expect(evidenceBtn).toHaveAttribute('aria-current', 'page')
    expect(verifyBtn).not.toHaveAttribute('aria-current')

    await user.click(verifyBtn)
    expect(verifyBtn).toHaveAttribute('aria-current', 'page')
    expect(evidenceBtn).not.toHaveAttribute('aria-current')
  })

  it('renders the nav with aria-label "Site navigation"', () => {
    render(<App />)
    expect(screen.getByRole('navigation')).toHaveAttribute('aria-label', 'Site navigation')
  })

  it('renders the main region with id="main-content" for skip-link target', () => {
    render(<App />)
    const main = document.getElementById('main-content')
    expect(main).toBeInTheDocument()
    expect(main).toHaveAttribute('tabindex', '-1')
  })

  it('renders the app-level sr-only aria-live polite status region', async () => {
    const user = userEvent.setup()
    render(<App />)

    await user.click(screen.getByRole('button', { name: /begin evidence flow/i }))

    const statusRegions = screen.getAllByRole('status')
    const srStatus = statusRegions.find((r) => r.classList.contains('sr-only'))
    expect(srStatus).toBeInTheDocument()
    expect(srStatus).toHaveAttribute('aria-live', 'polite')
  })

  it('renders tier tabs with aria-pressed attribute', async () => {
    const user = userEvent.setup()
    render(<App />)

    await user.click(screen.getByRole('button', { name: /begin evidence flow/i }))

    const silentTab = screen.getByRole('button', { name: /silent witness/i })
    expect(silentTab).toHaveAttribute('aria-pressed', 'true')

    await user.click(screen.getByRole('button', { name: /consistent source/i }))
    expect(silentTab).toHaveAttribute('aria-pressed', 'false')
  })

  it('renders the evidence studio section with aria-busy initially false', async () => {
    const user = userEvent.setup()
    render(<App />)

    await user.click(screen.getByRole('button', { name: /begin evidence flow/i }))

    const studio = screen.getByRole('region', { name: /evidence studio workspace/i })
    expect(studio).not.toHaveAttribute('aria-busy')
  })
})

