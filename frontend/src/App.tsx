import { useEffect, useMemo, useRef, useState } from 'react'
import { Wallet } from 'lucide-react'
import EvilEye from './components/EvilEye'
import BatchVerificationWorkspace from './components/BatchVerificationWorkspace'
import { LandingView } from './views/LandingView'
import { StudioView } from './views/StudioView'
import { VerifyView } from './views/VerifyView'
import { useWallet } from './hooks/useWallet'
import { useEvidence } from './hooks/useEvidence'
import { useVerification } from './hooks/useVerification'
import { useLiveRegion, useA11yStage, useSkipLink } from './hooks/useA11y'
import type { IdentityTier } from './types'
import type { View } from './types'
import { createProofManifest } from './proofManifest'
import { CONTRACT_NETWORK_PASSPHRASE } from './stellar'
import { buildProvenanceRecord } from './provenance/provenanceModel'
import './App.css'

const API_BASE = import.meta.env.VITE_API_BASE ?? 'http://127.0.0.1:5050'
const CONTRACT_ID = import.meta.env.VITE_HARPOCRATES_REGISTRY_ID ?? ''
const RPC_URL = import.meta.env.VITE_STELLAR_RPC_URL ?? 'https://soroban-testnet.stellar.org'

type AppView = View | 'batch'

function methodForTier(tier: IdentityTier) {
  if (tier === 'silent') return 'register_anonymous_verified'
  if (tier === 'seal') return 'register_seal'
  return 'register_source'
}

function initialView(): AppView {
  const hash = window.location.hash.replace('#', '')
  return hash === 'studio' || hash === 'verify' || hash === 'batch' ? hash : 'landing'
}

function App() {
  const [currentView, setCurrentView] = useState<AppView>(initialView)
  const [isScrolled, setIsScrolled] = useState(false)

  const { wallet, networkMismatch: walletNetworkMismatch, connectWallet } = useWallet()
  const evidence = useEvidence()
  const verification = useVerification()

  const liveStatus = useLiveRegion()
  const liveAlert = useLiveRegion()
  const { statusLabel } = useA11yStage(evidence.stage)
  const { mainRef, handleSkip } = useSkipLink()

  const prevStageRef = useRef(evidence.stage)
  useEffect(() => {
    if (evidence.stage === prevStageRef.current) return
    prevStageRef.current = evidence.stage

    if (evidence.stage === 'error') {
      liveAlert.announce(evidence.message)
    } else if (evidence.stage !== 'idle') {
      liveStatus.announce(statusLabel)
    }
  }, [evidence.stage, evidence.message, statusLabel])

  const viewHeadingId = currentView === 'studio'
    ? 'studio-heading'
    : currentView === 'verify'
      ? 'verify-heading'
      : null

  useEffect(() => {
    if (!viewHeadingId) return
    const timer = setTimeout(() => {
      document.getElementById(viewHeadingId)?.focus()
    }, 50)
    return () => clearTimeout(timer)
  }, [viewHeadingId])

  const provenanceRecord = useMemo(() => {
    if (!evidence.proof) return null

    return buildProvenanceRecord({
      manifest: createProofManifest({
        proofId: evidence.proof.proofId,
        tier: evidence.proof.tier,
        network: CONTRACT_NETWORK_PASSPHRASE,
        contractId: CONTRACT_ID,
        transactionRef: evidence.registration?.hash ?? '',
        videoHash: evidence.proof.videoHash,
        metadataHash: evidence.proof.metadataHash,
        sourceHash: evidence.proof.sourceHash,
        timestamp: evidence.proof.timestamp,
      }),
      chainProof: verification.chainProof,
      rpcUrl: RPC_URL,
      transactionHash: evidence.registration?.hash ?? null,
      method: methodForTier(evidence.proof.tier),
    })
  }, [evidence.proof, evidence.registration?.hash, verification.chainProof])

  useEffect(() => {
    const updateScrollState = () => setIsScrolled(window.scrollY > 36)
    updateScrollState()
    window.addEventListener('scroll', updateScrollState, { passive: true })
    return () => window.removeEventListener('scroll', updateScrollState)
  }, [])

  function openView(view: AppView) {
    setCurrentView(view)
    const nextHash = view === 'landing' ? window.location.pathname : `${window.location.pathname}#${view}`
    window.history.replaceState(null, '', nextHash)
    window.scrollTo({ top: 0, behavior: 'smooth' })
  }

  return (
    <>
      <a href="#main-content" className="skip-link" onClick={handleSkip}>
        Skip to main content
      </a>

      <div role="status" aria-live="polite" aria-atomic="true" className="sr-only">
        {liveStatus.message}
      </div>
      <div role="alert" aria-live="assertive" aria-atomic="true" className="sr-only">
        {liveAlert.message}
      </div>

      <main className="app-shell" ref={mainRef} id="main-content" tabIndex={-1}>
        <div className="signal-background" aria-hidden="true">
          <EvilEye
            eyeColor="#c8ceff"
            intensity={0.9}
            pupilSize={0.55}
            irisWidth={0.22}
            glowIntensity={0.28}
            scale={0.72}
            noiseScale={0.85}
            pupilFollow={0.7}
            flameSpeed={0.38}
            backgroundColor="#030305"
          />
          <div className="prismatic-veil" />
        </div>

        <nav className={isScrolled ? 'topbar scrolled' : 'topbar'} aria-label="Site navigation">
          <button className="brand" type="button" onClick={() => openView('landing')} title="Home">
            Harpocrates
          </button>
          <div className="navlinks" aria-label="Primary">
            <button
              className={currentView === 'studio' ? 'active' : ''}
              aria-current={currentView === 'studio' ? 'page' : undefined}
              type="button"
              onClick={() => openView('studio')}
            >
              Evidence
            </button>
            <button
              className={currentView === 'verify' ? 'active' : ''}
              aria-current={currentView === 'verify' ? 'page' : undefined}
              type="button"
              onClick={() => openView('verify')}
            >
              Verify
            </button>
            <button
              className={currentView === 'batch' ? 'active' : ''}
              aria-current={currentView === 'batch' ? 'page' : undefined}
              type="button"
              onClick={() => openView('batch')}
            >
              Batch Workspace
            </button>
          </div>
          <div className="network-pill">Stellar Testnet</div>
          <button
            className={`icon-button${walletNetworkMismatch ? ' wallet-mismatch' : ''}`}
            type="button"
            onClick={() => void connectWallet().catch(() => {})}
            title={walletNetworkMismatch ? 'Wallet network mismatch — click to reconnect' : 'Connect wallet'}
            aria-describedby={walletNetworkMismatch ? 'navbar-network-mismatch' : undefined}
          >
            <Wallet size={18} aria-hidden="true" />
            <span>{wallet ? `${wallet.slice(0, 5)}...${wallet.slice(-4)}` : 'Connect'}</span>
          </button>
        </nav>

        {walletNetworkMismatch ? (
          <div
            id="navbar-network-mismatch"
            className="network-mismatch-banner network-mismatch-banner--global"
            role="alert"
            aria-live="assertive"
            aria-atomic="true"
          >
            <span className="network-mismatch-icon" aria-hidden="true">⚠</span>
            <span>{walletNetworkMismatch}</span>
          </div>
        ) : null}

        {currentView === 'landing' ? (
          <LandingView onOpenStudio={() => openView('studio')} onOpenVerify={() => openView('verify')} />
        ) : null}

        {currentView === 'studio' ? (
          <StudioView
            wallet={wallet}
            evidence={evidence}
            verification={verification}
            provenanceRecord={provenanceRecord}
          />
        ) : null}

        {currentView === 'verify' ? (
          <VerifyView wallet={wallet} networkMismatch={walletNetworkMismatch} verification={verification} provenanceRecord={provenanceRecord} />
        ) : null}

        {currentView === 'batch' ? (
          <section className="workspace app-page verify-page" id="batch">
            <BatchVerificationWorkspace apiBase={API_BASE} contractId={CONTRACT_ID} wallet={wallet || undefined} />
          </section>
        ) : null}
      </main>
    </>
  )
}

export default App
