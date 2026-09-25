/// <reference lib="webworker" />
import { generateSilentWitnessProof } from '../noirClient'
import type { WorkerRequest, WorkerResponse, TransferableProofInput } from './proofWorker.types'

let activeRequestId: string | null = null
/** Cooperative cancel flag — terminate() is still the hard stop from the client. */
let cancelRequestedFor: string | null = null

function post(msg: WorkerResponse) {
  ;(self as unknown as Worker).postMessage(msg)
}

function bufToStr(buf: ArrayBuffer): string {
  return new TextDecoder().decode(buf)
}

function zero(buf: ArrayBuffer) {
  try {
    new Uint8Array(buf).fill(0)
  } catch {
    // Detached / already transferred buffers must not throw into the host.
  }
}

function zeroInput(input: TransferableProofInput) {
  zero(input.credentialSecret)
  zero(input.nullifierSecret)
}

async function handleGenerate(requestId: string, input: TransferableProofInput) {
  if (activeRequestId !== null) {
    // Privacy: never leave transferred secret buffers live on the BUSY path.
    zeroInput(input)
    post({ type: 'ERROR', requestId, code: 'BUSY', message: 'A proof is already being generated.' })
    return
  }

  activeRequestId = requestId
  cancelRequestedFor = null

  let credentialSecret = ''
  let nullifierSecret = ''
  try {
    credentialSecret = bufToStr(input.credentialSecret)
    nullifierSecret = bufToStr(input.nullifierSecret)
    // Zero transferable buffers as soon as strings are materialised so a later
    // terminate()/cancel cannot leave secret bytes resident in the ArrayBuffers.
    zeroInput(input)

    if (cancelRequestedFor === requestId) {
      post({ type: 'CANCELLED', requestId })
      return
    }

    post({ type: 'PROGRESS', requestId, stage: 'loading_circuits' })
    post({ type: 'PROGRESS', requestId, stage: 'executing_helper' })
    post({ type: 'PROGRESS', requestId, stage: 'executing_main' })
    post({ type: 'PROGRESS', requestId, stage: 'generating_proof' })

    const proof = await generateSilentWitnessProof({
      videoHash: input.videoHash,
      credentialSecret,
      nullifierSecret,
    })

    if (cancelRequestedFor === requestId) {
      post({ type: 'CANCELLED', requestId })
      return
    }

    post({ type: 'RESULT', requestId, proof })
  } catch (err) {
    if (cancelRequestedFor === requestId) {
      post({ type: 'CANCELLED', requestId })
      return
    }
    post({
      type: 'ERROR',
      requestId,
      code: 'PROOF_GENERATION_FAILED',
      message: err instanceof Error ? err.message : 'Unknown error during proof generation.',
    })
  } finally {
    credentialSecret = ''
    nullifierSecret = ''
    zeroInput(input)
    if (activeRequestId === requestId) {
      activeRequestId = null
    }
    if (cancelRequestedFor === requestId) {
      cancelRequestedFor = null
    }
  }
}

function handleCancel(requestId: string) {
  if (activeRequestId !== requestId) {
    // Stale or unknown cancel — acknowledge so the client can settle cleanly.
    post({ type: 'CANCELLED', requestId })
    return
  }
  cancelRequestedFor = requestId
  // UltraHonk cannot be interrupted mid-flight; the main thread will terminate
  // this worker. Mark cancelled so a rare cooperative path still settles safely.
  post({ type: 'CANCELLED', requestId })
}

self.onmessage = (event: MessageEvent<WorkerRequest>) => {
  const msg = event.data
  if (msg.type === 'GENERATE_PROOF') {
    void handleGenerate(msg.requestId, msg.input)
  } else if (msg.type === 'CANCEL') {
    handleCancel(msg.requestId)
  }
}

post({ type: 'READY' })
