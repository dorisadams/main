import { inflate as pakoInflate } from 'pako'

const MAGIC = new TextEncoder().encode('HRPSTG1')
const MAX_PAYLOAD_BYTES = 64 * 1024
const BORDER_BLOCK = 6
const BORDER_STRIDE = 2

export class MalformedEvidenceError extends Error {
  constructor() {
    super('Malformed evidence')
    this.name = 'MalformedEvidenceError'
  }
}

async function sha256(data: Uint8Array): Promise<Uint8Array> {
  // Copy into a plain ArrayBuffer-backed view: TS 5.7+ distinguishes
  // ArrayBufferLike (incl. SharedArrayBuffer) from the BufferSource the
  // digest API accepts, and Uint8Array.prototype.slice can preserve the
  // wider buffer type here.
  const digestInput = new Uint8Array(data.byteLength)
  digestInput.set(data)
  const hashBuffer = await crypto.subtle.digest('SHA-256', digestInput)
  return new Uint8Array(hashBuffer)
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false
  }
  return true
}

function bitsToBytes(bits: number[]): Uint8Array {
  const out = new Uint8Array(Math.floor(bits.length / 8))
  for (let index = 0; index <= bits.length - 8; index += 8) {
    let value = 0
    for (let i = 0; i < 8; i++) {
      value = (value << 1) | bits[index + i]
    }
    out[index / 8] = value
  }
  return out
}

async function unpackPayload(data: Uint8Array): Promise<unknown | null> {
  if (data.length < MAGIC.length + 4 + 32) return null
  for (let i = 0; i < MAGIC.length; i++) {
    if (data[i] !== MAGIC[i]) return null
  }

  const view = new DataView(data.buffer, data.byteOffset, data.byteLength)
  const size = view.getUint32(MAGIC.length, false)
  if (size > MAX_PAYLOAD_BYTES) return null

  const checksumStart = MAGIC.length + 4
  const bodyStart = checksumStart + 32
  const bodyEnd = bodyStart + size

  if (data.length < bodyEnd) return null

  const checksum = data.slice(checksumStart, bodyStart)
  const body = data.slice(bodyStart, bodyEnd)

  const actualChecksum = await sha256(body)
  if (!bytesEqual(checksum, actualChecksum)) return null

  try {
    const decompressed = pakoInflate(body)
    const jsonStr = new TextDecoder('utf-8').decode(decompressed)
    const value = JSON.parse(jsonStr)
    return typeof value === 'object' && value !== null ? value : null
  } catch {
    return null
  }
}

async function unpackProgressive(bits: number[]): Promise<unknown | null> {
  const headerBits = (MAGIC.length + 4 + 32) * 8
  if (bits.length < headerBits) return null

  const header = bitsToBytes(bits.slice(0, headerBits))
  for (let i = 0; i < MAGIC.length; i++) {
    if (header[i] !== MAGIC[i]) return null
  }

  const view = new DataView(header.buffer, header.byteOffset, header.byteLength)
  const size = view.getUint32(MAGIC.length, false)
  if (size > MAX_PAYLOAD_BYTES) return null

  const totalBits = (MAGIC.length + 4 + 32 + size) * 8
  if (bits.length < totalBits) return null

  return unpackPayload(bitsToBytes(bits.slice(0, totalBits)))
}

function getBorderPositions(width: number, height: number): [number, number][] {
  const positions: [number, number][] = []
  for (let x = 0; x < width; x += BORDER_BLOCK) {
    positions.push([BORDER_STRIDE, x])
  }
  for (let y = BORDER_BLOCK; y < height; y += BORDER_BLOCK) {
    positions.push([y, width - BORDER_STRIDE - 1])
  }
  for (let x = width - BORDER_BLOCK; x >= 0; x -= BORDER_BLOCK) {
    positions.push([height - BORDER_STRIDE - 1, x])
  }
  for (let y = height - BORDER_BLOCK; y >= BORDER_BLOCK; y -= BORDER_BLOCK) {
    positions.push([y, BORDER_STRIDE])
  }
  return positions
}

export async function extractMetadata(file: File): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const video = document.createElement('video')
    video.src = URL.createObjectURL(file)
    video.muted = true
    video.playsInline = true

    video.onloadedmetadata = () => {
      const width = video.videoWidth
      const height = video.videoHeight
      const canvas = document.createElement('canvas')
      canvas.width = width
      canvas.height = height
      const ctx = canvas.getContext('2d', { willReadFrequently: true })

      if (!ctx) {
        URL.revokeObjectURL(video.src)
        reject(new MalformedEvidenceError())
        return
      }

      const positions = getBorderPositions(width, height)
      const bits: number[] = []
      let isDone = false
      let frameCount = 0

      const processFrame = async () => {
        if (isDone) return
        ctx.drawImage(video, 0, 0, width, height)
        const frameData = ctx.getImageData(0, 0, width, height)
        const data = frameData.data

        for (const [y, x] of positions) {
          const y0 = Math.max(0, y - BORDER_STRIDE)
          const y1 = Math.min(height, y + BORDER_STRIDE + 1)
          const x0 = Math.max(0, x - BORDER_STRIDE)
          const x1 = Math.min(width, x + BORDER_STRIDE + 1)

          let sum = 0
          let count = 0
          for (let py = y0; py < y1; py++) {
            for (let px = x0; px < x1; px++) {
              const idx = (py * width + px) * 4
              sum += data[idx] + data[idx + 1] + data[idx + 2]
              count += 3
            }
          }
          const mean = sum / count
          bits.push(mean >= 128 ? 1 : 0)
        }

        const res = await unpackProgressive(bits)
        if (res !== null) {
          isDone = true
          video.pause()
          URL.revokeObjectURL(video.src)
          resolve(res)
          return
        }

        frameCount++
        if (frameCount > 240 || video.ended || video.paused) {
          if (!isDone) {
            isDone = true
            URL.revokeObjectURL(video.src)
            reject(new MalformedEvidenceError())
          }
        } else {
          if ('requestVideoFrameCallback' in video) {
            ;(video as any).requestVideoFrameCallback(processFrame)
          } else {
            requestAnimationFrame(processFrame)
          }
        }
      }

      video
        .play()
        .then(() => {
          if ('requestVideoFrameCallback' in video) {
            ;(video as any).requestVideoFrameCallback(processFrame)
          } else {
            requestAnimationFrame(processFrame)
          }
        })
        .catch(() => {
          URL.revokeObjectURL(video.src)
          reject(new MalformedEvidenceError())
        })

      video.onended = () => {
        if (!isDone) {
          isDone = true
          URL.revokeObjectURL(video.src)
          reject(new MalformedEvidenceError())
        }
      }
    }

    video.onerror = () => {
      URL.revokeObjectURL(video.src)
      reject(new MalformedEvidenceError())
    }
  })
}
