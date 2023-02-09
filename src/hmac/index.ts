import crypto from 'crypto'
import lengths from './lengths.js'

export async function create (hash: 'SHA1' | 'SHA256' | 'SHA512', secret: Uint8Array): Promise<{ digest: (data: Uint8Array) => Promise<Buffer>, length: number }> {
  const res = {
    async digest (data: Uint8Array) { // eslint-disable-line require-await
      const hmac = crypto.createHmac(hash.toLowerCase(), secret)
      hmac.update(data)
      return hmac.digest()
    },
    length: lengths[hash]
  }

  return res
}
