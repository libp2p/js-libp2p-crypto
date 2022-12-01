import crypto from 'crypto'
import { promisify } from 'util'

const keypair = promisify(crypto.generateKeyPair)

const PUBLIC_KEY_BYTE_LENGTH = 32
const PRIVATE_KEY_BYTE_LENGTH = 64 // private key is actually 32 bytes but for historical reasons we concat private and public keys
const KEYS_BYTE_LENGTH = 32
const SIGNATURE_BYTE_LENGTH = 64

export { PUBLIC_KEY_BYTE_LENGTH as publicKeyLength }
export { PRIVATE_KEY_BYTE_LENGTH as privateKeyLength }

function derivePublicKey (privateKey: Uint8Array) {
  const hash = crypto.createHash('sha512')
  hash.update(privateKey)
  return hash.digest().slice(32)
}

export async function generateKey () {
  const key = await keypair('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'jwk' },
    privateKeyEncoding: { type: 'pkcs8', format: 'jwk' }
  })

  // @ts-expect-error node types are missing jwk as a format
  const privateKeyRaw = Buffer.from(key.privateKey.d, 'base64')
  // @ts-expect-error node types are missing jwk as a format
  const publicKeyRaw = Buffer.from(key.privateKey.x, 'base64')

  return {
    privateKey: concatKeys(privateKeyRaw, publicKeyRaw),
    publicKey: publicKeyRaw
  }
}

/**
 * Generate keypair from a 32 byte uint8array
 */
export async function generateKeyFromSeed (seed: Uint8Array) {
  if (seed.length !== KEYS_BYTE_LENGTH) {
    throw new TypeError('"seed" must be 32 bytes in length.')
  } else if (!(seed instanceof Uint8Array)) {
    throw new TypeError('"seed" must be a node.js Buffer, or Uint8Array.')
  }

  // based on node forges algorithm, the seed is used directly as private key
  const publicKeyRaw = derivePublicKey(seed)

  return {
    privateKey: concatKeys(seed, publicKeyRaw),
    publicKey: publicKeyRaw
  }
}

export async function hashAndSign (key: Uint8Array, msg: Uint8Array) {
  if (!(key instanceof Uint8Array)) {
    throw new TypeError('"key" must be a node.js Buffer, or Uint8Array.')
  }

  let privateKey: Uint8Array
  let publicKey: Uint8Array

  if (key.byteLength === PRIVATE_KEY_BYTE_LENGTH) {
    privateKey = key.slice(0, 32)
    publicKey = key.slice(32)
  } else if (key.byteLength === KEYS_BYTE_LENGTH) {
    privateKey = key.slice(0, 32)
    publicKey = derivePublicKey(privateKey)
  } else {
    throw new TypeError('"key" must be 64 or 32 bytes in length.')
  }

  const obj = crypto.createPrivateKey({
    format: 'jwk',
    key: {
      crv: 'Ed25519',
      d: Buffer.from(privateKey).toString('base64'),
      x: Buffer.from(publicKey).toString('base64'),
      kty: 'OKP'
    }
  })

  return crypto.sign(null, msg, obj)
}

export async function hashAndVerify (key: Uint8Array, sig: Uint8Array, msg: Uint8Array) {
  if (key.byteLength !== PUBLIC_KEY_BYTE_LENGTH) {
    throw new TypeError('"key" must be 32 bytes in length.')
  } else if (!(key instanceof Uint8Array)) {
    throw new TypeError('"key" must be a node.js Buffer, or Uint8Array.')
  }

  if (sig.byteLength !== SIGNATURE_BYTE_LENGTH) {
    throw new TypeError('"sig" must be 64 bytes in length.')
  } else if (!(sig instanceof Uint8Array)) {
    throw new TypeError('"sig" must be a node.js Buffer, or Uint8Array.')
  }

  const obj = crypto.createPublicKey({
    format: 'jwk',
    key: {
      crv: 'Ed25519',
      x: Buffer.from(key).toString('base64'),
      kty: 'OKP'
    }
  })

  return crypto.verify(null, msg, obj, sig)
}

function concatKeys (privateKeyRaw: Uint8Array, publicKey: Uint8Array) {
  const privateKey = new Uint8Array(PRIVATE_KEY_BYTE_LENGTH)
  for (let i = 0; i < KEYS_BYTE_LENGTH; i++) {
    privateKey[i] = privateKeyRaw[i]
    privateKey[KEYS_BYTE_LENGTH + i] = publicKey[i]
  }
  return privateKey
}
