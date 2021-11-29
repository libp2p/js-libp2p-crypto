'use strict'

const randomBytes = require('../../random-bytes')

let impl

try {
  impl = require('./ed25519-native')
} catch {
  impl = require('./ed25519-wasm')
}

const PUBLIC_KEY_BYTE_LENGTH = 32
const PRIVATE_KEY_BYTE_LENGTH = 32
const SEED_BYTE_LENGTH = 32
const SIGNATURE_BYTE_LENGTH = 64

async function generateKey () {
  return generateKeyFromSeed(randomBytes(SEED_BYTE_LENGTH))
}

/**
 * Generate keypair from a seed
 *
 * @param {Uint8Array} seed - seed should be a 32 byte uint8array
 */
async function generateKeyFromSeed (seed) {
  assertBytes('seed', seed, SEED_BYTE_LENGTH)

  return impl.generateKeyFromSeed(seed)
}

/**
 * @param {Uint8Array} privateKey
 * @param {Uint8Array} message
 */
async function hashAndSign (privateKey, message) {
  assertBytes('privateKey', privateKey, PUBLIC_KEY_BYTE_LENGTH)
  assertBytes('message', message)

  return impl.hashAndSign(privateKey, message)
}

/**
 * @param {Uint8Array} publicKey
 * @param {Uint8Array} signature
 * @param {Uint8Array} message
 */
async function hashAndVerify (publicKey, signature, message) {
  assertBytes('publicKey', publicKey, PUBLIC_KEY_BYTE_LENGTH)
  assertBytes('signature', signature, SIGNATURE_BYTE_LENGTH)
  assertBytes('message', message)

  return impl.hashAndVerify(publicKey, signature, message)
}

function assertBytes (name, value, length) {
  if (!(value instanceof Uint8Array)) {
    throw new TypeError(`"${name}" must be a Uint8Array`)
  }

  if (length != null) {
    if (value.length !== length) {
      throw new TypeError(`"${name}" must be ${length} bytes in length`)
    }
  } else {
    if (!value.length) {
      throw new TypeError(`"${name}" must be have a length`)
    }
  }
}

module.exports = {
  publicKeyLength: PUBLIC_KEY_BYTE_LENGTH,
  privateKeyLength: PRIVATE_KEY_BYTE_LENGTH,

  generateKey,
  generateKeyFromSeed,
  hashAndSign,
  hashAndVerify
}
