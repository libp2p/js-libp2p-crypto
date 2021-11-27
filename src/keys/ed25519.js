'use strict'

const { subtle } = require('crypto').webcrypto
const { fromString: uint8ArrayFromString } = require('uint8arrays/from-string')
const { concat: uint8ArrayConcat } = require('uint8arrays/concat')

const PUBLIC_KEY_BYTE_LENGTH = 32
const PRIVATE_KEY_BYTE_LENGTH = 64 // private key is actually 32 bytes but for historical reasons we concat private and public keys
const KEYS_BYTE_LENGTH = 32

const ED25519_PKCS8_PREFIX = uint8ArrayFromString('302e020100300506032b657004220420', 'hex')

exports.publicKeyLength = PUBLIC_KEY_BYTE_LENGTH
exports.privateKeyLength = PRIVATE_KEY_BYTE_LENGTH

const ALGORITHM = 'NODE-ED25519'

exports.generateKey = async function () {
  const key = await subtle.generateKey({
    name: ALGORITHM,
    namedCurve: ALGORITHM
  }, true, ['sign', 'verify'])

  const privateKeyPKCS8 = await subtle.exportKey('pkcs8', key.privateKey)
  // get the raw key out of the PCKS#8 format buffer
  const privateKey = new Uint8Array(privateKeyPKCS8).subarray(ED25519_PKCS8_PREFIX.length)
  const publicKey = new Uint8Array(await subtle.exportKey('raw', key.publicKey))

  return {
    privateKey: uint8ArrayConcat([
      privateKey,
      publicKey
    ], privateKey.length + publicKey.length),
    publicKey
  }
}

/**
 * Generate keypair from a seed
 *
 * @param {Uint8Array} seed - seed should be a 32 byte uint8array
 * @returns
 */
exports.generateKeyFromSeed = async function (seed) {
  if (seed.length !== KEYS_BYTE_LENGTH) {
    throw new TypeError('"seed" must be 32 bytes in length.')
  } else if (!(seed instanceof Uint8Array)) {
    throw new TypeError('"seed" must be a node.js Buffer, or Uint8Array.')
  }

  // based on node forge's algorithm, the seed is used directly as private key
  const pkcs8 = uint8ArrayConcat([
    ED25519_PKCS8_PREFIX,
    seed
  ], ED25519_PKCS8_PREFIX.length + seed.length)

  // read private key
  const privateKey = await subtle.importKey('pkcs8', pkcs8, {
    name: ALGORITHM,
    namedCurve: ALGORITHM
  }, true, ['sign'])

  // export the private key as jwk
  const privateKeyJWK = await subtle.exportKey('jwk', privateKey)

  // read the public key out of the jwk
  const publicKey = uint8ArrayFromString(privateKeyJWK.x, 'base64url')

  return {
    privateKey: uint8ArrayConcat([
      seed,
      publicKey
    ], seed.length + publicKey.length),
    publicKey
  }
}

exports.hashAndSign = async function (privateKey, msg) {
  const pkcs8 = uint8ArrayConcat([
    ED25519_PKCS8_PREFIX,
    privateKey
  ], ED25519_PKCS8_PREFIX.length + privateKey.length)
  const key = await subtle.importKey('pkcs8', pkcs8, {
    name: ALGORITHM,
    namedCurve: ALGORITHM
  }, true, ['sign'])

  const signature = await subtle.sign(ALGORITHM, key, msg)

  return new Uint8Array(signature)
}

exports.hashAndVerify = async function (publicKey, sig, msg) {
  if (!(publicKey instanceof Uint8Array)) {
    throw new TypeError('"publicKey" must be a node.js Buffer, or Uint8Array.')
  }

  if (publicKey.length !== KEYS_BYTE_LENGTH) {
    throw new TypeError('"publicKey" must be 32 bytes in length.')
  }

  if (!(sig instanceof Uint8Array)) {
    throw new TypeError('"sig" must be a node.js Buffer, or Uint8Array.')
  }

  if (sig.length !== 64) {
    throw new TypeError('"sig" must be 64 bytes in length.')
  }

  if (!(msg instanceof Uint8Array)) {
    throw new TypeError('"msg" must be a node.js Buffer, or Uint8Array.')
  }

  if (!msg.length) {
    throw new TypeError('"msg" must have a length.')
  }

  const key = await subtle.importKey('raw', publicKey, {
    name: ALGORITHM,
    namedCurve: ALGORITHM,
    public: true
  }, true, ['verify'])

  return subtle.verify(ALGORITHM, key, sig, msg)
}
