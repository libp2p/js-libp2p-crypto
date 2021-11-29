'use strict'

const native = require('ed25519')

/**
 * Generate keypair from a seed
 *
 * @param {Uint8Array} seed - seed should be a 32 byte uint8array
 */
async function generateKeyFromSeed (seed) {
  const key = native.MakeKeypair(seed)

  return {
    privateKey: key.privateKey.subarray(0, 32),
    publicKey: key.publicKey
  }
}

/**
 * @param {Uint8Array} privateKey
 * @param {Uint8Array} message
 */
async function hashAndSign (privateKey, message) {
  return native.Sign(message, privateKey)
}

/**
 * @param {Uint8Array} publicKey
 * @param {Uint8Array} signature
 * @param {Uint8Array} message
 */
async function hashAndVerify (publicKey, signature, message) {
  return native.Verify(message, signature, publicKey)
}

module.exports = {
  generateKeyFromSeed,
  hashAndSign,
  hashAndVerify
}
