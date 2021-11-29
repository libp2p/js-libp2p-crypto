'use strict'

const ed25519 = require('ed25519-wasm-pro')

const ready = new Promise((resolve) => {
  ed25519.ready(() => {
    resolve()
  })
})

/**
 * Generate keypair from a seed
 *
 * @param {Uint8Array} seed - seed should be a 32 byte uint8array
 */
async function generateKeyFromSeed (seed) {
  await ready

  const key = ed25519.createKeyPair(seed)

  return {
    privateKey: seed,
    publicKey: key.publicKey
  }
}

/**
 * @param {Uint8Array} privateKey
 * @param {Uint8Array} message
 */
async function hashAndSign (privateKey, message) {
  await ready

  const key = ed25519.createKeyPair(privateKey)

  return ed25519.sign(message, key.publicKey, key.secretKey)
}

/**
 * @param {Uint8Array} publicKey
 * @param {Uint8Array} signature
 * @param {Uint8Array} message
 */
async function hashAndVerify (publicKey, signature, message) {
  await ready

  return ed25519.verify(signature, message, publicKey)
}

module.exports = {
  generateKeyFromSeed,
  hashAndSign,
  hashAndVerify
}
