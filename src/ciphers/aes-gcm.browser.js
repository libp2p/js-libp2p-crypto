'use strict'

const webcrypto = require('../webcrypto')

// Based off of code from https://github.com/luke-park/SecureCompatibleEncryptionExamples

/**
 *
 * @param {object} param0
 * @param {string} [param0.algorithm] Defaults to 'aes-128-gcm'
 * @param {Number} [param0.nonceLength] Defaults to 12 (96-bit)
 * @param {Number} [param0.keyLength] Defaults to 16
 * @param {string} [param0.digest] Defaults to 'sha256'
 * @param {Number} [param0.saltLength] Defaults to 16
 * @param {Number} [param0.iterations] Defaults to 32767
 * @returns {*}
 */
function create ({
  algorithm = 'AES-GCM',
  nonceLength = 12,
  keyLength = 16,
  digest = 'SHA-256',
  saltLength = 16,
  iterations = 32767
} = {}) {
  const crypto = webcrypto.get()
  keyLength *= 8 // Browser crypto uses bits instead of bytes

  /**
   *
   * @param {Uint8Array} data The data to decrypt
   * @param {string} password A plain password
   */
  async function encrypt (data, password) { // eslint-disable-line require-await
    const salt = crypto.getRandomValues(new Uint8Array(saltLength))
    const nonce = crypto.getRandomValues(new Uint8Array(nonceLength))
    const aesGcm = { name: algorithm, iv: nonce }

    // Derive a key using PBKDF2.
    const deriveParams = { name: 'PBKDF2', salt, iterations, hash: { name: digest } }
    const rawKey = await crypto.subtle.importKey('raw', (new TextEncoder()).encode(password), { name: 'PBKDF2' }, false, ['deriveKey', 'deriveBits'])
    const cryptoKey = await crypto.subtle.deriveKey(deriveParams, rawKey, { name: algorithm, length: keyLength }, true, ['encrypt'])

    // Encrypt the string.
    const ciphertext = await crypto.subtle.encrypt(aesGcm, cryptoKey, data)
    return joinBuffers(salt, joinBuffers(aesGcm.iv, new Uint8Array(ciphertext)))
  }

  async function decrypt (data, password) {
    const salt = data.slice(0, saltLength)
    const nonce = data.slice(saltLength, saltLength + nonceLength)
    const ciphertext = data.slice(saltLength + nonceLength)
    const aesGcm = { name: algorithm, iv: nonce }

    // Derive the key using PBKDF2.
    const deriveParams = { name: 'PBKDF2', salt, iterations, hash: { name: digest } }
    const rawKey = await crypto.subtle.importKey('raw', (new TextEncoder()).encode(password), { name: 'PBKDF2' }, false, ['deriveKey', 'deriveBits'])
    const cryptoKey = await crypto.subtle.deriveKey(deriveParams, rawKey, { name: algorithm, length: keyLength }, true, ['decrypt'])

    // Decrypt the string.
    const plaintext = await crypto.subtle.decrypt(aesGcm, cryptoKey, ciphertext)
    return new Uint8Array(plaintext)
  }

  return {
    encrypt,
    decrypt
  }
}

function joinBuffers (a, b) {
  const c = new Uint8Array(a.byteLength + b.byteLength)

  for (let i = 0; i < a.length; i++) {
    c[i] = a[i]
  }
  for (let i = 0; i < b.length; i++) {
    c[i + a.length] = b[i]
  }

  return c
}

module.exports = {
  create
}
