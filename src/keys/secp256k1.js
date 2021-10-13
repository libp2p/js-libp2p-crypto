'use strict'

const secp = require('noble-secp256k1')
// const secp256k1 = require('secp256k1')
const { sha256 } = require('multiformats/hashes/sha2')

module.exports = (randomBytes) => {
  const privateKeyLength = 32

  function generateKey () {
    return secp.utils.randomPrivateKey()
  }

  async function hashAndSign (key, msg) {
    const { digest } = await sha256.digest(msg)

    return await secp.sign(digest, key)
  }

  async function hashAndVerify (key, sig, msg) {
    const { digest } = await sha256.digest(msg)

    return secp.verify(sig, digest, key)
  }

  function compressPublicKey (key, pkey) {
    const point = secp.Point.fromHex(key).toRawBytes(true)
    return point
  }

  function decompressPublicKey (key) {
    const point = secp.Point.fromHex(key).toRawBytes(false)
    return point
  }

  function validatePrivateKey (key) {
    secp.getPublicKey(key, true)
  }

  function validatePublicKey (key) {
    secp.Point.fromHex(key)
  }

  function computePublicKey (privateKey) {
    return secp.getPublicKey(privateKey, true)
  }

  return {
    generateKey,
    privateKeyLength,
    hashAndSign,
    hashAndVerify,
    compressPublicKey,
    decompressPublicKey,
    validatePrivateKey,
    validatePublicKey,
    computePublicKey
  }
}
