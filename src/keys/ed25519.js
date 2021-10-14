'use strict'

const ed = require('noble-ed25519')

exports.publicKeyLength = 32 
exports.privateKeyLength = 64 // private key is 32 bytes actual private key and 32 bytes public key, for historical reasons

exports.generateKey = async function () {
  // the actual private key (32 bytes)
  const privateKeyRaw = ed.utils.randomPrivateKey()
  const publicKey = await ed.getPublicKey(privateKeyRaw)

  // concatenated the public key to the private key
  const privateKey = concatKeys(privateKeyRaw, publicKey)

  return {
    privateKey,
    publicKey
  }
}

// seed should be a 32 byte uint8array
exports.generateKeyFromSeed = async function (seed) { // eslint-disable-line require-await
  if (seed.length !== 32) {
    throw new TypeError('"seed" must be 32 bytes in length.')
  } else if (!(seed instanceof Uint8Array)) {
    throw new TypeError('"seed" must be a node.js Buffer, or Uint8Array.')
  }

  // based on node.forges algorithm, the seed is used directly as private key
  const privateKeyRaw = seed;
  const publicKey = await ed.getPublicKey(privateKeyRaw)
  
  const privateKey = concatKeys(privateKeyRaw, publicKey)

  return {
    privateKey,
    publicKey
  }
}

exports.hashAndSign = function (privateKey, msg) { // eslint-disable-line require-await
  const privateKeyRaw = privateKey.slice(0, 32)

  return ed.sign(msg, privateKeyRaw)
}

exports.hashAndVerify = async function (publicKey, sig, msg) { // eslint-disable-line require-await
  return ed.verify(sig, msg, publicKey)
}

function concatKeys(privateKeyRaw, publicKey) {
  const privateKey = new Uint8Array(exports.privateKeyLength)
  for (let i = 0; i < 32; i++) {
    privateKey[i] = privateKeyRaw[i]
    privateKey[32 + i] = publicKey[i]
  }
  return privateKey
}
