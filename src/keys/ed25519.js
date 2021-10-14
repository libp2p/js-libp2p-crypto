'use strict'

// require('node-forge/lib/ed25519')
// const forge = require('node-forge/lib/forge')
const ed = require('noble-ed25519')

exports.publicKeyLength = 32 //forge.pki.ed25519.constants.PUBLIC_KEY_BYTE_LENGTH
exports.privateKeyLength = 64 // forge.pki.ed25519.constants.PRIVATE_KEY_BYTE_LENGTH

exports.generateKey = async function () {
  // const pair= forge.pki.ed25519.generateKeyPair()
  const privateKey = ed.utils.randomPrivateKey()
  return {
    privateKey,
    publicKey: await ed.getPublicKey(privateKey)
  }
}

// seed should be a 32 byte uint8array
exports.generateKeyFromSeed = async function (seed) { // eslint-disable-line require-await
  return forge.pki.ed25519.generateKeyPair({ seed })
}

exports.hashAndSign = function (key, msg) { // eslint-disable-line require-await
  // return forge.pki.ed25519.sign({ message: msg, privateKey: key })
  // return Uint8Array.from(nacl.sign.detached(msg, key))

  return ed.sign(msg, key)
}

exports.hashAndVerify = async function (key, sig, msg) { // eslint-disable-line require-await
  // return forge.pki.ed25519.verify({ signature: sig, message: msg, publicKey: key })

  return ed.verify(sig, msg, key)
}
