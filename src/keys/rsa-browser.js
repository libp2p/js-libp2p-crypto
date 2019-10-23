'use strict'

const nodeify = require('../nodeify')
const webcrypto = require('../webcrypto')
const randomBytes = require('../random-bytes')

exports.utils = require('./rsa-utils')

exports.generateKey = function (bits, callback) {
  nodeify(webcrypto.subtle.generateKey(
    {
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: bits,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
      hash: { name: 'SHA-256' }
    },
    true,
    ['sign', 'verify']
  )
    .then(exportKey)
    .then((keys) => ({
      privateKey: keys[0],
      publicKey: keys[1]
    })), callback)
}

// Takes a jwk key
exports.unmarshalPrivateKey = function (key, callback) {
  const privateKey = webcrypto.subtle.importKey(
    'jwk',
    key,
    {
      name: 'RSASSA-PKCS1-v1_5',
      hash: { name: 'SHA-256' }
    },
    true,
    ['sign']
  )

  nodeify(Promise.all([
    privateKey,
    derivePublicFromPrivate(key)
  ]).then((keys) => exportKey({
    privateKey: keys[0],
    publicKey: keys[1]
  })).then((keys) => ({
    privateKey: keys[0],
    publicKey: keys[1]
  })), callback)
}

exports.getRandomValues = randomBytes

exports.hashAndSign = function (key, msg, callback) {
  nodeify(webcrypto.subtle.importKey(
    'jwk',
    key,
    {
      name: 'RSASSA-PKCS1-v1_5',
      hash: { name: 'SHA-256' }
    },
    false,
    ['sign']
  ).then((privateKey) => {
    return webcrypto.subtle.sign(
      { name: 'RSASSA-PKCS1-v1_5' },
      privateKey,
      Uint8Array.from(msg)
    )
  }).then((sig) => Buffer.from(sig)), callback)
}

exports.hashAndVerify = function (key, sig, msg, callback) {
  nodeify(webcrypto.subtle.importKey(
    'jwk',
    key,
    {
      name: 'RSASSA-PKCS1-v1_5',
      hash: { name: 'SHA-256' }
    },
    false,
    ['verify']
  ).then((publicKey) => {
    return webcrypto.subtle.verify(
      { name: 'RSASSA-PKCS1-v1_5' },
      publicKey,
      sig,
      msg
    )
  }), callback)
}

function exportKey (pair) {
  return Promise.all([
    webcrypto.subtle.exportKey('jwk', pair.privateKey),
    webcrypto.subtle.exportKey('jwk', pair.publicKey)
  ])
}

function derivePublicFromPrivate (jwKey) {
  return webcrypto.subtle.importKey(
    'jwk',
    {
      kty: jwKey.kty,
      n: jwKey.n,
      e: jwKey.e
    },
    {
      name: 'RSASSA-PKCS1-v1_5',
      hash: { name: 'SHA-256' }
    },
    true,
    ['verify']
  )
}

/*

RSA encryption/decryption for the browser with webcrypto workarround
"bloody dark magic. webcrypto's why."

Explanation:
  - Convert JWK to PEM
  - Load PEM with nodeForge
  - Convert msg buffer to nodeForge buffer: it's already uint8array, so do nothing
  - Convert resulting nodeForge buffer to buffer: it returns a binary string, turn that into a uint8array

*/

const forge = require('node-forge')
const pki = forge.pki
const jwkToPem = require('pem-jwk').jwk2pem
function convertKey (key, pub, msg, handle) {
  const pem = jwkToPem(key)
  const fkey = pki[pub ? 'publicKeyFromPem' : 'privateKeyFromPem'](pem)
  const fomsg = handle(Buffer.from(msg), fkey)
  return Buffer.from(fomsg, 'binary')
}

exports.encrypt = function (key, msg) {
  return convertKey(key, true, msg, (msg, key) => key.encrypt(msg))
}

exports.decrypt = function (key, msg) {
  return convertKey(key, false, msg, (msg, key) => key.decrypt(msg))
}
