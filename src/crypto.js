'use strict'

const crypto = getWebCrypto()
const multihashing = require('multihashing')

const sha2256 = multihashing.createHash('sha2-256')

function getWebCrypto () {
  let WebCrypto
  try {
    WebCrypto = require('node-webcrypto-ossl')
  } catch (err) {
  }

  if (typeof WebCrypto === 'function') {
    const webCrypto = new WebCrypto()
    return webCrypto
  }

  if (typeof window !== 'undefined') {
    require('webcrypto-shim')

    return window.crypto
  }

  throw new Error('Please use an environment with crypto support')
}

exports.generateKey = function (bits, callback) {
  crypto.subtle.generateKey(
    {
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: bits,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
      hash: {name: 'SHA-256'}
    },
    true,
    ['sign', 'verify']
  ).then((pair) => Promise.all([
    crypto.subtle.exportKey('pkcs8', pair.privateKey),
    crypto.subtle.exportKey('spki', pair.publicKey)
  ])).then((keys) => {
    callback(
      null,
      Buffer.from(keys[0]),
      Buffer.from(keys[1])
    )
  }).catch((err) => {
    callback(err)
  })
}

exports.getRandomValues = function (arr) {
  return Buffer.from(crypto.getRandomValues(arr).buffer)
}

exports.hashAndSign = function (key, msg, callback) {
  sha2256(msg, (err, digest) => {
    if (err) {
      return callback(err)
    }

    crypto.subtle.importKey(
      'pkcs8',
      key,
      {
        name: 'RSASSA-PKCS1-v1_5',
        hash: {name: 'SHA-256'}
      },
      false,
      ['sign']
    ).then((privateKey) => {
      return crypto.subtle.sign(
        {name: 'RSASSA-PKCS1-v1_5'},
        privateKey,
        Uint8Array.from(digest)
      )
    }).then((sig) => {
      callback(null, Buffer.from(sig))
    }).catch((err) => {
      callback(err)
    })
  })
}

exports.hashAndVerify = function (key, sig, msg, callback) {
  sha2256(msg, (err, digest) => {
    if (err) {
      return callback(err)
    }

    crypto.subtle.importKey(
      'spki',
      Uint8Array.from(key),
      {
        name: 'RSASSA-PKCS1-v1_5',
        hash: {name: 'SHA-256'}
      },
      false,
      ['verify']
    ).then((publicKey) => {
      return crypto.subtle.verify(
        {name: 'RSASSA-PKCS1-v1_5'},
        publicKey,
        Uint8Array.from(sig),
        Uint8Array.from(msg)
      )
    }).then((valid) => {
      callback(null, valid)
    }).catch((err) => {
      callback(err)
    })
  })
}
