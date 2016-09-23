'use strict'

const crypto = require('./crypto/webcrypto')()
const multihashing = require('multihashing')

const sha2256 = multihashing.createHash('sha2-256')

exports.hmac = require('./crypto/hmac')
exports.ecdh = require('./crypto/ecdh')

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
  )
  .then(exportKey)
  .then((keys) => {
    callback(
      null,
      Buffer.from(keys[0]),
      Buffer.from(keys[1])
    )
  }).catch((err) => {
    callback(err)
  })
}

exports.unmarshalPrivateKey = function (bytes, callback) {
  const privateKey = crypto.subtle.importKey(
    'pkcs8',
    bytes,
    {
      name: 'RSASSA-PKCS1-v1_5',
      hash: {name: 'SHA-256'}
    },
    true,
    ['sign']
  )
  Promise.all([
    privateKey,
    derivePublicFromPrivate(privateKey)
  ]).then((keys) => {
    return exportKey({
      privateKey: keys[0],
      publicKey: keys[1]
    })
  }).then((keys) => {
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
      Uint8Array.from(key),
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
        Uint8Array.from(digest)
      )
    }).then((valid) => {
      callback(null, valid)
    }).catch((err) => {
      callback(err)
    })
  })
}

function exportKey (pair) {
  return Promise.all([
    crypto.subtle.exportKey('pkcs8', pair.privateKey),
    crypto.subtle.exportKey('spki', pair.publicKey)
  ])
}

function derivePublicFromPrivate (privatePromise) {
  return privatePromise.then((privateKey) => {
    return crypto.subtle.exportKey('jwk', privateKey)
  }).then((jwKey) => crypto.subtle.importKey(
    'jwk',
    {
      kty: jwKey.kty,
      n: jwKey.n,
      e: jwKey.e,
      alg: jwKey.alg,
      kid: jwKey.kid
    },
    {
      name: 'RSASSA-PKCS1-v1_5',
      hash: {name: 'SHA-256'}
    },
    true,
    ['verify']
  ))
}
