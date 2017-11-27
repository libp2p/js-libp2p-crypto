'use strict'

const crypto = require('crypto')
const keypair = require('keypair')
const setImmediate = require('async/setImmediate')
const pemToJwk = require('pem-jwk').pem2jwk
const jwkToPem = require('pem-jwk').jwk2pem

exports.utils = require('./rsa-utils')

exports.generateKey = function (bits, callback) {
  const done = (err, res) => setImmediate(() => callback(err, res))

  let key
  try {
    key = keypair({ bits: bits })
  } catch (err) {
    return done(err)
  }

  let res
  try {
    res = {
      privateKey: pemToJwk(key.private),
      publicKey: pemToJwk(key.public)
    }
  } catch (err) {
    return done(err)
  }

  done(null, res)
}

// Takes a jwk key
exports.unmarshalPrivateKey = function (key, callback) {
  try {
    key = {
      privateKey: key,
      publicKey: {
        kty: key.kty,
        n: key.n,
        e: key.e
      }
    }
  } catch (err) {
    callback(new Error('Key is invalid!'))
  }
  callback(null, key)
}

exports.getRandomValues = function (arr) {
  return crypto.randomBytes(arr.length)
}

exports.hashAndSign = function (key, msg, callback) {
  const sign = crypto.createSign('RSA-SHA256')

  let pem

  try {
    sign.update(msg)
    pem = jwkToPem(key)
  } catch (err) {
    return callback(new Error('Key or message is invalid!'))
  }

  setImmediate(() => callback(null, sign.sign(pem)))
}

exports.hashAndVerify = function (key, sig, msg, callback) {
  const verify = crypto.createVerify('RSA-SHA256')

  let pem

  try {
    verify.update(msg)
    pem = jwkToPem(key)
  } catch (err) {
    return callback(new Error('Key or message is invalid!'))
  }

  setImmediate(() => callback(null, verify.verify(pem, sig)))
}
