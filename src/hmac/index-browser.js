'use strict'

const nodeify = require('../nodeify')

const crypto = require('../webcrypto')
const lengths = require('./lengths')
const nextTick = require('async/nextTick')
const { ERR_MISSING_WEB_CRYPTO } = require('../errors')

const hashTypes = {
  SHA1: 'SHA-1',
  SHA256: 'SHA-256',
  SHA512: 'SHA-512'
}

const sign = (key, data, cb) => {
  nodeify(crypto.get().subtle.sign({ name: 'HMAC' }, key, data)
    .then((raw) => Buffer.from(raw)), cb)
}

exports.create = function (hashType, secret, callback) {
  if (!crypto.get()) {
    return nextTick(() => callback(ERR_MISSING_WEB_CRYPTO()))
  }

  const hash = hashTypes[hashType]

  nodeify(crypto.get().subtle.importKey(
    'raw',
    secret,
    {
      name: 'HMAC',
      hash: { name: hash }
    },
    false,
    ['sign']
  ).then((key) => {
    return {
      digest (data, cb) {
        sign(key, data, cb)
      },
      length: lengths[hashType]
    }
  }), callback)
}
