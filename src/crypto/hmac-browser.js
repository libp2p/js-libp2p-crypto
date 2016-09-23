'use strict'

const crypto = require('./webcrypto')()
const lengths = require('./hmac-lengths')

const hashTypes = {
  SHA1: 'SHA-1',
  SHA256: 'SHA-256',
  SHA512: 'SHA-512'
}

exports.create = function (hashType, secret, callback) {
  const hash = hashTypes[hashType]

  crypto.subtle.importKey(
    'raw',
    secret.buffer,
    {
      name: 'HMAC',
      hash: {name: hash}
    },
    false,
    ['sign']
  ).then((key) => {
    const res = {
      digest (data, cb) {
        crypto.subtle.sign(
          {name: 'HMAC'},
          key,
          data.buffer
        ).then((raw) => {
          cb(null, Buffer.from(raw))
        }).catch((err) => {
          cb(err)
        })
      },
      length: lengths[hashType]
    }

    callback(null, res)
  }).catch((err) => {
    callback(err)
  })
}
