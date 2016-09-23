'use strict'

const crypto = require('./webcrypto')()

exports.create = function (key, iv, callback) {
  crypto.subtle.importKey(
    'raw',
    key.buffer,
    {
      name: 'AES-CTR'
    },
    false,
    ['encrypt', 'decrypt']
  ).then((key) => {
    const counter = copy(iv).buffer

    const res = {
      encrypt (data, cb) {
        crypto.subtle.encrypt(
          {
            name: 'AES-CTR',
            counter: counter,
            length: 128
          },
          key,
          data.buffer
        ).then((raw) => {
          cb(null, Buffer.from(raw))
        }).catch((err) => {
          cb(err)
        })
      },

      decrypt (data, cb) {
        crypto.subtle.decrypt(
          {
            name: 'AES-CTR',
            counter: counter,
            length: 128
          },
          key,
          data.buffer
        ).then((raw) => {
          cb(null, Buffer.from(raw))
        }).catch((err) => {
          cb(err)
        })
      }
    }

    callback(null, res)
  }).catch((err) => {
    callback(err)
  })
}

function copy (buf) {
  const fresh = new Buffer(buf.length)
  buf.copy(fresh)

  return fresh
}
