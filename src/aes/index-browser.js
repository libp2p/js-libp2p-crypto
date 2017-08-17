'use strict'

const aes = require('aes-js')
const Ctr = aes.ModeOfOperation.ctr

exports.create = function (key, iv, callback) {
  const cipher = new Ctr(key, new aes.Counter(iv))
  const decipher = new Ctr(key, new aes.Counter(iv))

  const res = {
    encrypt (data, cb) {
      cb(null, Buffer.from(cipher.encrypt(data)))
    },

    decrypt (data, cb) {
      cb(null, Buffer.from(decipher.decrypt(data)))
    }
  }

  callback(null, res)
}
