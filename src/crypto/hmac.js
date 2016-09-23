'use strict'

const crypto = require('crypto')

exports.create = function (hash, secret, callback) {
  const res = {
    digest (data, cb) {
      const hmac = genFresh()
      hmac.update(data)

      cb(null, hmac.digest())
    }
  }

  function genFresh () {
    return crypto.createHmac(hash.toLowerCase(), secret)
  }
  callback(null, res)
}
