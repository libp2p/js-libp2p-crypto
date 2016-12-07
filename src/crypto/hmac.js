'use strict'

const crypto = require('crypto')

const lengths = require('./hmac-lengths')

/**
 * Encrypt the given `data`.
 *
 * @callback HMACDigest
 * @param {Buffer} data
 * @param {function(Error, Buffer)} cb
 * @returns {undefined}
 */

/**
 * @typedef {Object} HMACCipher
 * @param {HMACDigest} digest
 * @param {number} length
 */

/**
 * @memberof libp2p-crypto
 * @alias hmac.create
 * @param {string} hash
 * @param {Buffer} secret
 * @param {function(Error, HMACCipher)} callback
 * @returns {undefined}
 */
exports.create = function (hash, secret, callback) {
  const res = {
    digest (data, cb) {
      const hmac = genFresh()
      hmac.update(data)

      setImmediate(() => {
        cb(null, hmac.digest())
      })
    },
    length: lengths[hash]
  }

  function genFresh () {
    return crypto.createHmac(hash.toLowerCase(), secret)
  }
  callback(null, res)
}
