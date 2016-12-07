'use strict'

const crypto = require('./crypto')

/**
 * Generates an ephemeral public key and returns a function that will compute
 * the shared secret key.
 *
 * Focuses only on ECDH now, but can be made more general in the future.
 *
 * @memberof libp2p-crypto
 * @alias generateEphemeralKeyPair
 * @param {string} curve - Can be one of `'P-256'`, `'P-384'` or `'P-521'`.
 * @param {function(Error, EphemeralKeyPair)} callback
 * @returns {undefined}
 */
module.exports = (curve, callback) => {
  crypto.ecdh.generateEphemeralKeyPair(curve, callback)
}

/**
 * @typedef {Object} EphemeralKeyPair
 * @param {Buffer} key - The generated public key
 * @param {genSharedKeyCb} genSharedKey
 */

/**
 * @callback genSharedKeyCb
 * @param {Buffer} theirPub
 * @param {function(Error, Buffer)} cb - Callback with the generated secret.
 * @returns {undefined}
 */
