'use strict'

/**
 * Depending on the environemnt this returns
 * - Browser: `window.crypto`
 * - Node.js: If installed an instance of [`node-webcrypto-ossl`](https://github.com/PeculiarVentures/node-webcrypto-ossl), otherwise `undefined`
 *
 * @memberof libp2p-crypto
 * @alias webcrypto
 * @type {crypto|undefined}
 */
exports.webcrypto = require('./crypto/webcrypto')()

exports.hmac = require('./crypto/hmac')
exports.ecdh = require('./crypto/ecdh')
exports.aes = require('./crypto/aes')
exports.rsa = require('./crypto/rsa')
