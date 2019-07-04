'use strict'

const webcrypto = require('../webcrypto')

module.exports = webcrypto ? require('./ecdh-webcrypto') : require('./ecdh-crypto')
