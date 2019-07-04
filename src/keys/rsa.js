'use strict'

const webcrypto = require('../webcrypto')

module.exports = webcrypto ? require('./rsa-webcrypto') : require('./rsa-crypto')
