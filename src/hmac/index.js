'use strict'

const webcrypto = require('../webcrypto')

module.exports = webcrypto ? require('./index-webcrypto') : require('./index-crypto')
