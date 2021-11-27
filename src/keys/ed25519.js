'use strict'

const webcrypto = require('crypto').webcrypto

if (!webcrypto || !webcrypto.subtle) {
  module.exports = require('./ed25519-browser')
} else {
  module.exports = require('./ed25519-node')
}
