/* global self */

'use strict'

module.exports = typeof self === 'undefined' ? null : (self.crypto || self.msCrypto)
