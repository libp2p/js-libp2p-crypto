'use strict'

const crypto = require('crypto')

// Check native crypto exists and is enabled (In insecure context `self.crypto`
// exists but `self.crypto.subtle` does not).
exports.get = () => {
  return crypto.webcrypto
}
