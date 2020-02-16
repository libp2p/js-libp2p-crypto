'use strict'

const { Buffer } = require('buffer')
require('node-forge/lib/util')
require('node-forge/lib/jsbn')
const forge = require('node-forge/lib/forge')

exports.bigIntegerToBase64url = buf => {
  return exports.bufferToBase64url(Buffer.from(buf.toByteArray()))
}

// Convert a Buffer to a base64 encoded string without padding
// Adapted from https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-41#appendix-C
exports.bufferToBase64url = buf => {
  return buf
    .toString('base64')
    .split('=')[0] // Remove any trailing '='s
    .replace(/\+/g, '-') // 62nd char of encoding
    .replace(/\//g, '_') // 63rd char of encoding
}

// Convert a base64url encoded string to a BigInteger
exports.base64urlToBigInteger = str => {
  str = (str + '==='.slice((str.length + 3) % 4))
    .replace(/-/g, '+')
    .replace(/_/g, '/')
  const bytes = forge.util.decode64(str)
  return new forge.jsbn.BigInteger(forge.util.bytesToHex(bytes), 16)
}
