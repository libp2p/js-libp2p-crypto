'use strict'

const crypto = require('./crypto')

exports.randomBytes = (number) => {
  if (!number || typeof number !== 'number') {
    throw new Error('first argument must be a Number bigger than 0')
  }

  return crypto.rsa.getRandomValues(new Uint8Array(number))
}
