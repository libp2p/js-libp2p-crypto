'use strict'
const randomBytes = require('iso-random-stream/src/random')
const errcode = require('err-code')

module.exports = function (length) {
  if (!length || typeof length !== 'number' || length <= 0) {
    throw errcode('random bytes length must be a Number bigger than 0', 'ERR_INVALID_LENGTH')
  }
  return randomBytes(length)
}
