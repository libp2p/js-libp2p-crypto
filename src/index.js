'use strict'

const protobuf = require('protocol-buffers')

const c = require('./crypto')
const utils = require('./utils')

const crypto = module.exports = {
  protobuf: protobuf(require('./crypto.proto')),
  hmac: c.hmac,
  aes: c.aes,
  rsa: c.rsa,
  ed25519: c.ed25519,
  webcrypto: c.webcrypto,
  keyStretcher: require('./key-stretcher'),
  generateEphemeralKeyPair: require('./ephemeral-keys'),
  randomBytes: utils.randomBytes,
  keys: {}
}

const keys = require('./keys')

crypto.addKeyType = (name, type) => {
  crypto.keys[name] = type(crypto)
}

Object.keys(keys).forEach((name) => {
  crypto.addKeyType(name, keys[name])
})

const keyHandling = require('./key-handling')(crypto)

crypto.generateKeyPair = keyHandling.generateKeyPair
crypto.unmarshalPublicKey = keyHandling.unmarshalPublicKey
crypto.unmarshalPrivateKey = keyHandling.unmarshalPrivateKey
crypto.marshalPublicKey = keyHandling.marshalPublicKey
crypto.marshalPrivateKey = keyHandling.marshalPrivateKey
