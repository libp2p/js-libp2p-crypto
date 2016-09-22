'use strict'

const protobuf = require('protocol-buffers')
const pbm = protobuf(require('./crypto.proto'))

const keys = exports.keys = require('./keys')
exports.pbm = pbm
exports.keyStretcher = require('./key-stretcher')
exports.generateEphemeralKeyPair = require('./ephemeral-keys')

// Generates a keypair of the given type and bitsize
exports.generateKeyPair = (type, bits, cb) => {
  let key = keys[type.toLowerCase()]
  if (!key) {
    throw new Error('invalid or unsupported key type')
  }

  key.generateKeyPair(bits, cb)
}

// Converts a protobuf serialized public key into its
// representative object
exports.unmarshalPublicKey = (buf) => {
  const decoded = pbm.PublicKey.decode(buf)

  switch (decoded.Type) {
    case pbm.KeyType.RSA:
      return keys.rsa.unmarshalRsaPublicKey(decoded.Data)
    default:
      throw new Error('invalid or unsupported key type')
  }
}

// Converts a public key object into a protobuf serialized public key
exports.marshalPublicKey = (key, type) => {
  type = (type || 'rsa').toLowerCase()

  // for now only rsa is supported
  if (type !== 'rsa') {
    throw new Error('invalid or unsupported key type')
  }

  return pbm.PublicKey.encode({
    Type: pbm.KeyType.RSA,
    Data: key.marshal()
  })
}

// Converts a protobuf serialized private key into its
// representative object
exports.unmarshalPrivateKey = (buf, callback) => {
  const decoded = pbm.PrivateKey.decode(buf)

  switch (decoded.Type) {
    case pbm.KeyType.RSA:
      return keys.rsa.unmarshalRsaPrivateKey(decoded.Data, callback)
    default:
      callback(new Error('invalid or unsupported key type'))
  }
}

// Converts a private key object into a protobuf serialized private key
exports.marshalPrivateKey = (key, type) => {
  type = (type || 'rsa').toLowerCase()

  // for now only rsa is supported
  if (type !== 'rsa') {
    throw new Error('invalid or unsupported key type')
  }

  return pbm.PrivateKey.encode({
    Type: pbm.KeyType.RSA,
    Data: key.marshal()
  })
}
