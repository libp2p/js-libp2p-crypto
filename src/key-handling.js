'use strict'

module.exports = (crypto) => {
  const keys = crypto.keys
  const pbm = crypto.protobuf

  const isValidKeyType = (keyType) => {
    const key = keys[keyType.toLowerCase()]
    return key !== undefined
  }

  const toKeyName = (keyNumber) => {
    switch (keyNumber) {
      case 0:
        return 'rsa'
      case 1:
        return 'ed25519'
      case 2:
        return 'secp256k1'
      default:
        return ''
    }
  }

  // Generates a keypair of the given type and bitsize
  const generateKeyPair = (type, bits, cb) => {
    let key = keys[type.toLowerCase()]
    if (!key) {
      return cb(new Error('invalid or unsupported key type'))
    }

    key.generateKeyPair(bits, cb)
  }

  // Converts a protobuf serialized public key into its
  // representative object
  const unmarshalPublicKey = (buf) => {
    const decoded = pbm.PublicKey.decode(buf)
    const keyType = toKeyName(decoded.Type)

    if (!isValidKeyType(keyType)) {
      throw new Error('invalid or unsupported key type: ' + decoded.Type)
    }

    return keys[keyType].unmarshalPublicKey(decoded.Data)
  }

  // Converts a public key object into a protobuf serialized public key
  const marshalPublicKey = (key, type) => {
    type = (type || 'rsa').toLowerCase()
    if (!isValidKeyType(type)) {
      throw new Error('invalid or unsupported key type')
    }

    return key.bytes
  }

  // Converts a protobuf serialized private key into its
  // representative object
  const unmarshalPrivateKey = (buf, callback) => {
    const decoded = pbm.PrivateKey.decode(buf)
    const keyType = toKeyName(decoded.Type)

    if (!isValidKeyType(keyType)) {
      return callback(new Error('invalid or unsupported key type: ' + decoded.Type))
    }

    keys[keyType].unmarshalPrivateKey(decoded.Data, callback)
  }

  // Converts a private key object into a protobuf serialized private key
  const marshalPrivateKey = (key, type) => {
    type = (type || 'rsa').toLowerCase()
    if (!isValidKeyType(type)) {
      throw new Error('invalid or unsupported key type')
    }

    return key.bytes
  }

  return {
    generateKeyPair,
    unmarshalPublicKey,
    unmarshalPrivateKey,
    marshalPublicKey,
    marshalPrivateKey
  }
}
