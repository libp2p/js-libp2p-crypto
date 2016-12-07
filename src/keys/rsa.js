'use strict'

const multihashing = require('multihashing-async')
const protobuf = require('protocol-buffers')

const crypto = require('../crypto').rsa
const pbm = protobuf(require('../crypto.proto'))

/**
 *
 */
class RsaPublicKey {
  /**
   * @param {Object} key - In jwk format.
   */
  constructor (key) {
    this._key = key
  }

  /**
   * @param {Buffer} data - Data to verify
   * @param {Buffer} sig - Signature
   * @param {function(Error, boolean)} callback
   * @returns {undefined}
   */
  verify (data, sig, callback) {
    ensure(callback)
    crypto.hashAndVerify(this._key, sig, data, callback)
  }

  /**
   * @returns {Buffer} The key in PKIX format.
   */
  marshal () {
    return crypto.utils.jwkToPkix(this._key)
  }

  /**
   * @type {Buffer}
   */
  get bytes () {
    return pbm.PublicKey.encode({
      Type: pbm.KeyType.RSA,
      Data: this.marshal()
    })
  }

  /**
   * Encrypt data with `RSAES-PKCS1-V1_5`.
   *
   * @param {Buffer} bytes - The data to encrypt.
   * @returns {Buffer}
   */
  encrypt (bytes) {
    return this._key.encrypt(bytes, 'RSAES-PKCS1-V1_5')
  }

  /**
   * Compare this key to another.
   *
   * @param {RSAPublicKey} key
   * @returns {boolean}
   */
  equals (key) {
    return this.bytes.equals(key.bytes)
  }

  /**
   * Hash this key with 'SHA2-256'.
   *
   * @param {function(Error, Buffer)} callback
   * @returns {undefined}
   */
  hash (callback) {
    ensure(callback)
    multihashing(this.bytes, 'sha2-256', callback)
  }
}

/**
 *
 */
class RsaPrivateKey {
  /**
   * @param {Object} key - In JWK format
   * @param {Buffer} publicKey - In SPKI format
   */
  constructor (key, publicKey) {
    this._key = key
    this._publicKey = publicKey
  }

  /**
   * Generate a 16 bytes long secret.
   *
   * @returns {Buffer}
   */
  genSecret () {
    return crypto.getRandomValues(new Uint8Array(16))
  }

  /**
   * Hash and sign a message.
   *
   * @param {Buffer} message - The data to sign.
   * @param {function(Error, Buffer)} callback
   * @returns {undefined}
   */
  sign (message, callback) {
    ensure(callback)
    crypto.hashAndSign(this._key, message, callback)
  }

  /**
   * @type {RSAPublicKey}
   */
  get public () {
    if (!this._publicKey) {
      throw new Error('public key not provided')
    }

    return new RsaPublicKey(this._publicKey)
  }

  /**
   * Decrypt a given message.
   *
   * @param {Buffer} msg - The data to be decrypted.
   * @param {function(Error, Buffer)} callback
   * @returns {undefined}
   */
  decrypt (msg, callback) {
    crypto.decrypt(this._key, msg, callback)
  }

  /**
   * The key in PKCS1 format.
   *
   * @returns {Buffer}
   */
  marshal () {
    return crypto.utils.jwkToPkcs1(this._key)
  }

  /**
   * @type {Buffer}
   */
  get bytes () {
    return pbm.PrivateKey.encode({
      Type: pbm.KeyType.RSA,
      Data: this.marshal()
    })
  }

  /**
   * Compare this key to another.
   *
   * @param {RSAPrivateKey} key
   * @returns {boolean}
   */
  equals (key) {
    return this.bytes.equals(key.bytes)
  }

  /**
   * Hash this key with `SHA2-256`.
   *
   * @param {function(Error, Buffer)} callback
   * @returns {undefine}
   */
  hash (callback) {
    ensure(callback)
    multihashing(this.bytes, 'sha2-256', callback)
  }
}

/**
 * Unmarshal an RSA private key.
 *
 * @memberof libp2p-crypto
 * @alias keys.rsa.unmarshalRSAPrivateKey
 *
 * @param {Buffer} bytes - The key in PKCS1 format.
 * @param {function(Error, RSAPrivateKey)} callback
 * @returns {undefined}
 */
function unmarshalRsaPrivateKey (bytes, callback) {
  const jwk = crypto.utils.pkcs1ToJwk(bytes)
  crypto.unmarshalPrivateKey(jwk, (err, keys) => {
    if (err) {
      return callback(err)
    }

    callback(null, new RsaPrivateKey(keys.privateKey, keys.publicKey))
  })
}

/**
 * Unmarshal an RSA public key.
 *
 * @memberof libp2p-crypto
 * @alias keys.rsa.unmarshalRSAPublicKey
 *
 * @param {Buffer} bytes - The key in PKIX format.
 * @returns {RSAPublicKey}
 */
function unmarshalRsaPublicKey (bytes) {
  const jwk = crypto.utils.pkixToJwk(bytes)

  return new RsaPublicKey(jwk)
}

/**
 * Generate a new RSA key pair.
 *
 * @memberof libp2p-crypto
 * @alias keys.rsa.generateKeyPair
 *
 * @param {number} bits - The bitlenght, minimum `1024`.
 * @param {function(Error, RSAPrivateKey)} callback
 * @returns {undefined}
 */
function generateKeyPair (bits, callback) {
  crypto.generateKey(bits, (err, keys) => {
    if (err) {
      return callback(err)
    }

    callback(null, new RsaPrivateKey(keys.privateKey, keys.publicKey))
  })
}

function ensure (callback) {
  if (typeof callback !== 'function') {
    throw new Error('callback is required')
  }
}

module.exports = {
  RsaPublicKey,
  RsaPrivateKey,
  unmarshalRsaPublicKey,
  unmarshalRsaPrivateKey,
  generateKeyPair
}
