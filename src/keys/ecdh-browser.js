'use strict'

const errcode = require('err-code')
const { Buffer } = require('buffer')
const webcrypto = require('../webcrypto')
const { bufferToBase64url } = require('../util')
const validateCurveType = require('./validate-curve-type')

const bits = {
  'P-256': 256,
  'P-384': 384,
  'P-521': 521
}

exports.generateEphmeralKeyPair = async function (curve) {
  validateCurveType(Object.keys(bits), curve)
  const pair = await webcrypto.get().subtle.generateKey(
    {
      name: 'ECDH',
      namedCurve: curve
    },
    true,
    ['deriveBits']
  )

  // forcePrivate is used for testing only
  const genSharedKey = async (theirPub, forcePrivate) => {
    let privateKey

    if (forcePrivate) {
      privateKey = await webcrypto.get().subtle.importKey(
        'jwk',
        unmarshalPrivateKey(curve, forcePrivate),
        {
          name: 'ECDH',
          namedCurve: curve
        },
        false,
        ['deriveBits']
      )
    } else {
      privateKey = pair.privateKey
    }

    const keys = [
      await webcrypto.get().subtle.importKey(
        'jwk',
        unmarshalPublicKey(curve, theirPub),
        {
          name: 'ECDH',
          namedCurve: curve
        },
        false,
        []
      ),
      privateKey
    ]

    return Buffer.from(await webcrypto.get().subtle.deriveBits(
      {
        name: 'ECDH',
        namedCurve: curve,
        public: keys[0]
      },
      keys[1],
      bits[curve]
    ))
  }

  const publicKey = await webcrypto.get().subtle.exportKey('jwk', pair.publicKey)

  return {
    key: marshalPublicKey(publicKey),
    genSharedKey
  }
}

const curveLengths = {
  'P-256': 32,
  'P-384': 48,
  'P-521': 66
}

const base64urlToBuffer = str => {
  str = (str + '==='.slice((str.length + 3) % 4))
    .replace(/-/g, '+')
    .replace(/_/g, '/')
  return Buffer.from(str, 'base64')
}

// Marshal converts a jwk encodec ECDH public key into the
// form specified in section 4.3.6 of ANSI X9.62. (This is the format
// go-ipfs uses)
function marshalPublicKey (jwk) {
  const byteLen = curveLengths[jwk.crv]

  return Buffer.concat([
    Buffer.from([4]), // uncompressed point
    // TODO: BN.toArrayLike(Buffer, 'be', byteLen) restricts size to passed byteLen
    // toBn(jwk.x).toArrayLike(Buffer, 'be', byteLen),
    // toBn(jwk.y).toArrayLike(Buffer, 'be', byteLen)
    base64urlToBuffer(jwk.x),
    base64urlToBuffer(jwk.y)
  ], 1 + byteLen * 2)
}

// Unmarshal converts a point, serialized by Marshal, into an jwk encoded key
function unmarshalPublicKey (curve, key) {
  const byteLen = curveLengths[curve]

  if (!key.slice(0, 1).equals(Buffer.from([4]))) {
    throw errcode(new Error('Cannot unmarshal public key - invalid key format'), 'ERR_INVALID_KEY_FORMAT')
  }

  return {
    kty: 'EC',
    crv: curve,
    x: bufferToBase64url(key.slice(1, byteLen + 1)),
    y: bufferToBase64url(key.slice(1 + byteLen)),
    ext: true
  }
}

const unmarshalPrivateKey = (curve, key) => ({
  ...unmarshalPublicKey(curve, key.public),
  d: bufferToBase64url(key.private)
})
