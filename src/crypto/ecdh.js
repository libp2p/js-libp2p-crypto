'use strict'

const crypto = require('./webcrypto')()

exports.generateEphmeralKeyPair = function (curve, callback) {
  crypto.subtle.generateKey(
    {
      name: 'ECDH',
      namedCurve: curve
    },
    true,
    ['deriveBits']
  ).then((pair) => {
    // forcePrivate is used for testing only
    const genSharedKey = (theirPub, forcePrivate, cb) => {
      if (typeof forcePrivate === 'function') {
        cb = forcePrivate
        forcePrivate = undefined
      }

      const privateKey = forcePrivate || pair.privateKey
      crypto.subtle.importKey(
        'spki',
        theirPub,
        {
          name: 'ECDH',
          namedCurve: curve
        },
        false,
        []
      ).then((publicKey) => {
        return crypto.subtle.deriveBits(
          {
            name: 'ECDH',
            namedCurve: curve,
            public: publicKey
          },
          privateKey,
          256
        )
      }).then((bits) => {
        // return p.derive(pub.getPublic()).toBuffer('be')
        cb(null, Buffer.from(bits))
      }).catch((err) => {
        cb(err)
      })
    }

    return crypto.subtle.exportKey(
      'spki',
      pair.publicKey
    ).then((publicKey) => {
      return {
        key: Buffer.from(publicKey),
        genSharedKey
      }
    })
  }).then((res) => {
    callback(null, res)
  }).catch((err) => {
    callback(err)
  })
}
