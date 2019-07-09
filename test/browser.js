/* eslint-env mocha */
'use strict'

const chai = require('chai')
const dirtyChai = require('dirty-chai')
const expect = chai.expect
chai.use(dirtyChai)
const crypto = require('../')
const webcrypto = require('../src/webcrypto')

describe('Missing web crypto', () => {
  let webcryptoGet
  let rsaPrivateKey

  before(done => {
    crypto.keys.generateKeyPair('RSA', 512, (err, key) => {
      if (err) return done(err)
      rsaPrivateKey = key
      done()
    })
  })

  before(() => {
    webcryptoGet = webcrypto.get
    webcrypto.get = () => null
  })

  after(() => {
    webcrypto.get = webcryptoGet
  })

  it('should error for hmac create when web crypto is missing', done => {
    crypto.hmac.create('SHA256', Buffer.from('secret'), err => {
      expect(err).to.exist()
      expect(err.code).to.equal('ERR_MISSING_WEB_CRYPTO')
      done()
    })
  })

  it('should error for generate ephemeral key pair when web crypto is missing', done => {
    crypto.keys.generateEphemeralKeyPair('P-256', err => {
      expect(err).to.exist()
      expect(err.code).to.equal('ERR_MISSING_WEB_CRYPTO')
      done()
    })
  })

  it('should error for generate rsa key pair when web crypto is missing', done => {
    crypto.keys.generateKeyPair('rsa', 256, err => {
      expect(err).to.exist()
      expect(err.code).to.equal('ERR_MISSING_WEB_CRYPTO')
      done()
    })
  })

  it('should error for unmarshal RSA private key when web crypto is missing', done => {
    crypto.keys.unmarshalPrivateKey(crypto.keys.marshalPrivateKey(rsaPrivateKey), err => {
      expect(err).to.exist()
      expect(err.code).to.equal('ERR_MISSING_WEB_CRYPTO')
      done()
    })
  })

  it('should error for sign RSA private key when web crypto is missing', done => {
    rsaPrivateKey.sign(Buffer.from('test'), err => {
      expect(err).to.exist()
      expect(err.code).to.equal('ERR_MISSING_WEB_CRYPTO')
      done()
    })
  })

  it('should error for verify RSA public key when web crypto is missing', done => {
    rsaPrivateKey.public.verify(Buffer.from('test'), Buffer.from('test'), err => {
      expect(err).to.exist()
      expect(err.code).to.equal('ERR_MISSING_WEB_CRYPTO')
      done()
    })
  })
})

describe('BYO web crypto', () => {
  it('should fallback to self.__crypto if self.crypto is missing', () => {
    const customCrypto = {}
    expect(webcrypto.get({ __crypto: customCrypto })).to.equal(customCrypto)
  })
})
