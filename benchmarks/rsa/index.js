/* eslint-disable no-console */
'use strict'

const Benchmark = require('benchmark')
const { subtle } = require('crypto').webcrypto
const ursa = require('ursa-optional')
const crypto = require('crypto')
const keypair = require('keypair')

const suite = new Benchmark.Suite('rsa implementations')
const BITS = 512

suite.add('ursa-optional', async (d) => {
  const message = Buffer.from('hello world ' + Math.random())
  const keyPair = ursa.generatePrivateKey(BITS)

  const signature = crypto.createSign('RSA-SHA256')
    .update(message)
    .sign(keyPair.toPrivatePem())

  const isSigned = crypto.createVerify('RSA-SHA256')
    .update(message)
    .verify(keyPair.toPublicPem(), signature)

  if (!isSigned) {
    throw new Error('could not verify ursa-optional signature')
  }

  d.resolve()
}, { defer: true })

suite.add('keypair', async (d) => {
  const message = Buffer.from('hello world ' + Math.random())
  const keyPair = keypair(BITS)

  const signature = crypto.createSign('RSA-SHA256')
    .update(message)
    .sign(keyPair.private)

  const isSigned = crypto.createVerify('RSA-SHA256')
    .update(message)
    .verify(keyPair.public, signature)

  if (!isSigned) {
    throw new Error('could not verify keypair signature')
  }

  d.resolve()
}, { defer: true })

suite.add('node.js web-crypto', async (d) => {
  const message = Buffer.from('hello world ' + Math.random())

  const keyPair = await subtle.generateKey({
    name: 'RSASSA-PKCS1-v1_5',
    modulusLength: BITS,
    publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
    hash: { name: 'SHA-256' }
  },
  true,
  ['sign', 'verify']
  )

  const signature = await subtle.sign('RSASSA-PKCS1-v1_5', keyPair.privateKey, message)
  const isSigned = await subtle.verify('RSASSA-PKCS1-v1_5', keyPair.publicKey, signature, message)

  if (!isSigned) {
    throw new Error('could not verify node.js signature')
  }

  d.resolve()
}, { defer: true })

async function main () {
  suite
    .on('cycle', (event) => console.log(String(event.target)))
    .on('complete', function () {
      console.log('fastest is ' + this.filter('fastest').map('name'))
    })
    .run({ async: true })
}

main()
  .catch(err => {
    console.error(err)
    process.exit(1)
  })
