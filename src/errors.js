exports.ERR_MISSING_WEB_CRYPTO = () => Object.assign(
  new Error(
    'Missing Web Crypto API. ' +
    'The most likely cause of this error is that this page is being accessed ' +
    'from an insecure context (i.e. not HTTPS). For more information and ' +
    'possible resolutions see ' +
    'https://github.com/libp2p/js-libp2p-crypto/blob/master/README.md#web-crypto-api'
  ),
  { code: 'ERR_MISSING_WEB_CRYPTO' }
)
