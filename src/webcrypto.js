/* eslint-env browser */

'use strict'

// Check native crypto exists and is enabled (In insecure context `self.crypto`
// exists but `self.crypto.subtle` does not). Fallback to custom Web Crypto API
// compatible implementation at `self.__crypto` if no native.
exports.get = (win = self) => {
  const nativeCrypto = win.crypto || win.msCrypto
  return nativeCrypto && nativeCrypto.subtle ? nativeCrypto : win.__crypto
}
