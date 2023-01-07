import { pbkdf2 as pbkdf2Sync } from '@noble/hashes/pbkdf2'
import { sha256 } from '@noble/hashes/sha256'
import { sha512 } from '@noble/hashes/sha512'
import errcode from 'err-code'
import { base64 } from 'multiformats/bases/base64'

/**
 * Maps an IPFS hash name to its node-forge equivalent.
 *
 * See https://github.com/multiformats/multihash/blob/master/hashtable.csv
 *
 * @private
 */
const hashName = {
  'sha2-256': sha256,
  'sha2-512': sha512
}

/**
 * Computes the Password-Based Key Derivation Function 2.
 */
export default function pbkdf2 (password: string, salt: string, iterations: number, keySize: number, hash: string): string {
  if (hash !== 'sha2-256' && hash !== 'sha2-512') {
    const types = Object.keys(hashName).join(' / ')
    throw errcode(new Error(`Hash '${hash}' is unknown or not supported. Must be ${types}`), 'ERR_UNSUPPORTED_HASH_TYPE')
  }

  const hasher = hashName[hash]
  const dek = pbkdf2Sync(
    hasher,
    password,
    salt, {
      c: iterations,
      dkLen: keySize
    }
  )

  return base64.encode(dek).substring(1)
}
