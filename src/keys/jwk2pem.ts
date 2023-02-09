import 'node-forge/lib/rsa.js'
// @ts-expect-error types are missing
import forge from 'node-forge/lib/forge.js'
import { base64urlToBigInteger } from '../util.js'

function convert (key: any, types: string[]): any {
  return types.map(t => base64urlToBigInteger(key[t]))
}

export function jwk2priv (key: JsonWebKey): { encrypt: (msg: string) => string, decrypt: (msg: string) => string } {
  return forge.pki.setRsaPrivateKey(...convert(key, ['n', 'e', 'd', 'p', 'q', 'dp', 'dq', 'qi']))
}

export function jwk2pub (key: JsonWebKey): { encrypt: (msg: string) => string, decrypt: (msg: string) => string } {
  return forge.pki.setRsaPublicKey(...convert(key, ['n', 'e']))
}
