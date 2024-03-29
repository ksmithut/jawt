import { subtleDSA } from './jwa.js'
import webcrypto from './webcrypto.node.js'

/** @typedef {ReturnType<subtleDSA>} DSA */

/**
 * @param {import('./jwa.js').JWAlgorithm} alg
 * @param {CryptoKey} cryptoKey
 * @param {ArrayBuffer} data
 */
export async function sign (alg, cryptoKey, data) {
  /* c8 ignore next */
  if (cryptoKey.type === 'public') throw new InvalidSigningKey()
  return webcrypto.subtle.sign(
    subtleDSA(alg, cryptoKey.algorithm),
    cryptoKey,
    data
  )
}

/**
 * @param {import('./jwa.js').JWAlgorithm} alg
 * @param {CryptoKey} cryptoKey
 * @param {ArrayBuffer} signature
 * @param {ArrayBuffer} data
 */
export async function verify (alg, cryptoKey, signature, data) {
  return webcrypto.subtle.verify(
    subtleDSA(alg, cryptoKey.algorithm),
    cryptoKey,
    signature,
    data
  )
}

export class InvalidSigningKey extends Error {
  constructor () {
    super('Given CryptoKey is not a signing key')
    Error.captureStackTrace(this, this.constructor)
    this.name = this.constructor.name
    this.code = 'INVALID_SIGNING_KEY'
  }
}
