import webcrypto from '#webcrypto'
import { base64urlDecode, stringToArrayBuffer } from './lib/utils/encoding.js'
import {
  cryptoKeyToJWK,
  jwkToCryptoKey,
  privateToPublic,
  generateKid,
  keyOps
} from './lib/jwk.js'
import { cryptoKeyToPEM } from './lib/pem.js'
import { subtleDSA, isAlgorithm } from './lib/jwa.js'

/**
 * @typedef {object} Key
 * @property {string} kid
 * @property {import('./lib/jwa').JWAlgorithm} alg
 * @property {(priv?: boolean) => JsonWebKey & { kid: string }} jwk
 * @property {() => Promise<ArrayBuffer>} signingKey
 * @property {() => Promise<ArrayBuffer>} verifyingKey
 * @property {(data: ArrayBuffer) => Promise<ArrayBuffer>} sign
 * @property {(data: ArrayBuffer, signature: ArrayBuffer) => Promise<boolean>} verify
 */

/**
 * @param {CryptoKey} cryptoKey
 * @param {object} options
 * @param {import('./lib/jwa').JWAlgorithm} options.alg
 * @param {string} [options.kid]
 * @returns {Promise<Key>}
 */
export async function fromCryptoKey (cryptoKey, options) {
  const algorithm = options.alg
  const dsa = subtleDSA(algorithm)
  const jwk = await cryptoKeyToJWK(cryptoKey)
  const publicJWK = privateToPublic(jwk)
  /** @type {string} */
  const kid =
    options.kid ||
    (await generateKid(cryptoKey.type === 'secret' ? jwk : publicJWK))
  /** @type {CryptoKey} */
  const verifyKey =
    cryptoKey.type === 'private'
      ? await jwkToCryptoKey(publicJWK, cryptoKey.algorithm)
      : cryptoKey
  return {
    get kid () {
      return kid
    },
    get alg () {
      return algorithm
    },
    jwk (priv = false) {
      if (!priv) return { ...publicJWK, kid, alg: algorithm }
      if (cryptoKey.type === 'public') {
        throw new Error('This key is not private or secret')
      }
      return { ...jwk, kid, alg: algorithm }
    },
    async signingKey () {
      switch (cryptoKey.type) {
        case 'secret':
          if (!jwk.k) throw new Error('missing secret')
          return base64urlDecode(jwk.k)
        case 'public':
          throw new Error('Key is public')
        case 'private':
          return stringToArrayBuffer(await cryptoKeyToPEM(cryptoKey))
      }
    },
    async verifyingKey () {
      switch (cryptoKey.type) {
        case 'secret':
          if (!jwk.k) throw new Error('missing secret')
          return base64urlDecode(jwk.k)
        case 'public':
        case 'private':
          return stringToArrayBuffer(await cryptoKeyToPEM(verifyKey))
      }
    },
    async sign (data) {
      if (cryptoKey.type === 'public') {
        throw new Error('This key is not able to sign')
      }
      return await webcrypto.subtle.sign(dsa, cryptoKey, data)
    },
    async verify (data, signature) {
      return webcrypto.subtle.verify(dsa, verifyKey, signature, data)
    }
  }
}

/**
 * @param {JsonWebKey & { kid?: string }} jwk
 */
export async function fromJWK (jwk) {
  if (!jwk.alg) throw new Error('MissingAlgorithm')
  if (!isAlgorithm(jwk.alg)) throw new Error('Unsupported Algorithm')
  const key = await webcrypto.subtle.importKey(
    'jwk',
    jwk,
    subtleDSA(jwk.alg),
    true,
    keyOps(jwk)
  )
  return fromCryptoKey(key, { alg: jwk.alg, kid: jwk.kid })
}
