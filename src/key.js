import webcrypto from '#webcrypto'
import { base64urlDecode, stringToArrayBuffer } from './lib/utils/encoding.js'
import { clone } from './lib/utils/clone.js'
import {
  UnsupportedAlgorithm,
  MissingAlgorithm,
  InvalidSigningKey
} from './lib/errors.js'
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
 * @property {() => Promise<ArrayBuffer | null>} signingKey
 * @property {() => Promise<ArrayBuffer | null>} verifyingKey
 * @property {(data: ArrayBuffer) => Promise<ArrayBuffer>} sign
 * @property {(data: ArrayBuffer, signature: ArrayBuffer) => Promise<boolean>} verify
 */

const keySet = new WeakSet()

/**
 * @param {Key} key
 * @returns {key is Key}
 */
export function isKey (key) {
  return keySet.has(key)
}

/**
 * @param {CryptoKey} cryptoKey
 * @param {object} options
 * @param {import('./lib/jwa').JWAlgorithm} options.alg
 * @param {string} [options.kid]
 * @returns {Promise<Key>}
 */
export async function createKeyfromCryptoKey (cryptoKey, options) {
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
  /** @type {Key} */
  const key = Object.freeze({
    get kid () {
      return kid
    },
    get alg () {
      return algorithm
    },
    jwk (priv = false) {
      if (!priv) return { ...clone(publicJWK), kid, alg: algorithm }
      if (cryptoKey.type === 'public') {
        throw new Error('This key is not private or secret')
      }
      return { ...clone(jwk), kid, alg: algorithm }
    },
    async signingKey () {
      switch (cryptoKey.type) {
        case 'secret':
          if (!jwk.k) return null
          return base64urlDecode(jwk.k)
        case 'public':
          return null
        case 'private':
          return stringToArrayBuffer(await cryptoKeyToPEM(cryptoKey))
      }
    },
    async verifyingKey () {
      switch (cryptoKey.type) {
        case 'secret':
          if (!jwk.k) return null
          return base64urlDecode(jwk.k)
        case 'public':
        case 'private':
          return stringToArrayBuffer(await cryptoKeyToPEM(verifyKey))
      }
    },
    async sign (data) {
      if (cryptoKey.type === 'public') throw new InvalidSigningKey()
      return await webcrypto.subtle.sign(dsa, cryptoKey, data)
    },
    async verify (data, signature) {
      return webcrypto.subtle.verify(dsa, verifyKey, signature, data)
    }
  })
  keySet.add(key)
  return key
}

/**
 * @param {JsonWebKey & { kid?: string }} jwk
 */
export async function createKeyFromJWK (jwk) {
  if (!jwk.alg) throw new MissingAlgorithm()
  if (!isAlgorithm(jwk.alg)) throw new UnsupportedAlgorithm(jwk.alg)
  const key = await webcrypto.subtle.importKey(
    'jwk',
    jwk,
    subtleDSA(jwk.alg),
    true,
    keyOps(jwk)
  )
  return createKeyfromCryptoKey(key, { alg: jwk.alg, kid: jwk.kid })
}
