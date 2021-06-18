import { createKeyfromCryptoKey } from './key.js'
import { generateES, generateRS, generateHS, generatePS } from './lib/jwa.js'
import { UnsupportedAlgorithm } from './lib/errors.js'

/**
 * @typedef {(alg: import('./lib/jwa').HSAlgorithm, options?: undefined) => Promise<import('./key').Key>} GenerateHS
 * @typedef {(alg: import('./lib/jwa').RSAlgorithm, options?: { modulusLength?: number }) => Promise<import('./key').Key>} GenerateRS
 * @typedef {(alg: import('./lib/jwa').PSAlgorithm, options?: { modulusLength?: number }) => Promise<import('./key').Key>} GeneratePS
 * @typedef {(alg: import('./lib/jwa').ESAlgorithm, options?: undefined) => Promise<import('./key').Key>} GenerateES
 *
 * @typedef {GenerateHS & GenerateRS & GeneratePS & GenerateES} Generate
 */

/** @type {Generate} */
// @ts-ignore
export const generate = async function generate (
  /** @type {string} */ alg,
  /** @type {{ modulusLength?: number } | undefined} */ options
) {
  switch (alg) {
    case 'HS256':
      return generateHS(256).then(key => createKeyfromCryptoKey(key, { alg }))
    case 'HS384':
      return generateHS(384).then(key => createKeyfromCryptoKey(key, { alg }))
    case 'HS512':
      return generateHS(512).then(key => createKeyfromCryptoKey(key, { alg }))
    case 'PS256':
      return generatePS(256, { modulusLength: options?.modulusLength }).then(
        key => createKeyfromCryptoKey(key, { alg })
      )
    case 'PS384':
      return generatePS(384, { modulusLength: options?.modulusLength }).then(
        key => createKeyfromCryptoKey(key, { alg })
      )
    case 'PS512':
      return generatePS(512, { modulusLength: options?.modulusLength }).then(
        key => createKeyfromCryptoKey(key, { alg })
      )
    case 'RS256':
      return generateRS(256, { modulusLength: options?.modulusLength }).then(
        key => createKeyfromCryptoKey(key, { alg })
      )
    case 'RS384':
      return generateRS(384, { modulusLength: options?.modulusLength }).then(
        key => createKeyfromCryptoKey(key, { alg })
      )
    case 'RS512':
      return generateRS(512, { modulusLength: options?.modulusLength }).then(
        key => createKeyfromCryptoKey(key, { alg })
      )
    case 'ES256':
      return generateES('P-256').then(key =>
        createKeyfromCryptoKey(key, { alg })
      )
    case 'ES384':
      return generateES('P-384').then(key =>
        createKeyfromCryptoKey(key, { alg })
      )
    case 'ES512':
      return generateES('P-521').then(key =>
        createKeyfromCryptoKey(key, { alg })
      ) // yes 521
    case 'ES256K':
    case 'EdDSA':
    default:
      throw new UnsupportedAlgorithm(alg)
  }
}
