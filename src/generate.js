import { createKeyFromCryptoKey } from './key.js'
import {
  generateES,
  generateHS,
  generatePS,
  generateRS,
  // generateEd,
  // UnsupportedEdDSACurve,
  UnsupportedAlgorithm
} from './lib/jwa.js'

/** @typedef {import('./lib/jwa.js').JWAlgorithm} JWAlgorithm */

/**
 * @param {JWAlgorithm} alg
 * @param {object} [options]
 * @param {number} [options.modulusLength]
 * @param {import('./lib/jwa.js').EdCurve} [options.curve]
 */
export async function generateCryptoKey (alg, options) {
  switch (alg) {
    case 'HS256':
      return generateHS(256)
    case 'HS384':
      return generateHS(384)
    case 'HS512':
      return generateHS(512)
    case 'RS256':
      return generateRS(256, { modulusLength: options?.modulusLength })
    case 'RS384':
      return generateRS(384, { modulusLength: options?.modulusLength })
    case 'RS512':
      return generateRS(512, { modulusLength: options?.modulusLength })
    case 'PS256':
      return generatePS(256, { modulusLength: options?.modulusLength })
    case 'PS384':
      return generatePS(384, { modulusLength: options?.modulusLength })
    case 'PS512':
      return generatePS(512, { modulusLength: options?.modulusLength })
    case 'ES256':
      return generateES('P-256')
    case 'ES384':
      return generateES('P-384')
    case 'ES512':
      return generateES('P-521')
    // case 'EdDSA':
    //   switch (options?.curve) {
    //     case undefined:
    //     case 'Ed25519':
    //       return generateEd('Ed25519')
    //     case 'Ed448':
    //       return generateEd('Ed448')
    //     default:
    //       throw new UnsupportedEdDSACurve(options?.curve)
    //   }
    default:
      throw new UnsupportedAlgorithm(alg)
  }
}

/**
 * @param {JWAlgorithm} alg
 * @param {object} [options]
 * @param {number} [options.modulusLength]
 */
async function generate (alg, options) {
  return generateCryptoKey(alg, options).then(cryptoKey =>
    createKeyFromCryptoKey(cryptoKey, { alg })
  )
}
export { generate }
