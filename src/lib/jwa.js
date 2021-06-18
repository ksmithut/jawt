import webcrypto from '#webcrypto'
import { InvalidModulusLength, UnsupportedAlgorithm } from './errors.js'

/**
 * @typedef {'HS256' | 'HS384' | 'HS512'} HSAlgorithm
 * @typedef {'RS256' | 'RS384' | 'RS512'} RSAlgorithm
 * @typedef {'PS256' | 'PS384' | 'PS512'} PSAlgorithm
 * @typedef {'ES256' | 'ES384' | 'ES512'} ESAlgorithm
 * TODO support 'ES256K'
 * TODO {'EdDSA'} EdDSAAlgorithm
 * TODO {'Ed25519' | 'Ed448'} EdDSACurve
 *
 * @typedef {HSAlgorithm | RSAlgorithm | PSAlgorithm | ESAlgorithm} JWAlgorithm
 */

/** @type {Set<JWAlgorithm>} */
const SUPPORTED_ALGORITHMS = new Set([
  'HS256',
  'HS384',
  'HS512',
  'RS256',
  'RS384',
  'RS512',
  'PS256',
  'PS384',
  'PS512',
  'ES256',
  'ES384',
  'ES512'
])

/**
 * @param {string} alg
 * @return {alg is JWAlgorithm}
 */
export function isAlgorithm (alg) {
  // @ts-ignore
  return SUPPORTED_ALGORITHMS.has(alg)
}

/**
 * @param {number} [modulusLength=2048]
 */
function getModulusLength (modulusLength = 2048) {
  if (
    typeof modulusLength !== 'number' ||
    isNaN(modulusLength) ||
    modulusLength < 2048 ||
    !Number.isFinite(modulusLength)
  ) {
    throw new InvalidModulusLength()
  }
  return modulusLength
}

/**
 * @param {256 | 384 | 512} length
 */
export async function generateHS (length) {
  return webcrypto.subtle.generateKey(
    {
      name: 'HMAC',
      hash: `SHA-${length}`,
      length
    },
    true,
    ['sign', 'verify']
  )
}

/**
 * @param {256 | 384 | 512} length
 * @param {object} options
 * @param {number} [options.modulusLength]
 */
export async function generatePS (length, options) {
  return webcrypto.subtle
    .generateKey(
      {
        name: 'RSA-PSS',
        hash: `SHA-${length}`,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        modulusLength: getModulusLength(options.modulusLength)
      },
      true,
      ['sign', 'verify']
    )
    .then(({ privateKey }) => privateKey)
}

/**
 * @param {256 | 384 | 512} length
 * @param {object} options
 * @param {number} [options.modulusLength]
 */
export async function generateRS (length, options) {
  return webcrypto.subtle
    .generateKey(
      {
        name: 'RSASSA-PKCS1-v1_5',
        hash: `SHA-${length}`,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        modulusLength: getModulusLength(options?.modulusLength)
      },
      true,
      ['sign', 'verify']
    )
    .then(({ privateKey }) => privateKey)
}

/**
 * @param {string} curve
 */
export async function generateES (curve) {
  return webcrypto.subtle
    .generateKey({ name: 'ECDSA', namedCurve: curve }, true, ['sign', 'verify'])
    .then(({ privateKey }) => privateKey)
}

/**
 * @param {string} alg
 */
export function subtleDSA (alg) {
  switch (alg) {
    case 'HS256':
      return { hash: 'SHA-256', name: 'HMAC' }
    case 'HS384':
      return { hash: 'SHA-384', name: 'HMAC' }
    case 'HS512':
      return { hash: 'SHA-512', name: 'HMAC' }
    case 'PS256':
      return {
        hash: 'SHA-256',
        name: 'RSA-PSS',
        saltLength: 256 >> 3
      }
    case 'PS384':
      return {
        hash: 'SHA-384',
        name: 'RSA-PSS',
        saltLength: 384 >> 3
      }
    case 'PS512':
      return {
        hash: 'SHA-512',
        name: 'RSA-PSS',
        saltLength: 512 >> 3
      }
    case 'RS256':
      return { hash: 'SHA-256', name: 'RSASSA-PKCS1-v1_5' }
    case 'RS384':
      return { hash: 'SHA-384', name: 'RSASSA-PKCS1-v1_5' }
    case 'RS512':
      return { hash: 'SHA-512', name: 'RSASSA-PKCS1-v1_5' }
    case 'ES256':
      return { hash: 'SHA-256', name: 'ECDSA', namedCurve: 'P-256' }
    case 'ES384':
      return { hash: 'SHA-384', name: 'ECDSA', namedCurve: 'P-384' }
    case 'ES512':
      return { hash: 'SHA-512', name: 'ECDSA', namedCurve: 'P-521' }
    /* istanbul ignore next */
    default:
      throw new UnsupportedAlgorithm(alg)
  }
}
