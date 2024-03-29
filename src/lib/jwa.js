import webcrypto from './webcrypto.node.js'

/**
 * @typedef {'HS256' | 'HS384' | 'HS512'} HSAlgorithm
 * @typedef {'RS256' | 'RS384' | 'RS512'} RSAlgorithm
 * @typedef {'PS256' | 'PS384' | 'PS512'} PSAlgorithm
 * @typedef {'ES256' | 'ES384' | 'ES512'} ESAlgorithm
 * @typedef {'EdDSA'} EdAlgorithm
 * TODO support ES256K
 * TODO support 'EdDSA' (crv: 'Ed25519' | 'Ed448')
 * @typedef {HSAlgorithm | RSAlgorithm | PSAlgorithm | ESAlgorithm | EdAlgorithm} JWAlgorithm
 *
 * @typedef {'P-256' | 'P-384' | 'P-521'} EcCurve
 * @typedef {'Ed25519' | 'Ed448'} EdCurve
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
  // 'EdDSA'
])

export function supportedAlgorithms () {
  return Array.from(SUPPORTED_ALGORITHMS)
}

/**
 * @param {unknown} alg
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
    { name: 'HMAC', hash: `SHA-${length}`, length },
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
  return webcrypto
    .subtle
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
  return webcrypto
    .subtle
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
 * @param {EcCurve} curve
 */
export async function generateES (curve) {
  return webcrypto
    .subtle
    .generateKey({ name: 'ECDSA', namedCurve: curve }, true, ['sign', 'verify'])
    .then(({ privateKey }) => privateKey)
}

/**
 * @param {EdCurve} curve
 * @returns {Promise<CryptoKey>}
 */
// TODO: EdDSA
/* c8 ignore next 8 */
export async function generateEd (curve) {
  return (webcrypto
    .subtle
    .generateKey({ name: curve }, true, ['sign', 'verify'])
    /** @ts-ignore */
    .then(({ privateKey }) => privateKey))
}

/**
 * @param {JWAlgorithm} alg
 * @param {KeyAlgorithm} algorithm
 */
export function subtleDSA (alg, algorithm) {
  switch (alg) {
    case 'HS256':
      return { hash: 'SHA-256', name: 'HMAC' }
    case 'HS384':
      return { hash: 'SHA-384', name: 'HMAC' }
    case 'HS512':
      return { hash: 'SHA-512', name: 'HMAC' }
    case 'PS256':
      return { hash: 'SHA-256', name: 'RSA-PSS', saltLength: 256 >> 3 }
    case 'PS384':
      return { hash: 'SHA-384', name: 'RSA-PSS', saltLength: 384 >> 3 }
    case 'PS512':
      return { hash: 'SHA-512', name: 'RSA-PSS', saltLength: 512 >> 3 }
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
    // TODO: EdDSA
    /* c8 ignore next 9 */
    case 'EdDSA':
      switch (algorithm.name) {
        case 'Ed25519':
          return { name: 'Ed25519' }
        case 'Ed448':
          return { name: 'Ed448' }
        default:
          throw new UnsupportedEdDSACurve(algorithm.name)
      }
    default:
      throw new UnsupportedAlgorithm(alg)
  }
}

/**
 * @param {JWAlgorithm} alg
 * @param {JsonWebKey} jwk
 * @returns
 */
export function subtleDSAFromJWK (alg, jwk) {
  switch (alg) {
    // TODO: EdDSA
    /* c8 ignore next 5 */
    case 'EdDSA':
      if (typeof jwk.crv === 'string') {
        return subtleDSA(alg, { name: jwk.crv })
      }
      throw new UnsupportedEdDSACurve('undefined')
    default:
      return subtleDSA(alg, { name: '' })
  }
}

export class InvalidModulusLength extends Error {
  constructor () {
    super('modulusLength must not be less than 2048')
    Error.captureStackTrace(this, this.constructor)
    this.name = this.constructor.name
    this.code = 'INVALID_MODULUS_LENGTH'
  }
}

export class UnsupportedAlgorithm extends Error {
  /**
   * @param {string} algorithm
   */
  constructor (algorithm) {
    super(`Unsupported algorithm: "${algorithm}"`)
    Error.captureStackTrace(this, this.constructor)
    this.name = this.constructor.name
    this.code = 'UNSUPPORTED_JWA_ALGORITHM'
    this.algorithm = algorithm
  }
}

// TODO: EdDSA
/* c8 ignore next 12 */
export class UnsupportedEdDSACurve extends Error {
  /**
   * @param {string} [curve]
   */
  constructor (curve) {
    super(`Unsupported EdDSA curve: "${curve}"`)
    Error.captureStackTrace(this, this.constructor)
    this.name = this.constructor.name
    this.code = 'UNSUPPORTED_EDDSA_CURVE'
    this.curve = curve
  }
}
