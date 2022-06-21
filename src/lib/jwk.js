import webcrypto from './webcrypto.node.js'
import { subtleDSA } from './jwa.js'
import { stringToArrayBuffer } from './utils.js'
import { base64urlEncode } from './base64.node.js'

/**
 * @param {CryptoKey} cryptoKey
 */
export async function exportJWK (cryptoKey) {
  const jwk = await webcrypto.subtle.exportKey('jwk', cryptoKey)
  delete jwk.ext
  return jwk
}

/**
 * @param {JsonWebKey} jwk
 * @param {import('./jwa.js').JWAlgorithm} algorithm
 */
export async function importJWK (jwk, algorithm) {
  return webcrypto.subtle.importKey(
    'jwk',
    jwk,
    subtleDSA(algorithm, jwk.kty === 'OKP' ? { name: jwk.crv } : {}),
    true,
    keyOps(jwk)
  )
}

/**
 * @param {JsonWebKey} jwk
 * @returns {JsonWebKey}
 */
export function privateToPublic (jwk) {
  switch (jwk.kty) {
    case 'oct':
      return { key_ops: [], kty: jwk.kty, alg: jwk.alg }
    case 'RSA':
      return {
        key_ops: ['verify'],
        kty: jwk.kty,
        n: jwk.n,
        e: jwk.e,
        alg: jwk.alg
      }
    case 'OKP':
      return {
        key_ops: ['verify'],
        crv: 'Ed25519',
        x: jwk.x,
        kty: jwk.kty,
        alg: jwk.alg
      }
    case 'EC':
      return {
        key_ops: ['verify'],
        kty: jwk.kty,
        x: jwk.x,
        y: jwk.y,
        crv: jwk.crv,
        alg: jwk.alg
      }
    /* c8 ignore next 2 */
    default:
      throw new UnsupportedKeyType(jwk.kty)
  }
}

/**
 * @param {JsonWebKey} jwk
 * @returns {KeyUsage[]}
 */
function keyOps (jwk) {
  switch (jwk.kty) {
    case 'oct':
      return jwk.k ? ['sign', 'verify'] : []
    case 'OKP':
    case 'EC':
    case 'RSA':
      return jwk.d ? ['sign'] : ['verify']
    default:
      throw new UnsupportedKeyType(jwk.kty)
  }
}

/**
 * @param {JsonWebKey} jwk
 */
function jwkThumbprintParts (jwk) {
  // Order of the keys matter
  switch (jwk.kty) {
    case 'oct':
      return { k: jwk.k, kty: jwk.kty }
    case 'RSA':
      return { e: jwk.e, kty: jwk.kty, n: jwk.n }
    case 'EC':
      return { crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y }
    case 'OKP':
      return { crv: jwk.crv, kty: jwk.kty, x: jwk.x }
    /* c8 ignore next 2 */
    default:
      throw new UnsupportedKeyType(jwk.kty)
  }
}

/**
 * @param {JsonWebKey} jwk
 */
export async function generateKid (jwk) {
  return base64urlEncode(
    await webcrypto.subtle.digest(
      'SHA-256',
      stringToArrayBuffer(JSON.stringify(jwkThumbprintParts(jwk)))
    )
  )
}

export class UnsupportedKeyType extends Error {
  /**
   * @param {string} [kty]
   */
  constructor (kty) {
    super(`Unsupported jwk kty: "${kty}"`)
    Error.captureStackTrace(this, this.constructor)
    this.name = this.constructor.name
    this.code = 'UNSUPPORTED_JWK_KTY'
  }
}
