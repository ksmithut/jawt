import webcrypto from './webcrypto.node.js'
import { subtleDSA } from './jwa.js'
import { clone, stringToArrayBuffer } from './utils.js'
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
    subtleDSA(algorithm),
    true,
    keyOps(jwk)
  )
}

/**
 * @param {JsonWebKey} jwk
 * @returns {JsonWebKey}
 */
export function privateToPublic (jwk) {
  jwk = clone(jwk)
  switch (jwk.kty) {
    case 'oct':
      delete jwk.k
      jwk.key_ops = []
      break
    case 'RSA':
      delete jwk.d
      delete jwk.p
      delete jwk.q
      delete jwk.dp
      delete jwk.dq
      delete jwk.qi
      jwk.key_ops = ['verify']
      break
    case 'EC':
      delete jwk.d
      jwk.key_ops = ['verify']
      break
    default:
      throw new UnsupportedKeyType(jwk.kty)
  }
  return jwk
}

/**
 * @param {JsonWebKey} jwk
 * @returns {KeyUsage[]}
 */
function keyOps (jwk) {
  switch (jwk.kty) {
    case 'oct':
      return jwk.k ? ['sign', 'verify'] : []
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
export async function generateKid (jwk) {
  // Order of the keys matter
  /** @type {JsonWebKey} */
  let strippedJWK
  switch (jwk.kty) {
    case 'oct':
      strippedJWK = { k: jwk.k, kty: jwk.kty }
      break
    case 'RSA':
      strippedJWK = { e: jwk.e, kty: jwk.kty, n: jwk.n }
      break
    case 'EC':
      strippedJWK = { crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y }
      break
    default:
      throw new UnsupportedKeyType(jwk.kty)
  }
  return base64urlEncode(
    await webcrypto.subtle.digest(
      'SHA-256',
      stringToArrayBuffer(JSON.stringify(strippedJWK))
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
