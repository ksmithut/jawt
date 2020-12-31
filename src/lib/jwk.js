import webcrypto from './webcrypto.js'
import { stringToArrayBuffer, base64urlEncode } from './utils/encoding.js'
import { UnsupportedKeyType } from './errors.js'

// TODO we probably need to add x5t and x5c: https://redthunder.blog/2017/06/08/jwts-jwks-kids-x5ts-oh-my/
// https://tools.ietf.org/html/rfc7515#page-12

/**
 * @param {CryptoKey} cryptoKey
 */
export async function cryptoKeyToJWK (cryptoKey) {
  const jwk = await webcrypto.subtle.exportKey('jwk', cryptoKey)
  delete jwk.ext
  return jwk
}

/**
 * @param {JsonWebKey} jwk
 * @param {KeyAlgorithm} algorithm
 */
export async function jwkToCryptoKey (jwk, algorithm) {
  return webcrypto.subtle.importKey('jwk', jwk, algorithm, true, keyOps(jwk))
}

/**
 * @param {JsonWebKey} jwk
 */
export function privateToPublic (jwk) {
  jwk = Object.assign({}, jwk)
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
export function keyOps (jwk) {
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
