import { fromJWK } from './key.js'

/**
 * @typedef {object} KeyStore
 * @property {() => import('./key').Key} primaryKey
 * @property {(kid?: string) => import('./key').Key?} get
 * @property {() => import('./key').Key[]} keys
 * @property {(priv?: boolean) => { keys: JsonWebKey[] }} jwks
 */

/**
 * @param {import('./key').Key[]} keys
 * @returns {KeyStore}
 */
export function createKeyStore (keys) {
  if (!Array.isArray(keys)) throw new TypeError('keys must be an array')
  if (keys.length === 0) {
    throw new ReferenceError('Key store must have at lest 1 key')
  }
  const keysByKid = new Map(keys.map(key => [key.kid, key]))
  return {
    primaryKey () {
      return keys[0]
    },
    get (kid) {
      return keysByKid.get(kid || '') || null
    },
    keys () {
      return keys.slice()
    },
    jwks (priv = false) {
      return { keys: keys.map(key => key.jwk(priv)) }
    }
  }
}

/**
 * @param {{ keys: JsonWebKey[] }} jwks
 */
export async function fromJWKS (jwks) {
  return createKeyStore(await Promise.all(jwks.keys.map(fromJWK)))
}
