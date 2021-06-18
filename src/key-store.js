import { createKeyFromJWK, isKey } from './key.js'

/**
 * @typedef {import('./key').Key} Key
 */

/**
 * @typedef {object} KeyStore
 * @property {() => import('./key').Key} primaryKey
 * @property {(kid?: string) => import('./key').Key?} get
 * @property {() => import('./key').Key[]} keys
 * @property {(priv?: boolean) => { keys: JsonWebKey[] }} jwks
 */

/**
 * @param {Key[]} keys
 * @returns {keys is Key[]}
 */
function isArrayOfKeys (keys) {
  if (!Array.isArray(keys)) return false
  return keys.every(key => isKey(key))
}

const keyStoreSet = new WeakSet()

/**
 * @param {KeyStore} keyStore
 * @returns {keyStore is KeyStore}
 */
export function isKeyStore (keyStore) {
  return keyStoreSet.has(keyStore)
}

/**
 * @param {import('./key').Key[]} keys
 * @returns {KeyStore}
 */
export function createKeyStore (keys) {
  if (!isArrayOfKeys(keys)) throw new TypeError('keys must be an array of keys')
  keys = keys.slice()
  if (keys.length === 0) {
    throw new ReferenceError('Key store must have at lest 1 key')
  }
  const keysByKid = new Map(keys.map(key => [key.kid, key]))
  /** @type {KeyStore} */
  const keyStore = Object.freeze({
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
  })
  keyStoreSet.add(keyStore)
  return keyStore
}

/**
 * @param {{ keys: JsonWebKey[] }} jwks
 */
export async function createKeyStoreFromJWKS (jwks) {
  return createKeyStore(
    await Promise.all(jwks.keys.map(key => createKeyFromJWK(key)))
  )
}
