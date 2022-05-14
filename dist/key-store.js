import { createKeyFromJWK, isKey } from './key.js';
/** @typedef {ReturnType<createKeyStore>} KeyStore */
/**
 * @param {unknown} keys
 * @returns {key is import('./key.js').Key[]}
 */
function isKeyArray(keys) {
    if (!Array.isArray(keys))
        return false;
    return keys.every(key => isKey(key));
}
const keyStoreSet = new WeakSet();
/**
 * @param {unknown} keyStore
 * @returns {keyStore is KeyStore}
 */
export function isKeyStore(keyStore) {
    // @ts-ignore
    return keyStoreSet.has(keyStore);
}
/**
 * @param {import('./key.js').Key[]} keys
 */
export function createKeyStore(keys) {
    if (!isKeyArray(keys))
        throw new TypeError('keys must be an array of Keys');
    keys = keys.slice();
    if (keys.length === 0) {
        throw new RangeError('KeyStore must have at least 1 key');
    }
    const keysByKid = new Map(keys.map(key => [key.kid(), key]));
    const keyStore = Object.freeze({
        primaryKey() {
            return keys[0];
        },
        /**
         * @param {string} [kid]
         */
        get(kid) {
            // @ts-ignore
            return keysByKid.get(kid) ?? null;
        },
        *keys() {
            for (const key of keys)
                yield key;
        },
        privateJWKS() {
            return { keys: keys.map(key => key.privateJWK()) };
        },
        publicJWKS() {
            return { keys: keys.map(key => key.publicJWK()) };
        }
    });
    keyStoreSet.add(keyStore);
    return keyStore;
}
/**
 * @param {{ keys: (JsonWebKey & { kid?: string, alg: string })[] }} jwks
 */
export async function createKeyStoreFromJWKS(jwks) {
    return createKeyStore(await Promise.all(jwks.keys.map(key => createKeyFromJWK(key))));
}
//# sourceMappingURL=key-store.js.map