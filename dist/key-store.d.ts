/**
 * @param {KeyStore} keyStore
 * @returns {keyStore is KeyStore}
 */
export function isKeyStore(keyStore: KeyStore): keyStore is KeyStore;
/**
 * @param {import('./key').Key[]} keys
 * @returns {KeyStore}
 */
export function createKeyStore(keys: import('./key').Key[]): KeyStore;
/**
 * @param {{ keys: JsonWebKey[] }} jwks
 */
export function createKeyStoreFromJWKS(jwks: {
    keys: JsonWebKey[];
}): Promise<KeyStore>;
export type Key = import('./key').Key;
export type KeyStore = {
    primaryKey: () => import('./key').Key;
    get: (kid?: string | undefined) => import('./key').Key | null;
    keys: () => import('./key').Key[];
    jwks: (priv?: boolean | undefined) => {
        keys: JsonWebKey[];
    };
};
