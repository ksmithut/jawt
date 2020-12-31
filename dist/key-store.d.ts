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
export function createKeyStore(keys: import('./key').Key[]): KeyStore;
/**
 * @param {{ keys: JsonWebKey[] }} jwks
 */
export function fromJWKS(jwks: {
    keys: JsonWebKey[];
}): Promise<KeyStore>;
export type KeyStore = {
    primaryKey: () => import('./key').Key;
    get: (kid?: string | undefined) => import('./key').Key | null;
    keys: () => import('./key').Key[];
    jwks: (priv?: boolean | undefined) => {
        keys: JsonWebKey[];
    };
};
