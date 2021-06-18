/**
 * @param {Key} key
 * @returns {key is Key}
 */
export function isKey(key: Key): key is Key;
/**
 * @param {CryptoKey} cryptoKey
 * @param {object} options
 * @param {import('./lib/jwa').JWAlgorithm} options.alg
 * @param {string} [options.kid]
 * @returns {Promise<Key>}
 */
export function createKeyfromCryptoKey(cryptoKey: CryptoKey, options: {
    alg: import('./lib/jwa').JWAlgorithm;
    kid?: string | undefined;
}): Promise<Key>;
/**
 * @param {JsonWebKey & { kid?: string }} jwk
 */
export function createKeyFromJWK(jwk: JsonWebKey & {
    kid?: string;
}): Promise<Key>;
export type Key = {
    kid: string;
    alg: import('./lib/jwa').JWAlgorithm;
    jwk: (priv?: boolean | undefined) => JsonWebKey & {
        kid: string;
    };
    signingKey: () => Promise<ArrayBuffer | null>;
    verifyingKey: () => Promise<ArrayBuffer | null>;
    sign: (data: ArrayBuffer) => Promise<ArrayBuffer>;
    verify: (data: ArrayBuffer, signature: ArrayBuffer) => Promise<boolean>;
};
