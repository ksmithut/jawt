/**
 * @typedef {object} Key
 * @property {string} kid
 * @property {import('./lib/jwa').JWAlgorithm} alg
 * @property {(priv?: boolean) => JsonWebKey} jwk
 * @property {() => Promise<ArrayBuffer>} signingKey
 * @property {() => Promise<ArrayBuffer>} verifyingKey
 * @property {(data: ArrayBuffer) => Promise<ArrayBuffer>} sign
 * @property {(data: ArrayBuffer, signature: ArrayBuffer) => Promise<boolean>} verify
 */
/**
 * @param {CryptoKey} cryptoKey
 * @param {object} options
 * @param {import('./lib/jwa').JWAlgorithm} options.alg
 * @param {string} [options.kid]
 * @returns {Promise<Key>}
 */
export function fromCryptoKey(cryptoKey: CryptoKey, options: {
    alg: import('./lib/jwa').JWAlgorithm;
    kid?: string | undefined;
}): Promise<Key>;
/**
 * @param {JsonWebKey & { kid?: string }} jwk
 */
export function fromJWK(jwk: JsonWebKey & {
    kid?: string;
}): Promise<Key>;
export type Key = {
    kid: string;
    alg: import('./lib/jwa').JWAlgorithm;
    jwk: (priv?: boolean | undefined) => JsonWebKey;
    signingKey: () => Promise<ArrayBuffer>;
    verifyingKey: () => Promise<ArrayBuffer>;
    sign: (data: ArrayBuffer) => Promise<ArrayBuffer>;
    verify: (data: ArrayBuffer, signature: ArrayBuffer) => Promise<boolean>;
};
