/**
 * @param {CryptoKey} cryptoKey
 */
export function exportJWK(cryptoKey: CryptoKey): Promise<JsonWebKey>;
/**
 * @param {JsonWebKey} jwk
 * @param {import('./jwa.js').JWAlgorithm} algorithm
 */
export function importJWK(jwk: JsonWebKey, algorithm: import('./jwa.js').JWAlgorithm): Promise<CryptoKey>;
/**
 * @param {JsonWebKey} jwk
 * @returns {JsonWebKey}
 */
export function privateToPublic(jwk: JsonWebKey): JsonWebKey;
/**
 * @param {JsonWebKey} jwk
 */
export function generateKid(jwk: JsonWebKey): Promise<string>;
export class UnsupportedKeyType extends Error {
    /**
     * @param {string} [kty]
     */
    constructor(kty?: string | undefined);
    code: string;
}
