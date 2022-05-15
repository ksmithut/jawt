/**
 * @param {unknown} value
 * @returns {value is Key}
 */
export function isKey(value: unknown): value is Readonly<{
    kid(): string;
    alg(): import("./lib/jwa.js").JWAlgorithm;
    /**
     * @returns {JsonWebKey & { kid: string, alg: string }}
     */
    privateJWK(): JsonWebKey & {
        kid: string;
        alg: string;
    };
    /**
     * @returns {JsonWebKey & { kid: string, alg: string }}
     */
    publicJWK(): JsonWebKey & {
        kid: string;
        alg: string;
    };
    signingKey(): CryptoKey;
    verifyingKey(): CryptoKey;
    signingKeyRaw(): Promise<ArrayBuffer>;
    verifyingKeyRaw(): Promise<ArrayBuffer>;
}>;
/**
 * @param {CryptoKey} cryptoKey
 * @param {object} options
 * @param {import('./lib/jwa').JWAlgorithm} options.alg
 * @param {string} [options.kid]
 */
export function createKeyFromCryptoKey(cryptoKey: CryptoKey, options: {
    alg: import('./lib/jwa').JWAlgorithm;
    kid?: string | undefined;
}): Promise<Readonly<{
    kid(): string;
    alg(): import("./lib/jwa.js").JWAlgorithm;
    /**
     * @returns {JsonWebKey & { kid: string, alg: string }}
     */
    privateJWK(): JsonWebKey & {
        kid: string;
        alg: string;
    };
    /**
     * @returns {JsonWebKey & { kid: string, alg: string }}
     */
    publicJWK(): JsonWebKey & {
        kid: string;
        alg: string;
    };
    signingKey(): CryptoKey;
    verifyingKey(): CryptoKey;
    signingKeyRaw(): Promise<ArrayBuffer>;
    verifyingKeyRaw(): Promise<ArrayBuffer>;
}>>;
/**
 * @param {JsonWebKey & { kid?: string, alg: string }} jwk
 */
export function createKeyFromJWK(jwk: JsonWebKey & {
    kid?: string | undefined;
    alg: string;
}): Promise<Readonly<{
    kid(): string;
    alg(): import("./lib/jwa.js").JWAlgorithm;
    /**
     * @returns {JsonWebKey & { kid: string, alg: string }}
     */
    privateJWK(): JsonWebKey & {
        kid: string;
        alg: string;
    };
    /**
     * @returns {JsonWebKey & { kid: string, alg: string }}
     */
    publicJWK(): JsonWebKey & {
        kid: string;
        alg: string;
    };
    signingKey(): CryptoKey;
    verifyingKey(): CryptoKey;
    signingKeyRaw(): Promise<ArrayBuffer>;
    verifyingKeyRaw(): Promise<ArrayBuffer>;
}>>;
export type Key = Awaited<ReturnType<typeof createKeyFromCryptoKey>>;
