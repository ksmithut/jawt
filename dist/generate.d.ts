/** @typedef {import('./lib/jwa.js').JWAlgorithm} JWAlgorithm */
/**
 * @param {JWAlgorithm} alg
 * @param {object} [options]
 * @param {number} [options.modulusLength]
 */
export function generateCryptoKey(alg: JWAlgorithm, options?: {
    modulusLength?: number | undefined;
} | undefined): Promise<CryptoKey>;
export type JWAlgorithm = import('./lib/jwa.js').JWAlgorithm;
/**
 * @param {JWAlgorithm} alg
 * @param {object} [options]
 * @param {number} [options.modulusLength]
 */
export function generate(alg: JWAlgorithm, options?: {
    modulusLength?: number | undefined;
} | undefined): Promise<Readonly<{
    kid(): string;
    alg(): import("./lib/jwa.js").JWAlgorithm;
    privateJWK(): JsonWebKey & {
        kid: string;
        alg: string;
    };
    publicJWK(): JsonWebKey & {
        kid: string;
        alg: string;
    };
    signingKey(): CryptoKey;
    verifyingKey(): CryptoKey;
    signingKeyRaw(): Promise<ArrayBuffer>;
    verifyingKeyRaw(): Promise<ArrayBuffer>;
}>>;
