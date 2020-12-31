/**
 * @param {string} alg
 * @return {alg is JWAlgorithm}
 */
export function isAlgorithm(alg: string): alg is JWAlgorithm;
/**
 * @param {256 | 384 | 512} length
 */
export function generateHS(length: 256 | 384 | 512): Promise<CryptoKey>;
/**
 * @param {256 | 384 | 512} length
 * @param {object} options
 * @param {number} [options.modulusLength]
 */
export function generatePS(length: 256 | 384 | 512, options: {
    modulusLength: number | undefined;
}): Promise<CryptoKey>;
/**
 * @param {256 | 384 | 512} length
 * @param {object} options
 * @param {number} [options.modulusLength]
 */
export function generateRS(length: 256 | 384 | 512, options: {
    modulusLength: number | undefined;
}): Promise<CryptoKey>;
/**
 * @param {string} curve
 */
export function generateES(curve: string): Promise<CryptoKey>;
/**
 * @param {string} alg
 */
export function subtleDSA(alg: string): {
    hash: string;
    name: string;
    saltLength?: undefined;
    namedCurve?: undefined;
} | {
    hash: string;
    name: string;
    saltLength: number;
    namedCurve?: undefined;
} | {
    hash: string;
    name: string;
    namedCurve: string;
    saltLength?: undefined;
};
export type HSAlgorithm = "HS256" | "HS384" | "HS512";
export type RSAlgorithm = "RS256" | "RS384" | "RS512";
export type PSAlgorithm = "PS256" | "PS384" | "PS512";
/**
 * TODO support 'ES256K'
 * TODO {'EdDSA'} EdDSAAlgorithm
 * TODO {'Ed25519' | 'Ed448'} EdDSACurve
 */
export type ESAlgorithm = "ES256" | "ES384" | "ES512";
export type JWAlgorithm = "HS256" | "HS384" | "HS512" | "RS256" | "RS384" | "RS512" | "PS256" | "PS384" | "PS512" | "ES256" | "ES384" | "ES512";
