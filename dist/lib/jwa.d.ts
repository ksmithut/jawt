export function supportedAlgorithms(): JWAlgorithm[];
/**
 * @param {unknown} alg
 * @return {alg is JWAlgorithm}
 */
export function isAlgorithm(alg: unknown): alg is JWAlgorithm;
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
    modulusLength?: number | undefined;
}): Promise<CryptoKey>;
/**
 * @param {256 | 384 | 512} length
 * @param {object} options
 * @param {number} [options.modulusLength]
 */
export function generateRS(length: 256 | 384 | 512, options: {
    modulusLength?: number | undefined;
}): Promise<CryptoKey>;
/**
 * @param {'P-256'|'P-384'|'P-521'} curve
 */
export function generateES(curve: 'P-256' | 'P-384' | 'P-521'): Promise<CryptoKey>;
/**
 * @param {JWAlgorithm} alg
 */
export function subtleDSA(alg: JWAlgorithm): {
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
export class InvalidModulusLength extends Error {
    constructor();
    code: string;
}
export class UnsupportedAlgorithm extends Error {
    /**
     * @param {string} algorithm
     */
    constructor(algorithm: string);
    code: string;
    algorithm: string;
}
export type HSAlgorithm = 'HS256' | 'HS384' | 'HS512';
export type RSAlgorithm = 'RS256' | 'RS384' | 'RS512';
export type PSAlgorithm = 'PS256' | 'PS384' | 'PS512';
/**
 * TODO support ES256K
 * TODO support 'EdDSA' (crv: 'Ed25519' | 'Ed448')
 */
export type ESAlgorithm = 'ES256' | 'ES384' | 'ES512';
export type JWAlgorithm = HSAlgorithm | RSAlgorithm | PSAlgorithm | ESAlgorithm;
