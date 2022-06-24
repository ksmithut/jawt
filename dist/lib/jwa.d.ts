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
 * @param {EcCurve} curve
 */
export function generateES(curve: EcCurve): Promise<CryptoKey>;
/**
 * @param {EdCurve} curve
 * @returns {Promise<CryptoKey>}
 */
export function generateEd(curve: EdCurve): Promise<CryptoKey>;
/**
 * @param {JWAlgorithm} alg
 * @param {KeyAlgorithm} algorithm
 */
export function subtleDSA(alg: JWAlgorithm, algorithm: KeyAlgorithm): {
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
} | {
    name: string;
    hash?: undefined;
    saltLength?: undefined;
    namedCurve?: undefined;
};
/**
 * @param {JWAlgorithm} alg
 * @param {JsonWebKey} jwk
 * @returns
 */
export function subtleDSAFromJWK(alg: JWAlgorithm, jwk: JsonWebKey): {
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
} | {
    name: string;
    hash?: undefined;
    saltLength?: undefined;
    namedCurve?: undefined;
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
export class UnsupportedEdDSACurve extends Error {
    /**
     * @param {string} [curve]
     */
    constructor(curve?: string | undefined);
    code: string;
    curve: string | undefined;
}
export type HSAlgorithm = 'HS256' | 'HS384' | 'HS512';
export type RSAlgorithm = 'RS256' | 'RS384' | 'RS512';
export type PSAlgorithm = 'PS256' | 'PS384' | 'PS512';
export type ESAlgorithm = 'ES256' | 'ES384' | 'ES512';
/**
 * TODO support ES256K
 * TODO support 'EdDSA' (crv: 'Ed25519' | 'Ed448')
 */
export type EdAlgorithm = 'EdDSA';
export type JWAlgorithm = HSAlgorithm | RSAlgorithm | PSAlgorithm | ESAlgorithm | EdAlgorithm;
export type EcCurve = 'P-256' | 'P-384' | 'P-521';
export type EdCurve = 'Ed25519' | 'Ed448';
