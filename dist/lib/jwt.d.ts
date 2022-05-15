/**
 * @param {object & { alg: import('./jwa.js').JWAlgorithm }} header
 * @param {{[key: string]: unknown}} payload
 * @param {CryptoKey} cryptoKey
 */
export function signJWT(header: object & {
    alg: import('./jwa.js').JWAlgorithm;
}, payload: {
    [key: string]: unknown;
}, cryptoKey: CryptoKey): Promise<string>;
/**
 * @typedef {{[key: string]: unknown}} JWTPayload
 * @typedef {{[key: string]: unknown, typ: 'JWT', alg: import('./jwa.js').JWAlgorithm, kid?: string }} JWTHeader
 */
/**
 * @param {string} token
 * @returns {[JWTPayload, JWTHeader, ArrayBuffer, ArrayBuffer]}
 */
export function decodeJWT(token: string): [JWTPayload, JWTHeader, ArrayBuffer, ArrayBuffer];
/**
 * @param {string} token
 * @param {(header: JWTHeader) => Generator<[string, CryptoKey], void, void>} getKeys
 * @returns {Promise<[JWTPayload, JWTHeader]>}
 */
export function verifyJWT(token: string, getKeys: (header: JWTHeader) => Generator<[string, CryptoKey], void, void>): Promise<[JWTPayload, JWTHeader]>;
export type JWTPayload = {
    [key: string]: unknown;
};
export type JWTHeader = {
    [key: string]: unknown;
    typ: 'JWT';
    alg: import('./jwa.js').JWAlgorithm;
    kid?: string | undefined;
};
