/** @typedef {ReturnType<subtleDSA>} DSA */
/**
 * @param {import('./jwa.js').JWAlgorithm} alg
 * @param {CryptoKey} cryptoKey
 * @param {ArrayBuffer} data
 */
export function sign(alg: import('./jwa.js').JWAlgorithm, cryptoKey: CryptoKey, data: ArrayBuffer): Promise<ArrayBuffer>;
/**
 * @param {import('./jwa.js').JWAlgorithm} alg
 * @param {CryptoKey} cryptoKey
 * @param {ArrayBuffer} signature
 * @param {ArrayBuffer} data
 */
export function verify(alg: import('./jwa.js').JWAlgorithm, cryptoKey: CryptoKey, signature: ArrayBuffer, data: ArrayBuffer): Promise<boolean>;
export class InvalidSigningKey extends Error {
    constructor();
    code: string;
}
export type DSA = ReturnType<typeof subtleDSA>;
import { subtleDSA } from "./jwa.js";
