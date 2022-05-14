import webcrypto from './webcrypto.node.js';
import { subtleDSA } from './jwa.js';
/** @typedef {ReturnType<subtleDSA>} DSA */
/**
 * @param {import('./jwa.js').JWAlgorithm} alg
 * @param {CryptoKey} cryptoKey
 * @param {ArrayBuffer} data
 */
export async function sign(alg, cryptoKey, data) {
    if (cryptoKey.type === 'public')
        throw new InvalidSigningKey();
    return webcrypto.subtle.sign(subtleDSA(alg), cryptoKey, data);
}
/**
 * @param {import('./jwa.js').JWAlgorithm} alg
 * @param {CryptoKey} cryptoKey
 * @param {ArrayBuffer} signature
 * @param {ArrayBuffer} data
 */
export async function verify(alg, cryptoKey, signature, data) {
    return webcrypto.subtle.verify(subtleDSA(alg), cryptoKey, signature, data);
}
export class InvalidSigningKey extends Error {
    constructor() {
        super('Given CryptoKey is not a signing key');
        Error.captureStackTrace(this, this.constructor);
        this.name = this.constructor.name;
        this.code = 'INVALID_SIGNING_KEY';
    }
}
//# sourceMappingURL=jws.js.map