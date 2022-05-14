import webcrypto from './lib/webcrypto.node.js';
import { clone, stringToArrayBuffer } from './lib/utils.js';
import { cryptoKeyToPEM } from './lib/pem.js';
import { isAlgorithm, UnsupportedAlgorithm } from './lib/jwa.js';
import { exportJWK, importJWK, privateToPublic, generateKid } from './lib/jwk.js';
import { InvalidSigningKey } from './lib/jws.js';
/**
 * @typedef {Awaited<ReturnType<createKeyFromCryptoKey>>} Key
 */
const keySet = new WeakSet();
/**
 * @param {unknown} value
 * @returns {value is Key}
 */
export function isKey(value) {
    // @ts-ignore
    return keySet.has(value);
}
/**
 * @param {CryptoKey} cryptoKey
 * @param {object} options
 * @param {import('./lib/jwa').JWAlgorithm} options.alg
 * @param {string} [options.kid]
 */
export async function createKeyFromCryptoKey(cryptoKey, options) {
    const alg = options.alg;
    const jwk = await exportJWK(cryptoKey);
    const publicJWK = privateToPublic(jwk);
    const kid = options.kid ??
        (await generateKid(cryptoKey.type === 'secret' ? jwk : publicJWK));
    const verifyKey = cryptoKey.type === 'private' ? await importJWK(publicJWK, alg) : cryptoKey;
    const key = Object.freeze({
        kid() {
            return kid;
        },
        alg() {
            return alg;
        },
        /**
         * @returns {JsonWebKey & { kid: string, alg: string }}
         */
        privateJWK() {
            if (cryptoKey.type === 'public')
                throw new InvalidSigningKey();
            return { ...clone(jwk), kid, alg };
        },
        /**
         * @returns {JsonWebKey & { kid: string, alg: string }}
         */
        publicJWK() {
            return { ...clone(publicJWK), kid, alg };
        },
        signingKey() {
            if (cryptoKey.type === 'public')
                throw new InvalidSigningKey();
            return cryptoKey;
        },
        verifyingKey() {
            return verifyKey;
        },
        async signingKeyRaw() {
            switch (cryptoKey.type) {
                case 'public':
                    throw new InvalidSigningKey();
                case 'private':
                    return stringToArrayBuffer(await cryptoKeyToPEM(cryptoKey));
                case 'secret':
                    return await webcrypto.subtle.exportKey('raw', cryptoKey);
            }
        },
        async verifyingKeyRaw() {
            switch (verifyKey.type) {
                case 'public':
                case 'private':
                    return stringToArrayBuffer(await cryptoKeyToPEM(verifyKey));
                case 'secret':
                    return await webcrypto.subtle.exportKey('raw', cryptoKey);
            }
        }
    });
    keySet.add(key);
    return key;
}
/**
 * @param {JsonWebKey & { kid?: string, alg: string }} jwk
 */
export async function createKeyFromJWK(jwk) {
    const { alg, kid } = jwk;
    if (!isAlgorithm(alg))
        throw new UnsupportedAlgorithm(jwk.alg);
    const key = await importJWK(jwk, alg);
    return createKeyFromCryptoKey(key, { alg, kid });
}
//# sourceMappingURL=key.js.map