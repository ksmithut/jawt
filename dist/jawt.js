import * as jwt from './lib/jwt.js';
import { attachStandardClaims, verifyStandardClaims } from './lib/jwt.standard-claims.js';
import { isKeyStore } from './key-store.js';
/** @typedef {import('./lib/jwt.standard-claims.js').AttachStandardClaimsParams} AttachStandardClaimsParams */
/** @typedef {import('./lib/jwt.standard-claims.js').VerifyStandardClaimsParams} VerifyStandardClaimsParams */
/** @typedef {import('./lib/jwt.standard-claims.js').PayloadWithStandardClaims} PayloadWithStandardClaims */
/** @typedef {import('./lib/jwt.js').JWTPayload} JWTPayload */
/** @typedef {import('./lib/jwt.js').JWTHeader} JWTHeader */
/**
 * @param {JWTPayload} payload
 * @param {import('./key-store.js').KeyStore} keyStore
 * @param {AttachStandardClaimsParams} [options]
 */
export async function sign(payload, keyStore, options) {
    if (!isKeyStore(keyStore))
        throw new TypeError('Invalid KeyStore');
    const claims = attachStandardClaims(payload, options);
    const key = keyStore.primaryKey();
    const header = { alg: key.alg(), typ: 'JWT', kid: key.kid() };
    return jwt.signJWT(header, claims, key.signingKey());
}
/**
 * @param {string} token
 * @param {import('./key-store').KeyStore} keyStore
 * @param {VerifyStandardClaimsParams} [options]
 * @returns {Promise<{ payload: PayloadWithStandardClaims, header: JWTHeader }>}
 */
export async function verify(token, keyStore, options) {
    if (!isKeyStore(keyStore))
        throw new TypeError('Invalid KeyStore');
    const [payload, header] = await jwt.verifyJWT(token, 
    /**
     * @param {import('./lib/jwt.js').JWTHeader} header
     * @returns {Generator<[string, CryptoKey], void, void>}
     */
    function* getKeys(header) {
        const key = keyStore.get(header.kid);
        if (key) {
            const alg = key.alg();
            if (alg === header.alg)
                yield [alg, key.verifyingKey()];
            return;
        }
        for (const key of keyStore.keys()) {
            const alg = key.alg();
            if (alg !== header.alg)
                continue;
            yield [alg, key.verifyingKey()];
        }
    });
    return { payload: verifyStandardClaims(payload, options), header };
}
/**
 * @typedef {object} VerifyResultSuccess
 * @property {true} success
 * @property {PayloadWithStandardClaims} payload
 * @property {JWTHeader} header
 */
/**
 * @typedef {object} VerifyResultError
 * @property {false} success
 * @property {import('./lib/jwt.errors.js').JsonWebTokenError|unknown} error
 */
/**
 * @param {string} token
 * @param {import('./key-store').KeyStore} keyStore
 * @param {VerifyStandardClaimsParams} [options]
 * @returns {Promise<VerifyResultSuccess | VerifyResultError>}
 */
export async function verifySafe(token, keyStore, options) {
    try {
        const result = await verify(token, keyStore, options);
        return { success: true, payload: result.payload, header: result.header };
    }
    catch (error) {
        return { success: false, error };
    }
}
//# sourceMappingURL=jawt.js.map