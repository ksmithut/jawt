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
export function sign(payload: JWTPayload, keyStore: import('./key-store.js').KeyStore, options?: import("./lib/jwt.standard-claims.js").AttachStandardClaimsParams | undefined): Promise<string>;
/**
 * @param {string} token
 * @param {import('./key-store').KeyStore} keyStore
 * @param {VerifyStandardClaimsParams} [options]
 * @returns {Promise<{ payload: PayloadWithStandardClaims, header: JWTHeader }>}
 */
export function verify(token: string, keyStore: import('./key-store').KeyStore, options?: import("./lib/jwt.standard-claims.js").VerifyStandardClaimsParams | undefined): Promise<{
    payload: PayloadWithStandardClaims;
    header: JWTHeader;
}>;
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
export function verifySafe(token: string, keyStore: import('./key-store').KeyStore, options?: import("./lib/jwt.standard-claims.js").VerifyStandardClaimsParams | undefined): Promise<VerifyResultSuccess | VerifyResultError>;
export type AttachStandardClaimsParams = import('./lib/jwt.standard-claims.js').AttachStandardClaimsParams;
export type VerifyStandardClaimsParams = import('./lib/jwt.standard-claims.js').VerifyStandardClaimsParams;
export type PayloadWithStandardClaims = import('./lib/jwt.standard-claims.js').PayloadWithStandardClaims;
export type JWTPayload = import('./lib/jwt.js').JWTPayload;
export type JWTHeader = import('./lib/jwt.js').JWTHeader;
export type VerifyResultSuccess = {
    success: true;
    payload: PayloadWithStandardClaims;
    header: JWTHeader;
};
export type VerifyResultError = {
    success: false;
    error: import('./lib/jwt.errors.js').JsonWebTokenError | unknown;
};
