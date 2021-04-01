/**
 * @typedef {object} SignOptions
 * @property {Date} [now] Date to use for all clock calculations
 * @property {string} [issuer] identifies the principal that issued the JWT
 * @property {string} [subject] identifies the principal that is the subject of the JWT
 * @property {string|string[]} [audience] identifies the recipients that the JWT is intended for
 * @property {Date|number} [expiresAt]
 * @property {number} [expiresIn]
 * @property {Date|number} [notBefore] identifies the time before which the JWT MUST NOT be accepted for processing
 * @property {boolean|Date|number} [issuedAt=true] identifies the time at which the JWT was issued
 * @property {string} [jwtId] provides a unique identifier for the JWT
 */
/**
 * @param {{[key: string]: any}} payload
 * @param {import('./key-store').KeyStore} keyStore
 * @param {SignOptions} [options]
 */
export function sign(payload: {
    [key: string]: any;
}, keyStore: import('./key-store').KeyStore, { now, issuer, subject, audience, expiresAt, expiresIn, notBefore, issuedAt, jwtId }?: SignOptions | undefined): Promise<string>;
/**
 * @typedef {object} VerifyOptions
 * @property {Date} [now] Date to use for all clock calculations
 * @property {string|string[]} [issuer]
 * @property {string} [subject]
 * @property {string|RegExp|(string|RegExp)[]} [audience]
 * @property {string} [jwtId]
 * @property {number} [clockTolerance]
 * @property {number} [maxAge]
 */
/**
 * @param {string} token
 * @param {import('./key-store').KeyStore} keyStore
 * @param {VerifyOptions} [options]
 */
export function verify(token: string, keyStore: import('./key-store').KeyStore, { now, issuer, subject, audience, jwtId, clockTolerance, maxAge }?: VerifyOptions | undefined): Promise<{
    [key: string]: unknown;
}>;
export type SignOptions = {
    /**
     * Date to use for all clock calculations
     */
    now?: Date | undefined;
    /**
     * identifies the principal that issued the JWT
     */
    issuer?: string | undefined;
    /**
     * identifies the principal that is the subject of the JWT
     */
    subject?: string | undefined;
    /**
     * identifies the recipients that the JWT is intended for
     */
    audience?: string | string[] | undefined;
    expiresAt?: number | Date | undefined;
    expiresIn?: number | undefined;
    /**
     * identifies the time before which the JWT MUST NOT be accepted for processing
     */
    notBefore?: number | Date | undefined;
    /**
     * identifies the time at which the JWT was issued
     */
    issuedAt?: number | boolean | Date | undefined;
    /**
     * provides a unique identifier for the JWT
     */
    jwtId?: string | undefined;
};
export type VerifyOptions = {
    /**
     * Date to use for all clock calculations
     */
    now?: Date | undefined;
    issuer?: string | string[] | undefined;
    subject?: string | undefined;
    audience?: string | RegExp | (string | RegExp)[] | undefined;
    jwtId?: string | undefined;
    clockTolerance?: number | undefined;
    maxAge?: number | undefined;
};
