/**
 * @param {{[key: string]: any}} payload
 * @param {import('./key-store').KeyStore} keyStore
 * @param {object} [options]
 * @param {Date} [options.now] Date to use for all clock calculations
 * @param {string} [options.issuer] identifies the principal that issued the JWT
 * @param {string} [options.subject] identifies the principal that is the subject of the JWT
 * @param {string|string[]} [options.audience] identifies the recipients that the JWT is intended for
 * @param {Date|number} [options.expiresAt]
 * @param {number} [options.expiresIn]
 * @param {Date|number} [options.notBefore] identifies the time before which the JWT MUST NOT be accepted for processing
 * @param {boolean|Date|number} [options.issuedAt=true] identifies the time at which the JWT was issued
 * @param {string} [options.jwtId] provides a unique identifier for the JWT
 */
export function sign(payload: {
    [key: string]: any;
}, keyStore: import('./key-store').KeyStore, { now, issuer, subject, audience, expiresAt, expiresIn, notBefore, issuedAt, jwtId }?: {
    now?: Date | undefined;
    issuer?: string | undefined;
    subject?: string | undefined;
    audience?: string | string[] | undefined;
    expiresAt?: number | Date | undefined;
    expiresIn?: number | undefined;
    notBefore?: number | Date | undefined;
    issuedAt?: number | boolean | Date | undefined;
    jwtId?: string | undefined;
} | undefined): Promise<string>;
/**
 * @param {string} token
 * @param {import('./key-store').KeyStore} keyStore
 * @param {object} [options]
 * @param {Date} [options.now] Date to use for all clock calculations
 * @param {string|string[]} [options.issuer]
 * @param {string} [options.subject]
 * @param {string|RegExp|(string|RegExp)[]} [options.audience]
 * @param {string} [options.jwtId]
 * @param {number} [options.clockTolerance]
 * @param {number} [options.maxAge]
 */
export function verify(token: string, keyStore: import('./key-store').KeyStore, { now, issuer, subject, audience, jwtId, clockTolerance, maxAge }?: {
    now?: Date | undefined;
    issuer?: string | string[] | undefined;
    subject?: string | undefined;
    audience?: string | RegExp | (string | RegExp)[] | undefined;
    jwtId?: string | undefined;
    clockTolerance?: number | undefined;
    maxAge?: number | undefined;
} | undefined): Promise<{
    [key: string]: unknown;
}>;
