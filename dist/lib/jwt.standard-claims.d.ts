/**
 * @param {import('./jwt.js').JWTPayload} claims
 * @returns {PayloadWithStandardClaims}
 */
export function assertStandardClaims(claims: import('./jwt.js').JWTPayload): PayloadWithStandardClaims;
/**
 * @typedef {object} AttachStandardClaimsParams
 * @property {Date} [clock = new Date()] Date to use for all clock calculations
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
 * @param {import('./jwt.js').JWTPayload} payload
 * @param {AttachStandardClaimsParams} [params]
 * @returns {PayloadWithStandardClaims}
 */
export function attachStandardClaims(payload: import('./jwt.js').JWTPayload, { clock, issuer, subject, audience, expiresAt, expiresIn, notBefore, issuedAt, jwtId }?: AttachStandardClaimsParams | undefined): PayloadWithStandardClaims;
/**
 * @typedef {object} VerifyStandardClaimsParams
 * @property {Date} [clock = new Date()] Date to use for all clock calculations
 * @property {number} [clockTolerance = 0]
 * @property {number} [maxAge = Infinity]
 * @property {string|string[]} [issuer]
 * @property {string} [subject]
 * @property {string|RegExp|(string|RegExp)[]} [audience]
 * @property {string} [jwtId]
 */
/**
 * @param {import('./jwt.js').JWTPayload} payload
 * @param {VerifyStandardClaimsParams} [params]
 */
export function verifyStandardClaims(payload: import('./jwt.js').JWTPayload, { clock, clockTolerance, maxAge, issuer, subject, audience, jwtId }?: VerifyStandardClaimsParams | undefined): PayloadWithStandardClaims;
export class TokenExpired extends JsonWebTokenError {
    /**
     * @param {Date} expiredAt
     */
    constructor(expiredAt: Date);
    expiredAt: Date;
}
export class NotBefore extends JsonWebTokenError {
    /**
     * @param {Date} date
     */
    constructor(date: Date);
    date: Date;
}
export type AttachStandardClaimsParams = {
    /**
     * Date to use for all clock calculations
     */
    clock?: Date | undefined;
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
export type VerifyStandardClaimsParams = {
    /**
     * Date to use for all clock calculations
     */
    clock?: Date | undefined;
    clockTolerance?: number | undefined;
    maxAge?: number | undefined;
    issuer?: string | string[] | undefined;
    subject?: string | undefined;
    audience?: string | RegExp | (string | RegExp)[] | undefined;
    jwtId?: string | undefined;
};
export type StandardClaims = {
    iss?: string | undefined;
    sub?: string | undefined;
    aud?: string | string[] | undefined;
    exp?: number | undefined;
    nbf?: number | undefined;
    iat?: number | undefined;
    jti?: string | undefined;
};
export type PayloadWithStandardClaims = StandardClaims & import('./jwt.js').JWTPayload;
import { JsonWebTokenError } from "./jwt.errors.js";
