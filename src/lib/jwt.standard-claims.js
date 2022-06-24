import { InvalidClaim, JsonWebTokenError } from './jwt.errors.js'
import { clone, dateToTimestamp, toArray } from './utils.js'
import * as v from './validate.js'

/**
 * @typedef {object} StandardClaims
 * @property {string} [iss]
 * @property {string} [sub]
 * @property {string|string[]} [aud]
 * @property {number} [exp]
 * @property {number} [nbf]
 * @property {number} [iat]
 * @property {string} [jti]
 */

/** @typedef {StandardClaims & import('./jwt.js').JWTPayload} PayloadWithStandardClaims */

const STANDARD_CLAIM_SCHEMAS = [{
  claim: 'iss',
  isValid: v.optional(v.isString),
  message: '"iss" must be a string or undefined'
}, {
  claim: 'sub',
  isValid: v.optional(v.isString),
  message: '"sub" must be a string or undefined'
}, {
  claim: 'aud',
  isValid: v.optional(v.or(v.isString, v.isArrayOf(v.isString))),
  message: '"aud" must be a string, array of strings, or undefined'
}, {
  claim: 'exp',
  isValid: v.optional(v.isInteger),
  message: '"exp" must be an integer or undefined'
}, {
  claim: 'nbf',
  isValid: v.optional(v.isInteger),
  message: '"nbf" must be an integer or undefined'
}, {
  claim: 'iat',
  isValid: v.optional(v.isInteger),
  message: '"iat" must be an integer or undefined'
}, {
  claim: 'jti',
  isValid: v.optional(v.isString),
  message: '"jti" must be a string or undefined'
}]

/**
 * @param {import('./jwt.js').JWTPayload} claims
 * @returns {PayloadWithStandardClaims}
 */
export function assertStandardClaims (claims) {
  STANDARD_CLAIM_SCHEMAS.forEach(schema => {
    const value = claims[schema.claim]
    if (!schema.isValid(value)) {
      throw new InvalidClaim(schema.claim, schema.message, value)
    }
  })
  return claims
}

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
export function attachStandardClaims (
  payload,
  {
    clock = new Date(),
    issuer,
    subject,
    audience,
    expiresAt,
    expiresIn,
    notBefore,
    issuedAt = true,
    jwtId
  } = {}
) {
  if (!v.isPlainObject(payload)) {
    throw new TypeError('"payload" must be a plain object')
  }
  if (!v.isDate(clock)) throw new TypeError('"clock" must be a Date object')
  const now = dateToTimestamp(clock)
  const claims = clone(payload)
  if (issuer !== undefined) claims.iss = issuer
  if (subject !== undefined) claims.sub = subject
  if (audience !== undefined) claims.aud = audience
  if (expiresIn !== undefined) claims.exp = now + expiresIn
  else if (expiresAt instanceof Date) claims.exp = dateToTimestamp(expiresAt)
  else if (expiresAt !== undefined) claims.exp = expiresAt
  if (notBefore instanceof Date) claims.nbf = dateToTimestamp(notBefore)
  else if (notBefore !== undefined) claims.nbf = notBefore
  if (issuedAt === true) claims.iat = now
  else if (issuedAt instanceof Date) claims.iat = dateToTimestamp(issuedAt)
  else if (issuedAt !== undefined && issuedAt !== false) claims.iat = issuedAt
  if (jwtId !== undefined) claims.jti = jwtId
  return assertStandardClaims(claims)
}

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
export function verifyStandardClaims (
  payload,
  {
    clock = new Date(),
    clockTolerance = 0,
    maxAge = Infinity,
    issuer,
    subject,
    audience,
    jwtId
  } = {}
) {
  const now = dateToTimestamp(clock)
  const claims = assertStandardClaims(payload)
  if (claims.iat != null && now - clockTolerance - claims.iat > maxAge) {
    throw new InvalidClaim('iat', 'JWT is too old', claims.iat)
  }
  if (claims.exp != null && now - clockTolerance > claims.exp) {
    throw new TokenExpired(new Date(claims.exp * 1000))
  }
  if (claims.nbf != null && now + clockTolerance < claims.nbf) {
    throw new NotBefore(new Date(claims.nbf * 1000))
  }
  if (issuer != null) {
    if (!toArray(issuer).some(issuer => issuer === claims.iss)) {
      throw new InvalidClaim(
        'iss',
        '"iss" did not match expected value',
        claims.iss,
        issuer
      )
    }
  }
  if (subject != null) {
    if (subject !== claims.sub) {
      throw new InvalidClaim(
        'sub',
        '"sub" did not match expected value',
        claims.sub,
        subject
      )
    }
  }
  if (audience != null) {
    const validAudience = toArray(audience).some(aud => {
      return aud instanceof RegExp
        ? toArray(claims.aud).some(claimAud => aud.test(claimAud))
        : toArray(claims.aud).some(claimAud => aud === claimAud)
    })
    if (!validAudience) {
      throw new InvalidClaim(
        'aud',
        '"aud" did not match expected value',
        claims.aud,
        audience
      )
    }
  }
  if (jwtId != null) {
    if (jwtId !== claims.jti) {
      throw new InvalidClaim(
        'jti',
        '"jti" did not match expected value',
        claims.jti,
        jwtId
      )
    }
  }
  return claims
}

export class TokenExpired extends JsonWebTokenError {
  /**
   * @param {Date} expiredAt
   */
  constructor (expiredAt) {
    super('TOKEN_EXPIRED', 'JWT expired')
    this.expiredAt = expiredAt
  }
}

export class NotBefore extends JsonWebTokenError {
  /**
   * @param {Date} date
   */
  constructor (date) {
    super('NOT_BEFORE', 'JWT not active')
    this.date = date
  }
}
