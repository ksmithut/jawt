export class UnsupportedAlgorithm extends Error {
  /**
   * @param {string} algorithm
   */
  constructor (algorithm) {
    super(`Unsupported algorithm: "${algorithm}"`)
    Error.captureStackTrace(this, this.constructor)
    this.code = 'UNSUPPORTED_JWA_ALGORITHM'
  }
}

export class InvalidModulusLength extends Error {
  constructor () {
    super('modulusLength must not be less than 2048')
    Error.captureStackTrace(this, this.constructor)
    this.code = 'INVALID_MODULUS_LENGTH'
  }
}

export class UnsupportedKeyType extends Error {
  /**
   * @param {string} [kty]
   */
  constructor (kty) {
    super(`Unsupported jwk kty: "${kty}"`)
    Error.captureStackTrace(this, this.constructor)
    this.code = 'UNSUPPORTED_JWK_KTY'
  }
}

export class JsonWebTokenError extends Error {
  /**
   * @param {string} code
   * @param {string} message
   */
  constructor (code, message) {
    super(message)
    Error.captureStackTrace(this, this.constructor)
    this.code = code
  }
}

export class MalformedJWT extends JsonWebTokenError {
  constructor () {
    super('MALFORMED_JWT', 'Malformed JWT')
  }
}

export class InvalidJSON extends JsonWebTokenError {
  /**
   * @param {'header'|'payload'} type
   */
  constructor (type) {
    super('INVALID_JSON', `Invalid JSON in ${type}`)
    this.type = type
  }
}

export class InvalidAlgorithm extends JsonWebTokenError {
  constructor () {
    super('INVALID_ALGORITHM', 'Invalid alg in token header')
  }
}

export class InvalidKeyId extends JsonWebTokenError {
  constructor () {
    super('INVALID_KEY_ID', 'Invalid kid in token header')
  }
}

export class AlgorithmMismatch extends JsonWebTokenError {
  constructor () {
    super(
      'ALGORITHM_MISMATCH',
      'JWT algorithm did not match keyStore algorithm'
    )
  }
}

export class InvalidSignature extends JsonWebTokenError {
  constructor () {
    super('INVALID_SIGNATURE', 'Invalid Signature')
  }
}

export class InvalidClaim extends JsonWebTokenError {
  /**
   * @param {string} claim
   */
  constructor (claim) {
    super('INVALID_CLAIM', `Invalid claim: ${claim}`)
    this.claim = claim
  }
}

export class NotBefore extends JsonWebTokenError {
  constructor () {
    super('NOT_BEFORE', 'Token is not yet active')
  }
}

export class TokenExpired extends JsonWebTokenError {
  constructor () {
    super('TOKEN_EXPIRED', 'Token has expired')
  }
}

export class AgeNotAccepted extends JsonWebTokenError {
  constructor () {
    super('AGE_NOT_ACCEPTED', 'Token is too old')
  }
}

export class IssuerNotAccepted extends JsonWebTokenError {
  constructor () {
    super('ISSUER_NOT_ACCEPTED', 'Given "iss" was not accepted')
  }
}

export class AudienceNotAccepted extends JsonWebTokenError {
  constructor () {
    super('AUDIENCE_NOT_ACCEPTED', 'Given "aud" was not accepted')
  }
}

export class SubjectNotAccepted extends JsonWebTokenError {
  constructor () {
    super('SUBJECT_NOT_ACCEPTED', 'Given "sub" was not accepted')
  }
}

export class JwtIdNotAccepted extends JsonWebTokenError {
  constructor () {
    super('JWT_ID_NOT_ACCEPTED', 'Given "jti" was not accepted')
  }
}
