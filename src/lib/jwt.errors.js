export class JsonWebTokenError extends Error {
  /**
   * @param {string} code
   * @param {string} message
   */
  constructor (code, message) {
    super(message)
    Error.captureStackTrace(this, this.constructor)
    this.name = this.constructor.name
    this.code = code
  }
}

export class InvalidClaim extends JsonWebTokenError {
  /**
   * @param {string} claim
   * @param {string} message
   * @param {unknown} givenValue
   * @param {unknown} [expectedValue]
   */
  constructor (claim, message, givenValue, expectedValue = null) {
    super('INVALID_CLAIM', message)
    this.claim = claim
    this.givenValue = givenValue
    if (expectedValue != null) this.expectedValue = expectedValue
  }
}

export class MalformedJWT extends JsonWebTokenError {
  constructor (message = 'Malformed JWT') {
    super('MALFORMED_JWT', message)
  }
}

export class InvalidJSON extends JsonWebTokenError {
  /**
   * @param {'header'|'payload'} type
   */
  constructor (type) {
    super('INVALID_JSON', `Invalid JSON in JWT ${type}`)
    this.type = type
  }
}

/* c8 ignore next 5 */
export class AlgorithmMismatch extends JsonWebTokenError {
  constructor () {
    super('ALGORITHM_MISMATCH', 'JWT algorithm did not match')
  }
}

export class InvalidAlgorithm extends JsonWebTokenError {
  constructor () {
    super('INVALID_ALGORITHM', 'Invalid alg in JWT header')
  }
}

export class InvalidSignature extends JsonWebTokenError {
  constructor () {
    super('INVALID_SIGNATURE', 'Invalid Signature')
  }
}

export class InvalidKeyId extends JsonWebTokenError {
  constructor () {
    super('INVALID_KEY_ID', 'Invalid kid in token header')
  }
}
