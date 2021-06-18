import {
  base64urlEncode,
  base64urlDecode,
  stringToArrayBuffer,
  arrayBufferToString
} from './lib/utils/encoding.js'
import {
  InvalidKeyStore,
  MalformedJWT,
  InvalidKeyId,
  InvalidAlgorithm,
  AlgorithmMismatch,
  InvalidSignature,
  InvalidClaim,
  TokenExpired,
  NotBefore,
  IssuerNotAccepted,
  AgeNotAccepted,
  AudienceNotAccepted,
  SubjectNotAccepted,
  JwtIdNotAccepted,
  InvalidJSON
} from './lib/errors.js'
import { isPlainObject } from './lib/utils/types.js'
import { isKeyStore } from './key-store.js'

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
export async function sign (
  payload,
  keyStore,
  {
    now = new Date(),
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
  if (!isPlainObject(payload)) {
    throw new TypeError('payload must be a plain object')
  }
  payload = { ...payload }
  const nowTimestamp = dateToTimestamp(now)
  if (issuer !== undefined) payload.iss = issuer
  if (subject !== undefined) payload.sub = subject
  if (audience !== undefined) payload.aud = audience
  if (expiresAt instanceof Date) payload.exp = dateToTimestamp(expiresAt)
  else if (typeof expiresAt === 'number') payload.exp = expiresAt
  else if (typeof expiresIn === 'number') payload.exp = nowTimestamp + expiresIn
  if (notBefore instanceof Date) payload.nbf = dateToTimestamp(notBefore)
  else if (typeof notBefore === 'number') payload.nbf = notBefore
  if (issuedAt === true) payload.iat = nowTimestamp
  else if (issuedAt instanceof Date) payload.iat = dateToTimestamp(issuedAt)
  else if (typeof issuedAt === 'number') payload.iat = issuedAt
  if (jwtId !== undefined) payload.jti = jwtId
  if (!isKeyStore(keyStore)) throw new InvalidKeyStore()
  const key = keyStore.primaryKey()
  const header = { alg: key.alg, typ: 'JWT', kid: key.kid }
  const data = `${base64urlEncode(JSON.stringify(header))}.${base64urlEncode(
    JSON.stringify(payload)
  )}`
  const signature = await key.sign(stringToArrayBuffer(data))
  return `${data}.${base64urlEncode(signature)}`
}

/**
 * @param {string} string
 * @param {'header'|'payload'} type
 */
function JSONParse (string, type) {
  try {
    return JSON.parse(string)
  } catch {
    throw new InvalidJSON(type)
  }
}

/**
 * @param {string} token
 * @returns {[{[key: string]: unknown}, {[key: string]: unknown}, ArrayBuffer, ArrayBuffer]}
 */
function decode (token) {
  const parts = token.split('.')
  if (parts.length !== 3) throw new MalformedJWT()
  const [rawHeader, rawPayload, rawSignature] = parts
  const header = JSONParse(
    arrayBufferToString(base64urlDecode(rawHeader)),
    'header'
  )
  if (!isPlainObject(header)) throw new MalformedJWT()
  const payload = JSONParse(
    arrayBufferToString(base64urlDecode(rawPayload)),
    'payload'
  )
  if (!isPlainObject(payload)) throw new MalformedJWT()
  return [
    header,
    payload,
    base64urlDecode(rawSignature),
    stringToArrayBuffer(`${rawHeader}.${rawPayload}`)
  ]
}

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
 * @typedef {object} VerifyResultSuccess
 * @property {true} success
 * @property {{[key: string]: unknown}} payload
 */

/**
 * @typedef {object} VerifyResultError
 * @property {false} success
 * @property {import('./lib/errors').JsonWebTokenError} error
 */

/**
 * @param {string} token
 * @param {import('./key-store').KeyStore} keyStore
 * @param {VerifyOptions} [options]
 * @returns {Promise<VerifyResultSuccess | VerifyResultError>}
 */
export async function verifySafe (token, keyStore, options) {
  try {
    const payload = await verify(token, keyStore, options)
    return { success: true, payload }
  } catch (error) {
    return { success: false, error }
  }
}

/**
 * @param {string} token
 * @param {import('./key-store').KeyStore} keyStore
 * @param {VerifyOptions} [options]
 */
export async function verify (
  token,
  keyStore,
  {
    now = new Date(),
    issuer,
    subject,
    audience,
    jwtId,
    clockTolerance,
    maxAge
  } = {}
) {
  if (!isKeyStore(keyStore)) throw new InvalidKeyStore()
  const [header, payload, signature, data] = decode(token)
  if (header.kid !== undefined && typeof header.kid !== 'string') {
    throw new InvalidKeyId()
  }
  if (!header.alg || typeof header.alg !== 'string') {
    throw new InvalidAlgorithm()
  }
  await findKeyAndVerify(header, data, signature, keyStore)
  if (issuer !== undefined) validateIssuer(issuer, payload.iss)
  if (subject !== undefined) validateSubject(subject, payload.sub)
  if (audience !== undefined) validateAudience(audience, payload.aud)
  if (jwtId !== undefined) validateJwtId(jwtId, payload.jti)
  validateTime(payload, { now, maxAge, clockTolerance })
  return payload
}

/**
 * @param {Date} date
 */
function dateToTimestamp (date) {
  return Math.round(date.getTime() / 1000)
}

/**
 * @param {object} header
 * @param {string} [header.kid]
 * @param {string} [header.alg]
 * @param {ArrayBuffer} data
 * @param {ArrayBuffer} signature
 * @param {import('./key-store').KeyStore} keyStore
 */
async function findKeyAndVerify (header, data, signature, keyStore) {
  const key = keyStore.get(header.kid)
  if (key) {
    if (header.alg !== key.alg) throw new AlgorithmMismatch()
    const validSignature = await key.verify(data, signature)
    if (!validSignature) throw new InvalidSignature()
    return
  }
  for (const possibleKey of keyStore.keys()) {
    if (header.alg !== possibleKey.alg) continue
    const validSignature = await possibleKey
      .verify(data, signature)
      .catch(/* istanbul ignore next */ () => false)
    if (validSignature) return
  }
  throw new InvalidSignature()
}

/**
 * @param {string|string[]} expected
 * @param {unknown} given
 */
function validateIssuer (expected, given) {
  if (typeof given !== 'string') throw new InvalidClaim('iss')
  expected = Array.isArray(expected) ? expected : [expected]
  if (!expected.includes(given)) throw new IssuerNotAccepted()
}

/**
 * @param {string} expected
 * @param {unknown} given
 */
function validateSubject (expected, given) {
  if (typeof given !== 'string') throw new InvalidClaim('sub')
  if (expected !== given) throw new SubjectNotAccepted()
}

/**
 * @param {string} expected
 * @param {unknown} given
 */
function validateJwtId (expected, given) {
  if (typeof given !== 'string') throw new InvalidClaim('jti')
  if (expected !== given) throw new JwtIdNotAccepted()
}

/**
 * @param {string|RegExp|(string|RegExp)[]} expected
 * @param {unknown} given
 */
function validateAudience (expected, given) {
  expected = Array.isArray(expected) ? expected : [expected]
  /** @type {string[]} */
  const payloadAudience = Array.isArray(given) ? given : [given]
  payloadAudience.forEach(audience => {
    if (typeof audience !== 'string') throw new InvalidClaim('aud')
  })
  const validAudience = expected.some(audience => {
    return audience instanceof RegExp
      ? payloadAudience.some(aud => audience.test(aud))
      : payloadAudience.some(aud => audience === aud)
  })
  if (!validAudience) throw new AudienceNotAccepted()
}

/**
 * @param {object} payload
 * @param {unknown} [payload.iat]
 * @param {unknown} [payload.exp]
 * @param {unknown} [payload.nbf]
 * @param {object} options
 * @param {Date} options.now
 * @param {number} [options.maxAge]
 * @param {number} [options.clockTolerance=0]
 */
function validateTime ({ iat, exp, nbf }, { now, maxAge, clockTolerance = 0 }) {
  const nowTimestamp = dateToTimestamp(now)
  if (nbf !== undefined) {
    if (typeof nbf !== 'number') throw new InvalidClaim('nbf')
    if (nbf > nowTimestamp + clockTolerance) throw new NotBefore()
  }
  if (exp !== undefined) {
    if (typeof exp !== 'number') throw new InvalidClaim('exp')
    if (exp < nowTimestamp - clockTolerance) throw new TokenExpired()
  }
  if (maxAge != null) {
    if (typeof iat !== 'number') throw new InvalidClaim('iat')
    const age = nowTimestamp - iat
    if (maxAge < age - clockTolerance) throw new AgeNotAccepted()
  }
  if (iat !== undefined) {
    if (typeof iat !== 'number') throw new InvalidClaim('iat')
    // TODO validate that iat is before now?
  }
}
