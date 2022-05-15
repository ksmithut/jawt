import {
  base64urlEncode,
  base64urlDecode,
  base64urlDecodeToArrayBuffer
} from './base64.node.js'
import { stringToArrayBuffer } from './utils.js'
import * as v from './validate.js'
import * as jws from './jws.js'
import { isAlgorithm } from './jwa.js'
import {
  AlgorithmMismatch,
  InvalidJSON,
  InvalidAlgorithm,
  InvalidKeyId,
  InvalidSignature,
  MalformedJWT
} from './jwt.errors.js'

/**
 * @param {object & { alg: import('./jwa.js').JWAlgorithm }} header
 * @param {{[key: string]: unknown}} payload
 * @param {CryptoKey} cryptoKey
 */
export async function signJWT (header, payload, cryptoKey) {
  const body =
    base64urlEncode(JSON.stringify(header)) +
    '.' +
    base64urlEncode(JSON.stringify(payload))
  const signature = base64urlEncode(
    await jws.sign(header.alg, cryptoKey, stringToArrayBuffer(body))
  )
  return body + '.' + signature
}

/**
 * @param {string} string
 * @param {'header'|'payload'} type
 */
function JSONParseBase64 (string, type) {
  try {
    return JSON.parse(base64urlDecode(string))
  } catch {
    throw new InvalidJSON(type)
  }
}

/**
 * @typedef {{[key: string]: unknown}} JWTPayload
 * @typedef {{[key: string]: unknown, typ: 'JWT', alg: import('./jwa.js').JWAlgorithm, kid?: string }} JWTHeader
 */

/**
 * @param {string} token
 * @returns {[JWTPayload, JWTHeader, ArrayBuffer, ArrayBuffer]}
 */
export function decodeJWT (token) {
  if (!v.isString(token)) throw new MalformedJWT('JWT not a string')
  const parts = token.trim().split('.')
  if (parts.length !== 3) throw new MalformedJWT('Not in valid JWT format')
  const [rawHeader, rawPayload, rawSignature] = parts
  const header = JSONParseBase64(rawHeader, 'header')
  if (!v.isPlainObject(header)) {
    throw new MalformedJWT('JWT header not an object')
  }
  const { typ, alg, kid } = header
  if (typ !== 'JWT') throw new MalformedJWT('JWT header missing "typ":"JWT"')
  if (!isAlgorithm(alg)) throw new InvalidAlgorithm()
  if (!v.optional(v.isString)(kid)) throw new InvalidKeyId()
  const payload = JSONParseBase64(rawPayload, 'payload')
  if (!v.isPlainObject(payload)) {
    throw new MalformedJWT('JWT payload not an object')
  }
  return [
    payload,
    { ...header, typ, alg, kid },
    base64urlDecodeToArrayBuffer(rawSignature),
    stringToArrayBuffer(`${rawHeader}.${rawPayload}`)
  ]
}

/**
 * @param {string} token
 * @param {(header: JWTHeader) => Generator<[string, CryptoKey], void, void>} getKeys
 * @returns {Promise<[JWTPayload, JWTHeader]>}
 */
export async function verifyJWT (token, getKeys) {
  const [claims, header, signature, data] = decodeJWT(token)
  for (const [alg, key] of getKeys(header)) {
    /* c8 ignore next */
    if (alg !== header.alg) throw new AlgorithmMismatch()
    if (await jws.verify(alg, key, signature, data).catch(() => false)) {
      return [claims, header]
    }
  }
  throw new InvalidSignature()
}
