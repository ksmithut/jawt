import { Buffer } from 'node:buffer'

/**
 * @param {ArrayBuffer|string} data
 */
export function base64urlEncode (data) {
  // @ts-ignore
  return Buffer.from(data).toString('base64url')
}

/**
 * @param {ArrayBuffer|string} data
 */
export function base64encode (data) {
  // @ts-ignore
  return Buffer.from(data).toString('base64')
}

/**
 * @param {string} data
 * @returns {string}
 */
export function base64urlDecode (data) {
  return Buffer.from(data, 'base64url').toString()
}

/**
 * @param {string} data
 * @returns {ArrayBuffer}
 */
export function base64urlDecodeToArrayBuffer (data) {
  return bufferToArrayBuffer(Buffer.from(data, 'base64url'))
}

/**
 * @param {Buffer} buffer
 */
function bufferToArrayBuffer (buffer) {
  if (
    buffer.byteOffset === 0 &&
    buffer.byteLength === buffer.buffer.byteLength
  ) {
    return buffer.buffer
  }
  return buffer.buffer.slice(
    buffer.byteOffset,
    buffer.byteOffset + buffer.byteLength
  )
}
