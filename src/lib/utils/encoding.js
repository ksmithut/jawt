/**
 * @param {string} str
 * @returns {ArrayBuffer}
 */
export function stringToArrayBuffer (str) {
  return Uint8Array.from(str, c => c.codePointAt(0) ?? 0).buffer
}

/**
 * @param {ArrayBuffer} arrayBuffer
 * @returns {string}
 */
export function arrayBufferToString (arrayBuffer) {
  return String.fromCodePoint(...new Uint8Array(arrayBuffer))
}

/** @type {(buffer: ArrayBuffer) => string} */
export const base64encode =
  typeof btoa === 'function'
    ? buffer => btoa(arrayBufferToString(buffer))
    : buffer => Buffer.from(buffer).toString('base64')

/** @type {(string: string) => ArrayBuffer} */
export const base64decode =
  typeof atob === 'function'
    ? string => stringToArrayBuffer(atob(string))
    : string => Uint8Array.from(Buffer.from(string, 'base64')).buffer

/**
 * @param {ArrayBuffer|string} buffer
 */
export function base64urlEncode (buffer) {
  if (typeof buffer === 'string') buffer = stringToArrayBuffer(buffer)
  return base64encode(buffer)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '')
}

/**
 * @param {string} string
 */
export function base64urlDecode (string) {
  return base64decode(string.replace(/-/g, '+').replace(/_/g, '/'))
}
