/**
 * @param {string} str
 * @returns {ArrayBuffer}
 */
export function stringToArrayBuffer (str) {
  /* istanbul ignore next */
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
export function base64encode (buffer) {
  return btoa(arrayBufferToString(buffer))
}

/** @type {(string: string) => ArrayBuffer} */
export function base64decode (string) {
  return stringToArrayBuffer(atob(string))
}

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
