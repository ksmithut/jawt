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

export const base64encode = btoa
export const base64decode = atob

/**
 * @param {ArrayBuffer|string} data
 */
export function base64urlEncode (data) {
  if (data instanceof ArrayBuffer) data = arrayBufferToString(data)
  return base64encode(data)
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
