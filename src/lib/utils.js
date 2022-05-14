/**
 * @template TValue
 * @param {TValue} value
 * @returns {TValue}
 */
export function clone (value) {
  // @ts-ignore
  return structuredClone(value)
}

/**
 * @param {string} string
 * @returns {ArrayBuffer}
 */
export function stringToArrayBuffer (string) {
  return Uint8Array.from(string, c => c.codePointAt(0) ?? 0).buffer
}

/**
 * @param {Date} date
 */
export function dateToTimestamp (date) {
  return Math.floor(date.getTime() / 1000)
}

/**
 * @template TValue
 * @param {TValue|TValue[]|null} [value]
 */
export function toArray (value) {
  if (value == null) return []
  if (Array.isArray(value)) return value
  return [value]
}

/**
 * @param {string} string
 * @param {number} length
 */
export function splitEvery (string, length) {
  const output = []
  while (string.length) {
    output.push(string.substring(0, length))
    string = string.substring(length)
  }
  return output
}
