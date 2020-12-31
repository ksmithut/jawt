/**
 * @param {string} string
 * @param {number} length
 */
export function splitEvery (string, length) {
  const output = []
  while (string.length) {
    output.push(string.substr(0, 64))
    string = string.substr(64)
  }
  return output
}
