import { base64encode } from './base64.node.js'
import { splitEvery } from './utils.js'
import webcrypto from './webcrypto.node.js'

const PRIVATE_KEY_HEADER = '-----BEGIN PRIVATE KEY-----'
const PRIVATE_KEY_FOOTER = '-----END PRIVATE KEY-----'
const PUBLIC_KEY_HEADER = '-----BEGIN PUBLIC KEY-----'
const PUBLIC_KEY_FOOTER = '-----END PUBLIC KEY-----'

/**
 * @param {CryptoKey} cryptoKey
 */
export async function cryptoKeyToPEM (cryptoKey) {
  switch (cryptoKey.type) {
    case 'private': {
      const exportedKey = await webcrypto.subtle.exportKey('pkcs8', cryptoKey)
      const encodedKey = base64encode(exportedKey)
      return [
        PRIVATE_KEY_HEADER,
        ...splitEvery(encodedKey, 64),
        PRIVATE_KEY_FOOTER
      ]
        .join('\n')
    }
    case 'public': {
      const exportedKey = await webcrypto.subtle.exportKey('spki', cryptoKey)
      const encodedKey = base64encode(exportedKey)
      return [
        PUBLIC_KEY_HEADER,
        ...splitEvery(encodedKey, 64),
        PUBLIC_KEY_FOOTER
      ]
        .join('\n')
    }
    /* c8 ignore next 2 */
    default:
      throw new Error(`Unknown type: "${cryptoKey.type}"`)
  }
}
