import webcrypto from '#webcrypto'
import { base64encode } from './utils/encoding.js'
import { splitEvery } from './utils/split-every.js'

/**
 * @param {CryptoKey} cryptoKey
 */
export async function cryptoKeyToPEM (cryptoKey) {
  switch (cryptoKey.type) {
    case 'private':
      return [
        '-----BEGIN PRIVATE KEY-----',
        ...splitEvery(
          base64encode(await webcrypto.subtle.exportKey('pkcs8', cryptoKey)),
          64
        ),
        '-----END PRIVATE KEY-----'
      ].join('\n')
    case 'public':
      return [
        '-----BEGIN PUBLIC KEY-----',
        ...splitEvery(
          base64encode(await webcrypto.subtle.exportKey('spki', cryptoKey)),
          64
        ),
        '-----END PUBLIC KEY-----'
      ].join('\n')
    default:
      throw new Error(`Unknown type: "${cryptoKey.type}"`)
  }
}
