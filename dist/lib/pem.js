import webcrypto from '#webcrypto';
import { base64encode, arrayBufferToString } from './utils/encoding.js';
import { splitEvery } from './utils/split-every.js';
const PRIVATE_KEY_HEADER = '-----BEGIN PRIVATE KEY-----';
const PRIVATE_KEY_FOOTER = '-----END PRIVATE KEY-----';
const PUBLIC_KEY_HEADER = '-----BEGIN PUBLIC KEY-----';
const PUBLIC_KEY_FOOTER = '-----END PUBLIC KEY-----';
/**
 * @param {CryptoKey} cryptoKey
 */
export async function cryptoKeyToPEM(cryptoKey) {
    switch (cryptoKey.type) {
        case 'private': {
            const exportedKey = await webcrypto.subtle.exportKey('pkcs8', cryptoKey);
            const encodedKey = base64encode(arrayBufferToString(exportedKey));
            return [
                PRIVATE_KEY_HEADER,
                ...splitEvery(encodedKey, 64),
                PRIVATE_KEY_FOOTER
            ].join('\n');
        }
        case 'public': {
            const exportedKey = await webcrypto.subtle.exportKey('spki', cryptoKey);
            const encodedKey = base64encode(arrayBufferToString(exportedKey));
            return [
                PUBLIC_KEY_HEADER,
                ...splitEvery(encodedKey, 64),
                PUBLIC_KEY_FOOTER
            ].join('\n');
        }
        /* istanbul ignore next */
        default:
            throw new Error(`Unknown type: "${cryptoKey.type}"`);
    }
}
//# sourceMappingURL=pem.js.map