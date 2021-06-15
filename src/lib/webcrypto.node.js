// This should be imported via #webcrypto
import crypto from 'crypto'

/** @type {Crypto} */
// @ts-ignore
const webcrypto = crypto.webcrypto
export default webcrypto
