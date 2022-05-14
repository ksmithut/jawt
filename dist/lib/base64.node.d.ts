/**
 * @param {ArrayBuffer|string} data
 */
export function base64urlEncode(data: ArrayBuffer | string): string;
/**
 * @param {ArrayBuffer|string} data
 */
export function base64encode(data: ArrayBuffer | string): string;
/**
 * @param {string} data
 * @returns {string}
 */
export function base64urlDecode(data: string): string;
/**
 * @param {string} data
 * @returns {ArrayBuffer}
 */
export function base64urlDecodeToArrayBuffer(data: string): ArrayBuffer;
