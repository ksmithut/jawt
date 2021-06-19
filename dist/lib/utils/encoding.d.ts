/**
 * @param {string} str
 * @returns {ArrayBuffer}
 */
export function stringToArrayBuffer(str: string): ArrayBuffer;
/**
 * @param {ArrayBuffer} arrayBuffer
 * @returns {string}
 */
export function arrayBufferToString(arrayBuffer: ArrayBuffer): string;
/**
 * @param {ArrayBuffer|string} data
 */
export function base64urlEncode(data: ArrayBuffer | string): string;
/**
 * @param {string} string
 */
export function base64urlDecode(string: string): string;
export const base64encode: typeof btoa;
export const base64decode: typeof atob;
