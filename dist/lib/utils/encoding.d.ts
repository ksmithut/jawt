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
 * @param {ArrayBuffer|string} buffer
 */
export function base64urlEncode(buffer: ArrayBuffer | string): string;
/**
 * @param {string} string
 */
export function base64urlDecode(string: string): ArrayBuffer;
/** @type {(buffer: ArrayBuffer) => string} */
export const base64encode: (buffer: ArrayBuffer) => string;
/** @type {(string: string) => ArrayBuffer} */
export const base64decode: (string: string) => ArrayBuffer;
