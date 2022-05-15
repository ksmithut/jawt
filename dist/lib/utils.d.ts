/**
 * @template TValue
 * @param {TValue} value
 * @returns {TValue}
 */
export function clone<TValue>(value: TValue): TValue;
/**
 * @param {string} string
 * @returns {ArrayBuffer}
 */
export function stringToArrayBuffer(string: string): ArrayBuffer;
/**
 * @param {Date} date
 */
export function dateToTimestamp(date: Date): number;
/**
 * @template TValue
 * @param {TValue|TValue[]|null} [value]
 */
export function toArray<TValue>(value?: TValue | TValue[] | null | undefined): TValue[];
/**
 * @param {string} string
 * @param {number} length
 */
export function splitEvery(string: string, length: number): string[];
