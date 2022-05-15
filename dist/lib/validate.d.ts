/**
 * @param {unknown} value
 * @returns {value is {[key: string]: unknown}}
 */
export function isObjectLike(value: unknown): value is {
    [key: string]: unknown;
};
/**
 * @param {unknown} value
 * @return {value is {[key: string]: unknown}}
 */
export function isPlainObject(value: unknown): value is {
    [key: string]: unknown;
};
/**
 * @param {unknown} value
 * @return {value is string}
 */
export function isString(value: unknown): value is string;
/**
 * @param {unknown} value
 * @return {value is undefined}
 */
export function isUndefined(value: unknown): value is undefined;
/**
 * @template T
 * @param {(value: unknown) => value is T} isType
 */
export function isArrayOf<T>(isType: (value: unknown) => value is T): (value: unknown) => value is T[];
/**
 * @param {unknown} value
 * @return {value is Date}
 */
export function isDate(value: unknown): value is Date;
/**
 * @param {unknown} value
 * @return {value is number}
 */
export function isNumber(value: unknown): value is number;
/**
 * @param {unknown} value
 * @return {value is number}
 */
export function isInteger(value: unknown): value is number;
/**
 * @template TA
 * @template TB
 * @param {(value: unknown) => value is TA} a
 * @param {(value: unknown) => value is TB} b
 */
export function or<TA, TB>(a: (value: unknown) => value is TA, b: (value: unknown) => value is TB): (value: unknown) => value is TA | TB;
/**
 * @template T
 * @param {(value: unknown) => value is T} isType
 */
export function optional<T>(isType: (value: unknown) => value is T): (value: unknown) => value is T | undefined;
