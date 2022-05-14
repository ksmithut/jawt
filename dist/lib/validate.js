/**
 * @param {unknown} value
 */
function getTag(value) {
    return Object.prototype.toString.call(value);
}
/**
 * @param {unknown} value
 * @returns {value is {[key: string]: unknown}}
 */
export function isObjectLike(value) {
    return typeof value === 'object' && value !== null;
}
/**
 * @param {unknown} value
 * @return {value is {[key: string]: unknown}}
 */
export function isPlainObject(value) {
    if (!isObjectLike(value) || getTag(value) !== '[object Object]') {
        return false;
    }
    if (Object.getPrototypeOf(value) === null)
        return true;
    let proto = value;
    while (Object.getPrototypeOf(proto) !== null) {
        proto = Object.getPrototypeOf(proto);
    }
    return Object.getPrototypeOf(value) === proto;
}
/**
 * @param {unknown} value
 * @return {value is string}
 */
export function isString(value) {
    return typeof value === 'string';
}
/**
 * @param {unknown} value
 * @return {value is undefined}
 */
export function isUndefined(value) {
    return value === undefined;
}
/**
 * @template T
 * @param {(value: unknown) => value is T} isType
 */
export function isArrayOf(isType) {
    /**
     * @param {unknown} value
     * @returns {value is T[]}
     */
    return value => Array.isArray(value) && value.every(isType);
}
/**
 * @param {unknown} value
 * @return {value is Date}
 */
export function isDate(value) {
    return value instanceof Date && !Number.isNaN(value.valueOf());
}
/**
 * @param {unknown} value
 * @return {value is number}
 */
export function isNumber(value) {
    return (typeof value === 'number' && !Number.isNaN(value) && Number.isFinite(value));
}
/**
 * @param {unknown} value
 * @return {value is number}
 */
export function isInteger(value) {
    return isNumber(value) && Number.isInteger(value);
}
/**
 * @template TA
 * @template TB
 * @param {(value: unknown) => value is TA} a
 * @param {(value: unknown) => value is TB} b
 */
export function or(a, b) {
    /**
     * @param {unknown} value
     * @returns {value is TA|TB}
     */
    return value => a(value) || b(value);
}
/**
 * @template T
 * @param {(value: unknown) => value is T} isType
 */
export function optional(isType) {
    return or(isType, isUndefined);
}
//# sourceMappingURL=validate.js.map