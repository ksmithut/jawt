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
