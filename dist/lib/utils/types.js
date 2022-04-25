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
    /* istanbul ignore if */
    if (Object.getPrototypeOf(value) === null) {
        return true;
    }
    let proto = value;
    while (Object.getPrototypeOf(proto) !== null) {
        proto = Object.getPrototypeOf(proto);
    }
    return Object.getPrototypeOf(value) === proto;
}
//# sourceMappingURL=types.js.map