import { isPlainObject } from './types.js';
/**
 * @param {object} object
 * @param {(value: unknown, key: string, object: object) => any} iterator
 */
function mapObject(object, iterator) {
    return Object.fromEntries(Object.entries(object).map(([key, value]) => [
        key,
        iterator(value, key, object)
    ]));
}
/**
 * @template T
 * @param {T} value
 * @returns {T}
 */
export function clone(value) {
    if (Array.isArray(value)) {
        // @ts-ignore
        return value.map(value => clone(value));
    }
    if (isPlainObject(value)) {
        // @ts-ignore
        return mapObject(value, value => clone(value));
    }
    /* istanbul ignore next */
    if (typeof value === 'string' ||
        typeof value === 'number' ||
        typeof value === 'boolean' ||
        typeof value === 'bigint' ||
        value == null) {
        return value;
    }
    /* istanbul ignore next */
    // @ts-ignore
    if (value instanceof Date)
        return new Date(value);
    /* istanbul ignore next */
    throw Object.assign(new Error('Unable to copy value'), { value });
}
//# sourceMappingURL=clone.js.map