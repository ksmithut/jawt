/**
 * @typedef {(alg: import('./lib/jwa').HSAlgorithm, options?: undefined) => Promise<import('./key').Key>} GenerateHS
 * @typedef {(alg: import('./lib/jwa').RSAlgorithm, options?: { modulusLength?: number }) => Promise<import('./key').Key>} GenerateRS
 * @typedef {(alg: import('./lib/jwa').PSAlgorithm, options?: { modulusLength?: number }) => Promise<import('./key').Key>} GeneratePS
 * @typedef {(alg: import('./lib/jwa').ESAlgorithm, options?: undefined) => Promise<import('./key').Key>} GenerateES
 *
 * @typedef {GenerateHS & GenerateRS & GeneratePS & GenerateES} Generate
 */
/** @type {Generate} */
export const generate: Generate;
export type GenerateHS = (alg: import('./lib/jwa').HSAlgorithm, options?: undefined) => Promise<import('./key').Key>;
export type GenerateRS = (alg: import('./lib/jwa').RSAlgorithm, options?: {
    modulusLength?: number | undefined;
} | undefined) => Promise<import('./key').Key>;
export type GeneratePS = (alg: import('./lib/jwa').PSAlgorithm, options?: {
    modulusLength?: number | undefined;
} | undefined) => Promise<import('./key').Key>;
export type GenerateES = (alg: import('./lib/jwa').ESAlgorithm, options?: undefined) => Promise<import('./key').Key>;
export type Generate = GenerateHS & GenerateRS & GeneratePS & GenerateES;
