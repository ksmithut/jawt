/**
 * @param {CryptoKey} cryptoKey
 */
export function cryptoKeyToJWK(cryptoKey: CryptoKey): Promise<JsonWebKey>;
/**
 * @param {JsonWebKey} jwk
 * @param {KeyAlgorithm} algorithm
 */
export function jwkToCryptoKey(jwk: JsonWebKey, algorithm: KeyAlgorithm): Promise<CryptoKey>;
/**
 * @param {JsonWebKey} jwk
 */
export function privateToPublic(jwk: JsonWebKey): JsonWebKey;
/**
 * @param {JsonWebKey} jwk
 * @returns {KeyUsage[]}
 */
export function keyOps(jwk: JsonWebKey): KeyUsage[];
/**
 * @param {JsonWebKey} jwk
 */
export function generateKid(jwk: JsonWebKey): Promise<string>;
