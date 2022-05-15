/**
 * @param {unknown} keyStore
 * @returns {keyStore is KeyStore}
 */
export function isKeyStore(keyStore: unknown): keyStore is Readonly<{
    primaryKey(): Readonly<{
        kid(): string;
        alg(): import("./lib/jwa.js").JWAlgorithm;
        privateJWK(): JsonWebKey & {
            kid: string;
            alg: string;
        };
        publicJWK(): JsonWebKey & {
            kid: string;
            alg: string;
        };
        signingKey(): CryptoKey;
        verifyingKey(): CryptoKey;
        signingKeyRaw(): Promise<ArrayBuffer>;
        verifyingKeyRaw(): Promise<ArrayBuffer>;
    }>;
    /**
     * @param {string} [kid]
     */
    get(kid?: string | undefined): Readonly<{
        kid(): string;
        alg(): import("./lib/jwa.js").JWAlgorithm;
        privateJWK(): JsonWebKey & {
            kid: string;
            alg: string;
        };
        publicJWK(): JsonWebKey & {
            kid: string;
            alg: string;
        };
        signingKey(): CryptoKey;
        verifyingKey(): CryptoKey;
        signingKeyRaw(): Promise<ArrayBuffer>;
        verifyingKeyRaw(): Promise<ArrayBuffer>;
    }> | null;
    keys(): Generator<Readonly<{
        kid(): string;
        alg(): import("./lib/jwa.js").JWAlgorithm;
        privateJWK(): JsonWebKey & {
            kid: string;
            alg: string;
        };
        publicJWK(): JsonWebKey & {
            kid: string;
            alg: string;
        };
        signingKey(): CryptoKey;
        verifyingKey(): CryptoKey;
        signingKeyRaw(): Promise<ArrayBuffer>;
        verifyingKeyRaw(): Promise<ArrayBuffer>;
    }>, void, unknown>;
    privateJWKS(): {
        keys: (JsonWebKey & {
            kid: string;
            alg: string;
        })[];
    };
    publicJWKS(): {
        keys: (JsonWebKey & {
            kid: string;
            alg: string;
        })[];
    };
}>;
/**
 * @param {import('./key.js').Key[]} keys
 */
export function createKeyStore(keys: import('./key.js').Key[]): Readonly<{
    primaryKey(): Readonly<{
        kid(): string;
        alg(): import("./lib/jwa.js").JWAlgorithm;
        privateJWK(): JsonWebKey & {
            kid: string;
            alg: string;
        };
        publicJWK(): JsonWebKey & {
            kid: string;
            alg: string;
        };
        signingKey(): CryptoKey;
        verifyingKey(): CryptoKey;
        signingKeyRaw(): Promise<ArrayBuffer>;
        verifyingKeyRaw(): Promise<ArrayBuffer>;
    }>;
    /**
     * @param {string} [kid]
     */
    get(kid?: string | undefined): Readonly<{
        kid(): string;
        alg(): import("./lib/jwa.js").JWAlgorithm;
        privateJWK(): JsonWebKey & {
            kid: string;
            alg: string;
        };
        publicJWK(): JsonWebKey & {
            kid: string;
            alg: string;
        };
        signingKey(): CryptoKey;
        verifyingKey(): CryptoKey;
        signingKeyRaw(): Promise<ArrayBuffer>;
        verifyingKeyRaw(): Promise<ArrayBuffer>;
    }> | null;
    keys(): Generator<Readonly<{
        kid(): string;
        alg(): import("./lib/jwa.js").JWAlgorithm;
        privateJWK(): JsonWebKey & {
            kid: string;
            alg: string;
        };
        publicJWK(): JsonWebKey & {
            kid: string;
            alg: string;
        };
        signingKey(): CryptoKey;
        verifyingKey(): CryptoKey;
        signingKeyRaw(): Promise<ArrayBuffer>;
        verifyingKeyRaw(): Promise<ArrayBuffer>;
    }>, void, unknown>;
    privateJWKS(): {
        keys: (JsonWebKey & {
            kid: string;
            alg: string;
        })[];
    };
    publicJWKS(): {
        keys: (JsonWebKey & {
            kid: string;
            alg: string;
        })[];
    };
}>;
/**
 * @param {{ keys: (JsonWebKey & { kid?: string, alg: string })[] }} jwks
 */
export function createKeyStoreFromJWKS(jwks: {
    keys: (JsonWebKey & {
        kid?: string;
        alg: string;
    })[];
}): Promise<Readonly<{
    primaryKey(): Readonly<{
        kid(): string;
        alg(): import("./lib/jwa.js").JWAlgorithm;
        privateJWK(): JsonWebKey & {
            kid: string;
            alg: string;
        };
        publicJWK(): JsonWebKey & {
            kid: string;
            alg: string;
        };
        signingKey(): CryptoKey;
        verifyingKey(): CryptoKey;
        signingKeyRaw(): Promise<ArrayBuffer>;
        verifyingKeyRaw(): Promise<ArrayBuffer>;
    }>;
    /**
     * @param {string} [kid]
     */
    get(kid?: string | undefined): Readonly<{
        kid(): string;
        alg(): import("./lib/jwa.js").JWAlgorithm;
        privateJWK(): JsonWebKey & {
            kid: string;
            alg: string;
        };
        publicJWK(): JsonWebKey & {
            kid: string;
            alg: string;
        };
        signingKey(): CryptoKey;
        verifyingKey(): CryptoKey;
        signingKeyRaw(): Promise<ArrayBuffer>;
        verifyingKeyRaw(): Promise<ArrayBuffer>;
    }> | null;
    keys(): Generator<Readonly<{
        kid(): string;
        alg(): import("./lib/jwa.js").JWAlgorithm;
        privateJWK(): JsonWebKey & {
            kid: string;
            alg: string;
        };
        publicJWK(): JsonWebKey & {
            kid: string;
            alg: string;
        };
        signingKey(): CryptoKey;
        verifyingKey(): CryptoKey;
        signingKeyRaw(): Promise<ArrayBuffer>;
        verifyingKeyRaw(): Promise<ArrayBuffer>;
    }>, void, unknown>;
    privateJWKS(): {
        keys: (JsonWebKey & {
            kid: string;
            alg: string;
        })[];
    };
    publicJWKS(): {
        keys: (JsonWebKey & {
            kid: string;
            alg: string;
        })[];
    };
}>>;
export type KeyStore = ReturnType<typeof createKeyStore>;
