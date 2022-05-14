export class JsonWebTokenError extends Error {
    /**
     * @param {string} code
     * @param {string} message
     */
    constructor(code: string, message: string);
    code: string;
}
export class InvalidClaim extends JsonWebTokenError {
    /**
     * @param {string} claim
     * @param {string} message
     * @param {unknown} givenValue
     * @param {unknown} [expectedValue]
     */
    constructor(claim: string, message: string, givenValue: unknown, expectedValue?: unknown);
    claim: string;
    givenValue: unknown;
    expectedValue: unknown;
}
export class MalformedJWT extends JsonWebTokenError {
    constructor(message?: string);
}
export class InvalidJSON extends JsonWebTokenError {
    /**
     * @param {'header'|'payload'} type
     */
    constructor(type: 'header' | 'payload');
    type: "header" | "payload";
}
export class AlgorithmMismatch extends JsonWebTokenError {
    constructor();
}
export class InvalidAlgorithm extends JsonWebTokenError {
    constructor();
}
export class InvalidSignature extends JsonWebTokenError {
    constructor();
}
export class InvalidKeyId extends JsonWebTokenError {
    constructor();
}
