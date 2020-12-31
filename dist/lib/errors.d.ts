export class UnsupportedAlgorithm extends Error {
    /**
     * @param {string} algorithm
     */
    constructor(algorithm: string);
    code: string;
}
export class InvalidModulusLength extends Error {
    code: string;
}
export class UnsupportedKeyType extends Error {
    /**
     * @param {string} [kty]
     */
    constructor(kty?: string | undefined);
    code: string;
}
export class JsonWebTokenError extends Error {
    /**
     * @param {string} code
     * @param {string} message
     */
    constructor(code: string, message: string);
    code: string;
}
export class MalformedJWT extends JsonWebTokenError {
}
export class InvalidAlgorithm extends JsonWebTokenError {
}
export class InvalidKeyId extends JsonWebTokenError {
}
export class AlgorithmMismatch extends JsonWebTokenError {
}
export class InvalidSignature extends JsonWebTokenError {
}
export class InvalidClaim extends JsonWebTokenError {
    /**
     * @param {string} claim
     */
    constructor(claim: string);
}
export class NotBefore extends JsonWebTokenError {
}
export class TokenExpired extends JsonWebTokenError {
}
export class AgeNotAccepted extends JsonWebTokenError {
}
export class IssuerNotAccepted extends JsonWebTokenError {
}
export class AudienceNotAccepted extends JsonWebTokenError {
}
export class SubjectNotAccepted extends JsonWebTokenError {
}
export class JwtIdNotAccepted extends JsonWebTokenError {
}
