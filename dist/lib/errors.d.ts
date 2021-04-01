export class UnsupportedAlgorithm extends Error {
    /**
     * @param {string} algorithm
     */
    constructor(algorithm: string);
    code: string;
}
export class InvalidModulusLength extends Error {
    constructor();
    code: string;
}
export class UnsupportedKeyType extends Error {
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
    constructor();
}
export class InvalidAlgorithm extends JsonWebTokenError {
    constructor();
}
export class InvalidKeyId extends JsonWebTokenError {
    constructor();
}
export class AlgorithmMismatch extends JsonWebTokenError {
    constructor();
}
export class InvalidSignature extends JsonWebTokenError {
    constructor();
}
export class InvalidClaim extends JsonWebTokenError {
    /**
     * @param {string} claim
     */
    constructor(claim: string);
}
export class NotBefore extends JsonWebTokenError {
    constructor();
}
export class TokenExpired extends JsonWebTokenError {
    constructor();
}
export class AgeNotAccepted extends JsonWebTokenError {
    constructor();
}
export class IssuerNotAccepted extends JsonWebTokenError {
    constructor();
}
export class AudienceNotAccepted extends JsonWebTokenError {
    constructor();
}
export class SubjectNotAccepted extends JsonWebTokenError {
    constructor();
}
export class JwtIdNotAccepted extends JsonWebTokenError {
    constructor();
}
