# jawt

This is a dependency-less implementation of
[JSON Web Tokens](https://tools.ietf.org/html/rfc7519) using WebCrypto for
[Node.js](https://nodejs.org).

# Reasoning

This was started as a project for me to dive deep into JSON Web Tokens and the
cryptography involved. This is not currently recommended for production usage!
I am fairly new to cryptography and should really be left to the experts. If
this library gets peer reviewed by experts and sees a decent amount of
"production" usage, only then will I stop discouraging the usage of this
library. Even if that's the case, I would still recommend you use a more fleshed
out library like [jsonwebtoken](https://github.com/auth0/node-jsonwebtoken) or
[jose](https://github.com/panva/jose). Much inspiration was taken from both of
these libraries.

# Requirements

This requires at least Node.js v15.13.0 because it utilizes the
[WebCrypto](https://nodejs.org/dist/latest-v15.x/docs/api/webcrypto.html)
implementation introduced in Node.js v15.0.0. At the time of writing this, it
also says this API is experimental (Stability 1), which states:

> Experimental. The feature is not subject to Semantic Versioning rules.
> Non-backward compatible changes or removal may occur in any future release.
> Use of the feature is not recommended in production environments.

I wanted to pin to WebCrypto because it had a lot of features fleshed out that I
was looking for (native JWK support, more standard signing/verifying api). So
the actual crypto bits are still left to the professionals. This also should
make it fairly easy to make it compatible with the browser once I figure out how
to split the webcrypto exports.

Also, there is no CommonJS version of this library. I'm sure it's just a simple
build process to split the two, which I'll look into when I spend more time on
this. For now, you should by able to use `import('jawt').then(jawt => {})`.

# Basic Usage

```js
import { fromJWKS, jwt } from 'jawt'

async function configureApp () {
  // Then import the keys
  const keyStore = await fromJWKS(JSON.parse(process.env.JWKS))
  // You can get the public keys in `jwks` format to use for a
  // `/.well-known/jwks.json` endpoint
  console.log(keyStore.jwks())

  const token = await jwt.sign({}, keyStore)
  const payload = await jwt.verify(token, keyStore)
}
```

# Comparison to other Libraries

|                | jsonwebtoken | jose | jawt |
| -------------- | ------------ | ---- | ---- |
| Sign           | ✔            | ✔    | ✔    |
| Verify         | ✔            | ✔    | ✔    |
| `iss` check    | ✔            | ✔    | ✔    |
| `sub` check    | ✔            | ✔    | ✔    |
| `aud` check    | ✔            | ✔    | ✔    |
| `exp` check    | ✔            | ✔    | ✔    |
| `nbf` check    | ✔            | ✔    | ✔    |
| `iat` check    | ✔            | ✔    | ✔    |
| `jti` check    | ✔            | ✔    | ✔    |
| None algorithm | ✔            | ✔    |      |
| HS256          | ✔            | ✔    | ✔    |
| HS384          | ✔            | ✔    | ✔    |
| HS512          | ✔            | ✔    | ✔    |
| PS256          | ✔            | ✔    | ✔    |
| PS384          | ✔            | ✔    | ✔    |
| PS512          | ✔            | ✔    | ✔    |
| RS256          | ✔            | ✔    | ✔    |
| RS384          | ✔            | ✔    | ✔    |
| RS512          | ✔            | ✔    | ✔    |
| ES256          | ✔            | ✔    | ✔    |
| ES256K         |              | ✔    |      |
| ES384          | ✔            | ✔    | ✔    |
| ES512          | ✔            | ✔    | ✔    |
| EdDSA          |              | ✔    |      |

# API

## `generate(algorithm, options) => Promise<Key>`

Generates a key to be used for signing/verifying

```js
import { generate } from 'jawt'

// Modulus length options are optional
const rs256Key = await generate('RS256', { modulusLength: 2048 })
const rs384Key = await generate('RS384', { modulusLength: 2048 })
const rs512Key = await generate('RS512', { modulusLength: 2048 })
const ps256Key = await generate('PS256', { modulusLength: 2048 })
const ps384Key = await generate('PS384', { modulusLength: 2048 })
const ps512Key = await generate('PS512', { modulusLength: 2048 })
const es256Key = await generate('ES256')
const es384Key = await generate('ES384')
const es512Key = await generate('ES512')
const hs256Key = await generate('HS256')
const hs384Key = await generate('HS384')
const hs512Key = await generate('HS512')
```

`ES256K` and `EdDSA` is not supported by Node's version of WebCrypto at the time
of writing this. If you find they are before I do, an open issue would be most
welcome.

## `createKeyStore(keys) => KeyStore`

Creates a KeyStore to be used for signing and verifying.

```js
import { generate, createKeyStore } from 'jawt'

const keys = await Promise.all([generate('ES512'), generate('HS256')])
const keyStore = createKeyStore(keys)

keyStore.primaryKey() // gets the first key, used for signing
keyStore.get(keys[0].kid) // gets a key by kid, used in verifying
keyStore.keys() // gets the list of keys in the order given
keyStore.jwks() // { keys: [] } returns the public version of the keys in JWK format
keyStore.jwks(true) // {keys: [] } returns the private version of the keys in JWK format
```

## `fromJWKs(JWKS) => Promise<KeyStore>`

Creates a KeyStore from a JSON Web Key Set

```js
import { generate, createKeyStore, fromJWKS } from 'jawt'

const keys = await Promise.all([generate('ES512'), generate('HS256')])
const keyStore = createKeyStore(keys)

const jwks = keyStore.jwks(true)

// You could then export it and use it in an environment variable
// console.log(JSON.stringify(jwks))
// Then reimport it
// const jwks = JSON.parse(process.env.JWKS)

const duplicateKeyStore = await fromJWKS(jwks)
```

## `jwt.sign(payload, keyStore, options) => Promise<string>`

Sign a payload into a JWT formated string.

```js
import { fromJWKS, jwt } from 'jawt'

const keyStore = await fromJWKS(JSON.parse(process.env.JWKS))
const token = await jwt.sign({}, keyStore)

const tokenWithOptions = await jwt.sign({ userId: '123' }, keyStore, {
  // Date to use for date based operations
  // type: Date
  now: new Date(),

  // turns into `iss` claim
  // type: string
  // Defaults to `undefined`
  issuer: 'iss',

  // turns into `sub` claim
  // type: string
  // Defaults to `undefined`
  subject: 'sub',

  // turns into `aud` claim
  // type: string | string[]
  // Defaults to `undefined`
  audience: 'aud',

  // turns into `exp` claim
  // type: Date | number
  // if it is a number it should be the unix timestamp (seconds) you want it to expire
  // Takes precedence over expiresAt
  // Defaults to `undefined`
  expiresAt: new Date(),

  // turns into `exp` claim
  // type: Date | number
  // if it is a number it should be the number of seconds you want it to expire relative to the `now` option
  // Defaults to `undefined`
  expiresIn: 60,

  // turns into `nbf` claim.
  // type: Date | number
  // if it is a number it should be the unix timestamp (seconds) you want the token to be valid after
  // Defaults to `undefined`
  notBefore: new Date(),

  // turns into `iat` claim.
  // type: boolean | Date | number
  // if it is a boolean, `true` will use the `now` option, `false` will disable sending the claim
  // if it is a number it should be the unix timestamp (seconds) you want the token to say it was issued at
  // Defaults to `true`
  issuedAt: new Date(),

  // turns into `jti` claim.
  // type: string
  // Defaults to `undefined`
  jwtId: 'jti'
})
```

## `jwt.verify(token, keyStore, options) => Promise<payload>`

Validates a token against the keys in the keystore and the expected claims. If
it fails the signature or any of the claims, it will reject the promise with an
error that will have a `.code` property that tells you which claim failed.

```js
import { jwt, createKeyStore, generate } from 'jawt'

const key1 = await generate('HS256')
const key2 = await generate('ES512')
const oldKeyStore = createKeyStore([key1])
const newKeyStore = createKeyStore([key2, key1])

const token1 = await jwt.sign({}, oldKeyStore)
const token2 = await jwt.sign({}, newKeyStore)

// You can use the keystore to rotate in new keys. If you sign the JWT with this
// library, it will encode the JWK id (kid) in the JWT header and will use that
// to determine which key to use. If there is no `kid` in the header, it will
// attempt to verify the JWT data against all the keys until finds the key that
// validates against it. It will only check keys whose algorithms match up
// against the `alg` property in the jwt header.
const payload1 = await jwt.verify(token1, newKeyStore)
const payload2 = await jwt.verify(token2, newKeyStore)

const token3 = await jwt.sign({}, newKeyStore, {
  issuer: 'my-issuer',
  subject: 'my-subject',
  audience: ['audience1', 'audience2'],
  expiresIn: 60,
  jwtId: '4e351afe-026d-44e0-9630-14fd279e70cf'
})

const payload3 = await jwt.verify(token3, newKeyStore, {
  // Date to use for date based operations
  // type: Date
  // Defaults to `new Date()`
  now: new Date(),

  // Checks the `iss` claim
  // type: string | string[]
  // If an array of strings given, the given `iss` claim must be one of the strings
  // Defaults to `undefined`
  issuer: 'my-issuer',

  // Checks the `sub` claim
  // type: string
  // Defaults to `undefined`
  subject: 'my-subject',

  // Checks the `aud` claim
  // type: string | RegExp | (string|RegExp)[]
  // If a string or RegExp is given, the `aud` claim(s) must match the string or RegExp
  // if it is an array of strings and/or RegExps, then the `aud` claim(s) must match one of the given strings or RegExp
  // Defaults to `undefined`
  audience: /^audience\d$/,

  // Checks the `jti` claim
  // type: string
  // Defaults to `undefined`
  jwtId: '4e351afe-026d-44e0-9630-14fd279e70cf',

  // Number of seconds difference to allow for all clock operations
  // type: string
  // Defaults to `0`
  clockTolerance: 30,

  // Maximum number of seconds the token is allows to be old
  // type: number
  // This is used if you don't want to trust super long-lived tokens. If the `iat`
  // claim doesn't exist, then it will fail validation
  maxAge: 60
})
```

## `jwt.verifySafe(token, keyStore, options) => Promise<result>`

This is the same as `jwt.verify()`, but instead of throwing an error, it returns
you an object that is either `{ success: true, payload }` or
`{ success: false, error }`. It should be TypeScript friendly, so if you check
`result.success` in an if statement, you'll be guaranteed the `.payload` or
`.error` depending on what you checked for.

```js
import { setTimeout } from 'timers/promises'
import { jwt, createKeyStore, generate, TokenExpired } from 'jawt'

const key = await generate('HS256')
const keyStore = createKeyStore([key])

const token = await jwt.sign({}, keyStore, {
  expiresIn: 1
})

await setTimeout(2 * 1000)

const result = await jwt.verifySafe(token, keyStore)

if (result.success === false) {
  if (result.error instanceof TokenExpired) {
    console.error('Token Expired')
  } else {
    console.log('Other token error', result.error.code)
  }
} else {
  console.log('success', result.payload)
}
```

# Error Codes

- `MALFORMED_JWT` - This means the JWT didn't have three parts (header, payload,
  signature), or the header wasn't a JSON object, or the payload wasn't a JSON
  object.

- `INVALID_ALGORITHM` - The `alg` in the JWT header isn't supported.

- `INVALID_KEY_ID` - The `kid` in the JWT header exists, but wasn't a string.

- `ALGORITHM_MISMATCH` - The key in the key store found by the `kid` had a
  different algorithm than the `alg` in the JWT header.

- `INVALID_SIGNATURE` - The signature did not match.

- `INVALID_CLAIM` - A claim was being checked, but was the wrong type.

- `NOT_BEFORE` - The token was checked before the `nbf` claim.

- `TOKEN_EXPIRED` - The token was checked after the `exp` claim.

- `AGE_NOT_ACCEPTABLE` - The token was older than the allowed `maxAge` option.

- `ISSUER_NOT_ACCEPTED` - The `iss` claim did not match the `issuer` option.

- `AUDIENCE_NOT_ACCEPTED` - The `aud` claim did not match the `audience` option.

- `SUBJECT_NOT_ACCEPTED` - The `sub` claim did not match the `subject` option.

- `JWT_ID_NOT_ACCEPTED` - The `jti` claim did not match the `jwtId` option.
