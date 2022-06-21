import assert from 'node:assert'
import fs from 'node:fs/promises'
import { Buffer } from 'node:buffer'
import tap from 'tap'
import jsonwebtoken from 'jsonwebtoken'
import {
  generate,
  jwt,
  createKeyStore,
  createKeyStoreFromJWKS,
  createKeyFromCryptoKey,
  createKeyFromJWK,
  supportedAlgorithms
} from '../src/index.js'

const { test } = tap

test('jawt', async t => {
  t.test('can sign jwt', async () => {
    const keyStore = createKeyStore([await generate('ES256')])
    const clock = new Date()
    const token = await jwt.sign({}, keyStore, { clock })
    const { payload } = await jwt.verify(token, keyStore)
    assert.deepStrictEqual(payload, { iat: Math.floor(clock.getTime() / 1000) })
  })

  t.test('tokens can be verified by external library', async () => {
    const keyStore = createKeyStore([await generate('ES256')])
    const key = keyStore.primaryKey()
    const clock = new Date()
    const clockTimestamp = Math.floor(clock.getTime() / 1000)
    const token = await jwt.sign({}, keyStore, { clock })
    const payload = jsonwebtoken.verify(
      token,
      Buffer.from(await key.verifyingKeyRaw()),
      { algorithms: [key.alg()] }
    )
    assert.deepStrictEqual(payload, { iat: clockTimestamp })
  })

  t.test('external tokens can be verified', async () => {
    const keyStore = createKeyStore([await generate('ES256')])
    const key = keyStore.primaryKey()
    const clock = new Date()
    const clockTimestamp = Math.floor(clock.getTime() / 1000)
    const token = jsonwebtoken.sign(
      { iat: clockTimestamp },
      Buffer.from(await key.signingKeyRaw()),
      { algorithm: key.alg() }
    )
    const { payload } = await jwt.verify(token, keyStore)
    assert.deepStrictEqual(payload, { iat: clockTimestamp })
  })

  t.test('fails if algorithm is not supported', async () => {
    // @ts-ignore
    await assert.rejects(() => generate('RANDO'), {
      name: 'UnsupportedAlgorithm',
      code: 'UNSUPPORTED_JWA_ALGORITHM',
      message: 'Unsupported algorithm: "RANDO"',
      algorithm: 'RANDO'
    })
  })

  t.test('works with tokens generated from two different keys', async () => {
    const newKey = await generate('ES256')
    const oldKey = await generate('HS256')
    const newKeyStore = createKeyStore([newKey, oldKey])
    const oldKeyStore = createKeyStore([oldKey])
    const newToken = await jwt.sign({ type: 'new' }, newKeyStore)
    const oldToken = await jwt.sign({ type: 'old' }, oldKeyStore)
    const newResult = await jwt.verify(newToken, newKeyStore)
    const oldResult = await jwt.verify(oldToken, newKeyStore)
    assert.deepStrictEqual(newResult.payload.type, 'new')
    assert.deepStrictEqual(oldResult.payload.type, 'old')
  })

  t.test(
    'works with external tokens generate from two different keys',
    async () => {
      const newKey = await generate('ES256')
      const oldKey = await generate('HS256')
      const keyStore = createKeyStore([newKey, oldKey])
      const newToken = jsonwebtoken.sign(
        { type: 'new' },
        Buffer.from(await newKey.signingKeyRaw()),
        { algorithm: newKey.alg() }
      )
      const oldToken = jsonwebtoken.sign(
        { type: 'old' },
        Buffer.from(await oldKey.signingKeyRaw()),
        { algorithm: oldKey.alg() }
      )
      const newResult = await jwt.verify(newToken, keyStore)
      const oldResult = await jwt.verify(oldToken, keyStore)
      assert.deepStrictEqual(newResult.payload.type, 'new')
      assert.deepStrictEqual(oldResult.payload.type, 'old')
    }
  )

  t.test('fails if kid matches but signature fails', async () => {
    const key1 = await generate('HS256')
    const keyStore = createKeyStore([key1])
    const token = jsonwebtoken.sign({}, 'secretsecret', {
      algorithm: key1.alg(),
      keyid: key1.kid()
    })
    await assert.rejects(() => jwt.verify(token, keyStore), {
      name: 'InvalidSignature',
      code: 'INVALID_SIGNATURE'
    })
  })

  t.test('fails if we do not have key', async () => {
    const keyStore = createKeyStore([await generate('HS256')])
    const token = await jwt.sign({}, createKeyStore([await generate('HS256')]))
    await assert.rejects(() => jwt.verify(token, keyStore), {
      name: 'InvalidSignature',
      code: 'INVALID_SIGNATURE'
    })
  })

  t.test('verifySafe does not throw', async () => {
    const keyStore = createKeyStore([await generate('HS256')])
    const token = await jwt.sign({}, keyStore)
    const result = await jwt.verifySafe(
      token,
      createKeyStore([await generate('HS256')])
    )
    assert.deepStrictEqual(result.success, false)
    // @ts-ignore
    assert.deepStrictEqual(result.error.code, 'INVALID_SIGNATURE')
    // @ts-ignore
    assert.deepStrictEqual(result.error.message, 'Invalid Signature')
  })

  t.test('verifySafe gets successful result', async () => {
    const key = await generate('HS256')
    const keyStore = createKeyStore([key])
    const clock = new Date()
    const clockTimestamp = Math.floor(clock.getTime() / 1000)
    const token = await jwt.sign({}, keyStore, { clock })
    const result = await jwt.verifySafe(token, keyStore)
    assert.deepStrictEqual(result, {
      success: true,
      payload: { iat: clockTimestamp },
      header: { alg: key.alg(), kid: key.kid(), typ: 'JWT' }
    })
  })

  t.test('cannot sign jwts with only public keys', async () => {
    const keyStore = await createKeyStoreFromJWKS(
      createKeyStore([await generate('ES256')]).publicJWKS()
    )
    await assert.rejects(() => jwt.sign({}, keyStore), {
      name: 'InvalidSigningKey',
      message: 'Given CryptoKey is not a signing key'
    })
  })

  t.test('cannot get signingKeyRaw with public key', async () => {
    const keyStore = await createKeyStoreFromJWKS(
      createKeyStore([await generate('ES256')]).publicJWKS()
    )
    await assert.rejects(() => keyStore.primaryKey().signingKeyRaw(), {
      name: 'InvalidSigningKey',
      message: 'Given CryptoKey is not a signing key'
    })
  })

  t.test('can use HS*** key with external library', async () => {
    const keyStore = createKeyStore([await generate('HS256')])
    const key = keyStore.primaryKey()
    const clock = new Date()
    const clockTimestamp = Math.floor(clock.getTime() / 1000)
    const token = await jwt.sign({}, keyStore, { clock })
    const payload = jsonwebtoken.verify(
      token,
      Buffer.from(await key.verifyingKeyRaw()),
      { algorithms: [key.alg()] }
    )
    assert.deepStrictEqual(payload, { iat: clockTimestamp })
  })

  t.test('gets list of supported algorithms', async () => {
    assert.deepStrictEqual(supportedAlgorithms(), [
      'HS256',
      'HS384',
      'HS512',
      'RS256',
      'RS384',
      'RS512',
      'PS256',
      'PS384',
      'PS512',
      'ES256',
      'ES384',
      'ES512',
      'EdDSA'
    ])
  })
})

test('option claims', async t => {
  const keyStore = createKeyStore([await generate('ES256')])
  const clock = new Date(1552444004292)
  const iat = Math.floor(clock.getTime() / 1000)

  /** @type {[string, import('../src/jawt.js').AttachStandardClaimsParams, import('../src/jawt.js').PayloadWithStandardClaims][]} */
  const optionPayloads = [
    ['issuer', { issuer: 'test.issuer', clock }, { iss: 'test.issuer', iat }],
    [
      'subject',
      { subject: 'test.subject', clock },
      { sub: 'test.subject', iat }
    ],
    [
      'audience string',
      { audience: 'test.audience', clock },
      { aud: 'test.audience', iat }
    ],
    [
      'audience array',
      { audience: ['test1', 'test2'], clock },
      { aud: ['test1', 'test2'], iat }
    ],
    [
      'expiresAt Date',
      { expiresAt: new Date(1652444004292), clock },
      { exp: 1652444004, iat }
    ],
    [
      'expiresAt number',
      { expiresAt: 1652444004, clock },
      { exp: 1652444004, iat }
    ],
    [
      'expiresIn',
      { expiresIn: 60, clock: new Date(1652444004292) },
      { exp: 1652444064, iat: 1652444004 }
    ],
    [
      'notBefore Date',
      { notBefore: new Date(1652444004292), clock },
      { nbf: 1652444004, iat }
    ],
    [
      'notBefore number',
      { notBefore: 1652444004, clock },
      { nbf: 1652444004, iat }
    ],
    [
      'issuedAt default',
      { clock: new Date(1652444004292) },
      { iat: 1652444004 }
    ],
    ['issuedAt false', { issuedAt: false }, {}],
    [
      'issuedAt Date',
      { issuedAt: new Date(1652444004292) },
      { iat: 1652444004 }
    ],
    ['issuedAt number', { issuedAt: 1652444004 }, { iat: 1652444004 }],
    [
      'jwtId',
      { jwtId: 'fce0865f-c96e-4352-b29c-8efdf66c3d8e', clock },
      { jti: 'fce0865f-c96e-4352-b29c-8efdf66c3d8e', iat }
    ]
  ]

  for (const [name, options, expectedPayload] of optionPayloads) {
    t.test(name, async () => {
      const token = await jwt.sign({}, keyStore, options)
      const result = await jwt.verify(token, keyStore, {
        clockTolerance: Infinity
      })
      assert.deepStrictEqual(result.payload, expectedPayload)
    })
  }

  t.test('fails if payload is not an object', async () => {
    // @ts-ignore
    await assert.rejects(() => jwt.sign('payload', keyStore), {
      name: 'TypeError',
      message: '"payload" must be a plain object'
    })
  })

  t.test('fails if clock is not a date', async () => {
    // @ts-ignore
    await assert.rejects(() => jwt.sign({}, keyStore, { clock: 7 }), {
      name: 'TypeError',
      message: '"clock" must be a Date object'
    })
  })

  t.test('does not mutate the payload object', async () => {
    /** @type {import('../src/index.js').jwt.JWTPayload} */
    const payload = {}
    const token = await jwt.sign(payload, keyStore, { issuedAt: 7 })
    const result = await jwt.verify(token, keyStore)
    assert.deepStrictEqual(payload, {})
    assert.deepStrictEqual(result.payload, { iat: 7 })
  })

  /** @type {[string, object, object][]} */
  const optionErrors = [
    [
      'issuer',
      { issuer: 123 },
      {
        name: 'InvalidClaim',
        message: '"iss" must be a string or undefined',
        claim: 'iss',
        givenValue: 123
      }
    ],
    [
      'subject',
      { subject: 123 },
      {
        name: 'InvalidClaim',
        message: '"sub" must be a string or undefined',
        claim: 'sub',
        givenValue: 123
      }
    ],
    [
      'audience',
      { audience: [['aud']] },
      {
        name: 'InvalidClaim',
        message: '"aud" must be a string, array of strings, or undefined',
        claim: 'aud',
        givenValue: [['aud']]
      }
    ],
    [
      'expiresAt',
      { expiresAt: 'foobar' },
      {
        name: 'InvalidClaim',
        message: '"exp" must be an integer or undefined',
        claim: 'exp',
        givenValue: 'foobar'
      }
    ],
    [
      'notBefore',
      { notBefore: 'foobar' },
      {
        name: 'InvalidClaim',
        message: '"nbf" must be an integer or undefined',
        claim: 'nbf',
        givenValue: 'foobar'
      }
    ],
    [
      'issuedAt',
      { issuedAt: 'foobar' },
      {
        name: 'InvalidClaim',
        message: '"iat" must be an integer or undefined',
        claim: 'iat',
        givenValue: 'foobar'
      }
    ],
    [
      'jwtId',
      { jwtId: 123 },
      {
        name: 'InvalidClaim',
        message: '"jti" must be a string or undefined',
        claim: 'jti',
        givenValue: 123
      }
    ]
  ]
  for (const [name, options, error] of optionErrors) {
    t.test(`invalid option ${name}`, async () => {
      await assert.rejects(() => jwt.sign({}, keyStore, options), error)
    })
  }

  /** @type {[string, import('../src/index.js').jwt.AttachStandardClaimsParams, import('../src/index.js').jwt.VerifyStandardClaimsParams, object][]} */
  const validateFailureOptions = [
    [
      'maxAge',
      { clock },
      { clock: new Date(clock.getTime() + 50000), maxAge: 30 },
      {
        name: 'InvalidClaim',
        claim: 'iat',
        message: 'JWT is too old',
        code: 'INVALID_CLAIM'
      }
    ],
    [
      'maxAge with clockTolerance',
      { clock },
      {
        clock: new Date(clock.getTime() + 100000),
        maxAge: 90,
        clockTolerance: 5
      },
      {
        name: 'InvalidClaim',
        claim: 'iat',
        message: 'JWT is too old',
        code: 'INVALID_CLAIM'
      }
    ],
    [
      'expiration',
      { clock, expiresIn: 50 },
      { clock: new Date(clock.getTime() + 100000) },
      { name: 'TokenExpired', code: 'TOKEN_EXPIRED', message: 'JWT expired' }
    ],
    [
      'notBefore',
      { clock, notBefore: clock },
      { clock: new Date(clock.getTime() - 50000) },
      { name: 'NotBefore', code: 'NOT_BEFORE', message: 'JWT not active' }
    ],
    [
      'issuer string',
      { clock, issuer: 'test.issuer' },
      { issuer: 'prod.issuer' },
      {
        name: 'InvalidClaim',
        code: 'INVALID_CLAIM',
        message: '"iss" did not match expected value',
        claim: 'iss',
        givenValue: 'test.issuer',
        expectedValue: 'prod.issuer'
      }
    ],
    [
      'issuer array',
      { clock, issuer: 'test.issuer' },
      { issuer: ['prod.issuer', 'test.foobar'] },
      {
        name: 'InvalidClaim',
        code: 'INVALID_CLAIM',
        message: '"iss" did not match expected value',
        claim: 'iss',
        givenValue: 'test.issuer',
        expectedValue: ['prod.issuer', 'test.foobar']
      }
    ],
    [
      'subject',
      { clock, subject: 'test.subject' },
      { subject: 'prod.subject' },
      {
        name: 'InvalidClaim',
        code: 'INVALID_CLAIM',
        message: '"sub" did not match expected value',
        claim: 'sub',
        givenValue: 'test.subject',
        expectedValue: 'prod.subject'
      }
    ],
    [
      'audience string',
      { clock, audience: ['test.audience'] },
      { audience: 'prod.audience' },
      {
        name: 'InvalidClaim',
        code: 'INVALID_CLAIM',
        message: '"aud" did not match expected value',
        claim: 'aud',
        givenValue: ['test.audience'],
        expectedValue: 'prod.audience'
      }
    ],
    [
      'audience array',
      { clock, audience: 'test.audience' },
      { audience: [/^prod\./, 'stage.audience'] },
      {
        name: 'InvalidClaim',
        code: 'INVALID_CLAIM',
        message: '"aud" did not match expected value',
        claim: 'aud',
        givenValue: 'test.audience'
      }
    ],
    [
      'jwtId',
      { clock, jwtId: '43da3783-cea7-44c1-949b-bd7c807506e6' },
      { jwtId: '273c8860-722f-48c8-864d-e316ccf20f93' },
      {
        name: 'InvalidClaim',
        code: 'INVALID_CLAIM',
        message: '"jti" did not match expected value',
        claim: 'jti',
        givenValue: '43da3783-cea7-44c1-949b-bd7c807506e6',
        expectedValue: '273c8860-722f-48c8-864d-e316ccf20f93'
      }
    ]
  ]

  for (const [
    name,
    payloadOptions,
    verifyOptions,
    error
  ] of validateFailureOptions) {
    t.test(`validate ${name}`, async () => {
      const token = await jwt.sign({}, keyStore, payloadOptions)
      await assert.rejects(
        () => jwt.verify(token, keyStore, verifyOptions),
        error
      )
    })
  }
})

test('jwks support', async t => {
  const jwks = JSON.parse(
    await fs.readFile(new URL('./fixtures/jwks.json', import.meta.url), 'utf-8')
  )

  const publicJWKS = JSON.parse(
    await fs.readFile(
      new URL('./fixtures/public-jwks.json', import.meta.url),
      'utf-8'
    )
  )

  t.test('can create store from jwks', async () => {
    const keyStore = await createKeyStoreFromJWKS(jwks)
    const clock = new Date()
    const clockTimestamp = Math.floor(clock.getTime() / 1000)
    const token = await jwt.sign({}, keyStore, { clock })
    const result = await jwt.verify(token, keyStore)
    assert.deepStrictEqual(result, {
      payload: {
        iat: clockTimestamp
      },
      header: {
        typ: 'JWT',
        alg: keyStore.primaryKey().alg(),
        kid: keyStore.primaryKey().kid()
      }
    })
  })

  t.test('can export jwks', async () => {
    const keyStore = await createKeyStoreFromJWKS(jwks)
    assert.deepStrictEqual(keyStore.privateJWKS(), jwks)
    assert.deepStrictEqual(keyStore.publicJWKS(), publicJWKS)
  })

  t.test('cannot export private JWKS from importing public', async () => {
    const keyStore = await createKeyStoreFromJWKS(publicJWKS)
    assert.throws(() => keyStore.privateJWKS(), {
      name: 'InvalidSigningKey',
      code: 'INVALID_SIGNING_KEY'
    })
  })

  t.test('cannot import JWK if alg is missing', async () => {
    const jwks = JSON.parse(JSON.stringify(publicJWKS))
    delete jwks.keys[0].alg
    await assert.rejects(() => createKeyStoreFromJWKS(jwks), {
      name: 'UnsupportedAlgorithm',
      code: 'UNSUPPORTED_JWA_ALGORITHM',
      algorithm: undefined
    })
  })
})

test('algorithm support', async t => {
  /** @type {import('../src/index').JWAlgorithm[]} */
  const algorithms = [
    'HS256',
    'HS384',
    'HS512',
    'RS256',
    'RS384',
    'RS512',
    'PS256',
    'PS384',
    'PS512',
    'ES256',
    'ES384',
    'ES512',
    'EdDSA'
  ]
  for (const alg of algorithms) {
    t.test(`Can generate and verify key with ${alg}`, async () => {
      const keyStore = createKeyStore([await generate(alg)])
      const key = keyStore.primaryKey()
      const clock = new Date()
      const clockTimestamp = Math.floor(clock.getTime() / 1000)
      const token = await jwt.sign({}, keyStore, { clock })
      const result = await jwt.verify(token, keyStore)
      assert.deepStrictEqual(result, {
        payload: { iat: clockTimestamp },
        header: { alg: key.alg(), kid: key.kid(), typ: 'JWT' }
      })
    })
  }
  /** @type {import('../src/index').JWAlgorithm[]} */
  const rsAlgorithms = ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512']
  for (const alg of rsAlgorithms) {
    t.test(
      `Can generate and verify key with ${alg} modulus option`,
      async () => {
        const keyStore = createKeyStore([
          await generate(alg, { modulusLength: 4096 })
        ])
        const key = keyStore.primaryKey()
        const clock = new Date()
        const clockTimestamp = Math.floor(clock.getTime() / 1000)
        const token = await jwt.sign({}, keyStore, { clock })
        const result = await jwt.verify(token, keyStore)
        assert.deepStrictEqual(result, {
          payload: { iat: clockTimestamp },
          header: { alg: key.alg(), kid: key.kid(), typ: 'JWT' }
        })
      }
    )
  }
  /** @type {['EdDSA', { curve: 'Ed25519'|'Ed448' }][]} */
  const edAlgorithms = [
    ['EdDSA', { curve: 'Ed25519' }],
    ['EdDSA', { curve: 'Ed448' }]
  ]
  for (const [alg, options] of edAlgorithms) {
    t.test(
      `Can generate and verify key with ${alg} and curve ${options.curve}`,
      async () => {
        const keyStore = createKeyStore([await generate(alg, options)])
        const key = keyStore.primaryKey()
        console.log(key.privateJWK())
        console.log(key.publicJWK())
        const clock = new Date()
        const clockTimestamp = Math.floor(clock.getTime() / 1000)
        const token = await jwt.sign({}, keyStore, { clock })
        const result = await jwt.verify(token, keyStore)
        assert.deepStrictEqual(result, {
          payload: { iat: clockTimestamp },
          header: { alg: key.alg(), kid: key.kid(), typ: 'JWT' }
        })
      }
    )
  }
})

test('edge case errors', async t => {
  t.test('fails sign without proper keyStore', async () => {
    const key = await generate('HS256')
    // @ts-ignore
    await assert.rejects(() => jwt.sign({}, key), {
      name: 'TypeError',
      message: 'Invalid KeyStore'
    })
  })

  t.test('fails verify without proper keyStore', async () => {
    const key = await generate('HS256')
    // @ts-ignore
    await assert.rejects(() => jwt.verify({}, key), {
      name: 'TypeError',
      message: 'Invalid KeyStore'
    })
  })

  t.test('fails to create store if not an array of keys', async () => {
    // @ts-ignore
    assert.throws(() => createKeyStore(['key']), {
      name: 'TypeError',
      message: 'keys must be an array of Keys'
    })
    // @ts-ignore
    assert.throws(() => createKeyStore('key'), {
      name: 'TypeError',
      message: 'keys must be an array of Keys'
    })
  })

  t.test('fails to create store if empty array', async () => {
    assert.throws(() => createKeyStore([]), {
      name: 'RangeError',
      message: 'KeyStore must have at least 1 key'
    })
  })

  t.test(
    'fails to generate key with modulus length less than 2048',
    async () => {
      await assert.rejects(() => generate('RS256', { modulusLength: 1024 }), {
        name: 'InvalidModulusLength',
        code: 'INVALID_MODULUS_LENGTH'
      })
    }
  )

  t.test('fails to import invalid jwk kty', async () => {
    const key = await generate('ES256')
    const jwk = key.publicJWK()
    jwk.kty = 'foobar'
    await assert.rejects(() => createKeyFromJWK(jwk), {
      name: 'UnsupportedKeyType',
      code: 'UNSUPPORTED_JWK_KTY'
    })
  })

  t.test('fails to import invalid jwk alg', async () => {
    const key = await generate('ES256')
    const jwk = key.publicJWK()
    jwk.alg = 'foobar'
    await assert.rejects(() => createKeyFromJWK(jwk), {
      name: 'UnsupportedAlgorithm',
      code: 'UNSUPPORTED_JWA_ALGORITHM'
    })
  })

  t.test('fails to validate if token is not a string', async () => {
    const keyStore = createKeyStore([await generate('ES256')])
    // @ts-ignore next
    await assert.rejects(() => jwt.verify(1, keyStore), {
      name: 'MalformedJWT',
      code: 'MALFORMED_JWT',
      message: 'JWT not a string'
    })
  })

  t.test('fails to validate if not formatted into three parts', async () => {
    const keyStore = createKeyStore([await generate('ES256')])
    const token = 'foo.bar.baz.tar'
    await assert.rejects(() => jwt.verify(token, keyStore), {
      name: 'MalformedJWT',
      code: 'MALFORMED_JWT',
      message: 'Not in valid JWT format'
    })
  })

  t.test('fails if header is not valid json', async () => {
    const keyStore = createKeyStore([await generate('ES256')])
    const token = [
      Buffer.from('notjson').toString('base64url'),
      Buffer.from('{}').toString('base64url'),
      ''
    ].join('.')
    await assert.rejects(() => jwt.verify(token, keyStore), {
      name: 'InvalidJSON',
      code: 'INVALID_JSON',
      message: 'Invalid JSON in JWT header'
    })
  })

  t.test('fails if header is not an object', async () => {
    const keyStore = createKeyStore([await generate('ES256')])
    const token = [
      Buffer.from('"notobject"').toString('base64url'),
      Buffer.from('{}').toString('base64url'),
      ''
    ].join('.')
    await assert.rejects(() => jwt.verify(token, keyStore), {
      name: 'MalformedJWT',
      code: 'MALFORMED_JWT',
      message: 'JWT header not an object'
    })
  })

  t.test('fails if header does not contain typ:JWT', async () => {
    const keyStore = createKeyStore([await generate('ES256')])
    const token = [
      Buffer.from('{}').toString('base64url'),
      Buffer.from('{}').toString('base64url'),
      ''
    ].join('.')
    await assert.rejects(() => jwt.verify(token, keyStore), {
      name: 'MalformedJWT',
      code: 'MALFORMED_JWT',
      message: 'JWT header missing "typ":"JWT"'
    })
  })

  t.test('fails if algorithm is not supported algorithm', async () => {
    const keyStore = createKeyStore([await generate('ES256')])
    const token = [
      Buffer.from('{"typ":"JWT"}').toString('base64url'),
      Buffer.from('{}').toString('base64url'),
      ''
    ].join('.')
    await assert.rejects(() => jwt.verify(token, keyStore), {
      name: 'InvalidAlgorithm',
      code: 'INVALID_ALGORITHM',
      message: 'Invalid alg in JWT header'
    })
  })

  t.test('fails if kid is not a string', async () => {
    const keyStore = createKeyStore([await generate('ES256')])
    const token = [
      Buffer.from('{"typ":"JWT","alg":"ES256","kid":[]}').toString('base64url'),
      Buffer.from('{}').toString('base64url'),
      ''
    ].join('.')
    await assert.rejects(() => jwt.verify(token, keyStore), {
      name: 'InvalidKeyId',
      code: 'INVALID_KEY_ID',
      message: 'Invalid kid in token header'
    })
  })

  t.test('fails if payload is not an object', async () => {
    const keyStore = createKeyStore([await generate('ES256')])
    const token = [
      Buffer.from('{"typ":"JWT","alg":"ES256","kid":"a"}').toString(
        'base64url'
      ),
      Buffer.from('[]').toString('base64url'),
      ''
    ].join('.')
    await assert.rejects(() => jwt.verify(token, keyStore), {
      name: 'MalformedJWT',
      code: 'MALFORMED_JWT',
      message: 'JWT payload not an object'
    })
  })

  t.test('fails to import cryptoKey if unsupported algorithm', async () => {
    const key = await generate('ES256')
    await assert.rejects(
      // @ts-ignore
      () => createKeyFromCryptoKey(key.signingKey(), { alg: 'ES257' }),
      {
        name: 'UnsupportedAlgorithm',
        code: 'UNSUPPORTED_JWA_ALGORITHM',
        message: 'Unsupported algorithm: "ES257"'
      }
    )
  })

  t.test(
    'fails to import cryptoKey if HMAC JWK and missing secret',
    async () => {
      const prevKey = await generate('HS256')
      const key = await createKeyFromJWK(prevKey.privateJWK())
      const publicJWK = key.publicJWK()
      await assert.rejects(() => createKeyFromJWK(publicJWK), {
        name: 'TypeError',
        code: 'ERR_CRYPTO_INVALID_JWK',
        message: 'Invalid JWK secret key format'
      })
    }
  )
})
