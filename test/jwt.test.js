import assert from 'assert'
import fs from 'fs'
import tap from 'tap'
import jsonwebtoken from 'jsonwebtoken'
import {
  jwt,
  fromJWKS,
  errors,
  generate,
  createKeyStore
} from '../src/index.js'

tap.test('jwt', async tap => {
  const keyStore = await getKeyStore()

  await tap.test('signs and verifies jwt', async tap => {
    const now = new Date(1609025188322)
    const token = await jwt.sign({}, keyStore, { now })
    assert.strictEqual(typeof token, 'string', 'token was not a string')
    await assertVerifySuccess(token, keyStore, undefined, {
      iat: 1609025188
    })
  })

  await tap.test('external library can verify jwt', async () => {
    const now = new Date(1609025188322)
    const token = await jwt.sign({}, keyStore, { now })
    assert.strictEqual(typeof token, 'string', 'token was not a string')
    assert.deepStrictEqual(await verifyExternal(token, keyStore.primaryKey()), {
      iat: 1609025188
    })
  })

  await tap.test('can verify jwt signed by external library', async () => {
    const now = new Date(1609025188322)
    const token = await signExternal(
      { iat: Math.round(now.getTime() / 1000) },
      keyStore.primaryKey()
    )
    await assertVerifySuccess(token, keyStore, undefined, {
      iat: 1609025188
    })
  })

  await tap.test('tries both keys when kid is not present', async () => {
    const now = new Date(1609025188322)
    const token = await signExternal(
      { iat: Math.round(now.getTime() / 1000) },
      keyStore.keys()[1],
      { keyid: 'wrongkid' }
    )
    await assertVerifySuccess(token, keyStore, undefined, {
      iat: 1609025188
    })
  })

  await tap.test('fails if the kid matches, but alg does not', async () => {
    const key = (await generate('RS384')).jwk(true)
    key.kid = keyStore.primaryKey().kid
    const altKeyStore = await fromJWKS({ keys: [key] })
    const token = await jwt.sign({}, altKeyStore)
    await assertVerifyFailure(
      token,
      keyStore,
      undefined,
      errors.AlgorithmMismatch,
      {
        code: 'ALGORITHM_MISMATCH',
        message: 'JWT algorithm did not match keyStore algorithm'
      }
    )
  })

  await tap.test(
    'fails if the kid matches, but produces invalid signature',
    async () => {
      const key = (await generate('ES256')).jwk(true)
      key.kid = keyStore.primaryKey().kid
      const altKeyStore = await fromJWKS({ keys: [key] })
      const token = await jwt.sign({}, altKeyStore)
      await assertVerifyFailure(
        token,
        keyStore,
        undefined,
        errors.InvalidSignature,
        {
          code: 'INVALID_SIGNATURE',
          message: 'Invalid Signature'
        }
      )
    }
  )

  await tap.test('fails if token was not signed by known key', async () => {
    const altKeyStore = createKeyStore([await generate('ES256')])
    const token = await jwt.sign({}, altKeyStore)
    await assertVerifyFailure(
      token,
      keyStore,
      undefined,
      errors.InvalidSignature,
      {
        code: 'INVALID_SIGNATURE',
        message: 'Invalid Signature'
      }
    )
  })

  await tap.test('iss', async tap => {
    await tap.test('verifies claim', async () => {
      const now = new Date(1609025188322)
      const token = await jwt.sign({}, keyStore, { now, issuer: 'iss-test' })
      await assertVerifySuccess(
        token,
        keyStore,
        { issuer: 'iss-test' },
        { iss: 'iss-test', iat: 1609025188 }
      )
      await assertVerifySuccess(
        token,
        keyStore,
        { issuer: ['foo', 'iss-test'] },
        { iss: 'iss-test', iat: 1609025188 }
      )
    })
    await tap.test('fails claim', async () => {
      const now = new Date(1609025188322)
      const token = await jwt.sign({}, keyStore, { now, issuer: 'iss-test' })
      await assertVerifyFailure(
        token,
        keyStore,
        { issuer: 'foo' },
        errors.IssuerNotAccepted,
        {
          message: 'Given "iss" was not accepted',
          code: 'ISSUER_NOT_ACCEPTED'
        }
      )
      await assertVerifyFailure(
        token,
        keyStore,
        { issuer: ['foo'] },
        errors.IssuerNotAccepted,
        {
          message: 'Given "iss" was not accepted',
          code: 'ISSUER_NOT_ACCEPTED'
        }
      )
    })
    await tap.test('fails invalid claim', async () => {
      const now = new Date(1609025188322)
      const token = await jwt.sign({ iss: ['invalid'] }, keyStore, { now })
      await assertVerifyFailure(
        token,
        keyStore,
        { issuer: 'iss-test' },
        errors.InvalidClaim,
        { message: 'Invalid claim: iss', claim: 'iss', code: 'INVALID_CLAIM' }
      )
    })
  })

  await tap.test('sub', async tap => {
    await tap.test('verifies claim', async () => {
      const now = new Date(1609025188322)
      const token = await jwt.sign({}, keyStore, { now, subject: 'sub-test' })
      await assertVerifySuccess(
        token,
        keyStore,
        { subject: 'sub-test' },
        { sub: 'sub-test', iat: 1609025188 }
      )
    })
    await tap.test('fails claim', async () => {
      const now = new Date(1609025188322)
      const token = await jwt.sign({}, keyStore, { now, subject: 'sub-test' })
      await assertVerifyFailure(
        token,
        keyStore,
        { subject: 'foo' },
        errors.SubjectNotAccepted,
        {
          message: 'Given "sub" was not accepted',
          code: 'SUBJECT_NOT_ACCEPTED'
        }
      )
    })
    await tap.test('fails invalid claim', async () => {
      const now = new Date(1609025188322)
      const token = await jwt.sign({ sub: ['sub-test'] }, keyStore, { now })
      await assertVerifyFailure(
        token,
        keyStore,
        { subject: 'sub-test' },
        errors.InvalidClaim,
        { message: 'Invalid claim: sub', claim: 'sub', code: 'INVALID_CLAIM' }
      )
    })
  })

  await tap.test('aud', async tap => {
    await tap.test('verifies claim', async () => {
      const now = new Date(1609025188322)
      const token = await jwt.sign({}, keyStore, { now, audience: 'aud-test' })
      const expectedPayload = { aud: 'aud-test', iat: 1609025188 }
      await assertVerifySuccess(
        token,
        keyStore,
        { audience: 'aud-test' },
        expectedPayload
      )
      await assertVerifySuccess(
        token,
        keyStore,
        { audience: ['foo', 'aud-test'] },
        expectedPayload
      )
      await assertVerifySuccess(
        token,
        keyStore,
        { audience: /^aud-/ },
        expectedPayload
      )
      await assertVerifySuccess(
        token,
        keyStore,
        { audience: ['foo', /^aud-/] },
        expectedPayload
      )
    })
    await tap.test('verifies array claim', async () => {
      const now = new Date(1609025188322)
      const token = await jwt.sign({}, keyStore, {
        now,
        audience: ['aud-test1', 'aud-test2']
      })
      const expectedPayload = {
        aud: ['aud-test1', 'aud-test2'],
        iat: 1609025188
      }
      await assertVerifySuccess(
        token,
        keyStore,
        { audience: 'aud-test1' },
        expectedPayload
      )
      await assertVerifySuccess(
        token,
        keyStore,
        { audience: ['aud-test2'] },
        expectedPayload
      )
      await assertVerifySuccess(
        token,
        keyStore,
        { audience: /^aud-test\d$/ },
        expectedPayload
      )
      await assertVerifySuccess(
        token,
        keyStore,
        { audience: ['foo', /^aud-test\d$/] },
        expectedPayload
      )
    })
    await tap.test('fails claim', async () => {
      const now = new Date(1609025188322)
      const token = await jwt.sign({}, keyStore, { now, audience: 'aud-test' })
      await assertVerifyFailure(
        token,
        keyStore,
        { audience: 'foo' },
        errors.AudienceNotAccepted,
        {
          message: 'Given "aud" was not accepted',
          code: 'AUDIENCE_NOT_ACCEPTED'
        }
      )
      await assertVerifyFailure(
        token,
        keyStore,
        { audience: ['foo'] },
        errors.AudienceNotAccepted,
        {
          message: 'Given "aud" was not accepted',
          code: 'AUDIENCE_NOT_ACCEPTED'
        }
      )
    })
    await tap.test('fails invalid claim', async () => {
      const now = new Date(1609025188322)
      const token = await jwt.sign({ aud: 5 }, keyStore, { now })
      await assertVerifyFailure(
        token,
        keyStore,
        { audience: 'aud-test' },
        errors.InvalidClaim,
        { message: 'Invalid claim: aud', claim: 'aud', code: 'INVALID_CLAIM' }
      )
    })
  })

  await tap.test('jti', async tap => {
    await tap.test('verifies claim', async () => {
      const now = new Date(1609025188322)
      const jwtId = 'b1d37d04-dea3-4e90-9c64-c58ff7249475'
      const token = await jwt.sign({}, keyStore, { now, jwtId })
      const expectedPayload = {
        jti: 'b1d37d04-dea3-4e90-9c64-c58ff7249475',
        iat: 1609025188
      }
      await assertVerifySuccess(token, keyStore, { jwtId }, expectedPayload)
    })
    await tap.test('fails claim', async () => {
      const jwtId = 'b1d37d04-dea3-4e90-9c64-c58ff7249475'
      const token = await jwt.sign({}, keyStore, { jwtId })
      await assertVerifyFailure(
        token,
        keyStore,
        { jwtId: 'foo' },
        errors.JwtIdNotAccepted,
        {
          message: 'Given "jti" was not accepted',
          code: 'JWT_ID_NOT_ACCEPTED'
        }
      )
    })
    await tap.test('fails invalid claim', async () => {
      const jwtId = 'b1d37d04-dea3-4e90-9c64-c58ff7249475'
      const token = await jwt.sign({ jwtId: [jwtId] }, keyStore, {})
      await assertVerifyFailure(
        token,
        keyStore,
        { jwtId },
        errors.InvalidClaim,
        {
          message: 'Invalid claim: jti',
          claim: 'jti',
          code: 'INVALID_CLAIM'
        }
      )
    })
  })

  await tap.test('exp', async tap => {
    await tap.test('verifies claim with expiresIn', async () => {
      const now = new Date(1609025188322)
      const token = await jwt.sign({}, keyStore, { now, expiresIn: 60 })
      await assertVerifySuccess(
        token,
        keyStore,
        { now: new Date(now.getTime() + 30_000) },
        { exp: 1609025248, iat: 1609025188 }
      )
    })
    await tap.test('verifies claim with expiresAt', async () => {
      const now = new Date(1609025188322)
      const token1 = await jwt.sign({}, keyStore, {
        now,
        expiresAt: new Date(now.getTime() + 60_000)
      })
      const token2 = await jwt.sign({}, keyStore, {
        now,
        expiresAt: Math.round((now.getTime() + 60_000) / 1000)
      })
      await assertVerifySuccess(
        token1,
        keyStore,
        { now: new Date(now.getTime() + 30_000) },
        { exp: 1609025248, iat: 1609025188 }
      )
      await assertVerifySuccess(
        token2,
        keyStore,
        { now: new Date(now.getTime() + 30_000) },
        { exp: 1609025248, iat: 1609025188 }
      )
    })
    await tap.test('fails claim', async () => {
      const now = new Date(1609025188322)
      const token = await jwt.sign({}, keyStore, { now, expiresIn: 60 })
      await assertVerifyFailure(
        token,
        keyStore,
        { now: new Date(now.getTime() + 61_000) },
        errors.TokenExpired,
        { code: 'TOKEN_EXPIRED', message: 'Token has expired' }
      )
    })
    await tap.test('fails invalid claim', async () => {
      const now = new Date(1609025188322)
      const token = await jwt.sign({ exp: '500' }, keyStore, { now })
      await assertVerifyFailure(token, keyStore, {}, errors.InvalidClaim, {
        code: 'INVALID_CLAIM',
        message: 'Invalid claim: exp',
        claim: 'exp'
      })
    })
  })

  await tap.test('nbf', async tap => {
    await tap.test('verifies claim', async () => {
      const now = new Date(1609025188322)
      const token1 = await jwt.sign({}, keyStore, {
        now,
        notBefore: new Date(now.getTime() + 60_000)
      })
      const token2 = await jwt.sign({}, keyStore, {
        now,
        notBefore: Math.round((now.getTime() + 60_000) / 1000)
      })
      await assertVerifySuccess(
        token1,
        keyStore,
        { now: new Date(now.getTime() + 61_000) },
        { nbf: 1609025248, iat: 1609025188 }
      )
      await assertVerifySuccess(
        token2,
        keyStore,
        { now: new Date(now.getTime() + 61_000) },
        { nbf: 1609025248, iat: 1609025188 }
      )
    })
    await tap.test('fails claim', async () => {
      const now = new Date(1609025188322)
      const token = await jwt.sign({}, keyStore, {
        now,
        notBefore: new Date(now.getTime() + 60_000)
      })
      await assertVerifyFailure(
        token,
        keyStore,
        { now: new Date(now.getTime() + 30_000) },
        errors.NotBefore,
        { code: 'NOT_BEFORE', message: 'Token is not yet active' }
      )
    })
    await tap.test('fails invalid claim', async () => {
      const now = new Date(1609025188322)
      const token = await jwt.sign({ nbf: '500' }, keyStore)
      await assertVerifyFailure(
        token,
        keyStore,
        { now: new Date(now.getTime() + 30_000) },
        errors.InvalidClaim,
        { code: 'INVALID_CLAIM', message: 'Invalid claim: nbf', claim: 'nbf' }
      )
    })
  })

  await tap.test('iat', async tap => {
    await tap.test('includes iat by default', async () => {
      const nowTimestamp = Math.round(new Date().getTime() / 1000)
      const token = await jwt.sign({}, keyStore)
      const payload = await jwt.verify(token, keyStore)
      const thenTimestamp = Math.round(new Date().getTime() / 1000)
      assert.ok(payload.iat >= nowTimestamp)
      assert.ok(payload.iat <= thenTimestamp)
      assert.deepStrictEqual(Object.keys(payload), ['iat'])
    })
    await tap.test('can be disabled', async () => {
      const token = await jwt.sign({}, keyStore, { issuedAt: false })
      const payload = await jwt.verify(token, keyStore)
      assert.deepStrictEqual(payload, {})
    })
    await tap.test('verifies maxAge', async () => {
      const now = new Date(1609025188322)
      const token = await jwt.sign({}, keyStore, { issuedAt: now })
      assertVerifySuccess(
        token,
        keyStore,
        { now: new Date(now.getTime() + 30_000), maxAge: 60 },
        { iat: 1609025188 }
      )
    })
    await tap.test('verifies maxAge', async () => {
      const now = new Date(1609025188322)
      const token = await jwt.sign({}, keyStore, { issuedAt: 1609025188 })
      assertVerifySuccess(
        token,
        keyStore,
        { now: new Date(now.getTime() + 30_000), maxAge: 60 },
        { iat: 1609025188 }
      )
    })
    await tap.test('fails maxAge', async () => {
      const now = new Date(1609025188322)
      const token = await jwt.sign({}, keyStore, { now })
      await assertVerifyFailure(
        token,
        keyStore,
        { now: new Date(now.getTime() + 30_000), maxAge: 20 },
        errors.AgeNotAccepted,
        { code: 'AGE_NOT_ACCEPTED', message: 'Token is too old' }
      )
    })
    await tap.test('invalid claim if no iat and maxAge send', async () => {
      const token = await jwt.sign({}, keyStore, { issuedAt: false })
      await assertVerifyFailure(
        token,
        keyStore,
        { maxAge: 20 },
        errors.InvalidClaim,
        {
          code: 'INVALID_CLAIM',
          message: 'Invalid claim: iat',
          claim: 'iat'
        }
      )
    })
    await tap.test('fails invalid claim', async () => {
      const token = await jwt.sign({ iat: '500' }, keyStore, {
        issuedAt: false
      })
      await assertVerifyFailure(
        token,
        keyStore,
        undefined,
        errors.InvalidClaim,
        {
          code: 'INVALID_CLAIM',
          message: 'Invalid claim: iat',
          claim: 'iat'
        }
      )
    })
  })

  await tap.test('malformed jwt', async tap => {
    await tap.test('too many parts', async () => {
      const now = new Date(1609025188322)
      const token = await jwt.sign({}, keyStore, { now })
      await assertVerifyFailure(
        `${token}.foo`,
        keyStore,
        undefined,
        errors.MalformedJWT,
        {
          code: 'MALFORMED_JWT',
          message: 'Malformed JWT'
        }
      )
    })

    await tap.test('too few parts', async () => {
      const token = (await jwt.sign({}, keyStore)).split('.', 2).join('.')
      await assertVerifyFailure(
        token,
        keyStore,
        undefined,
        errors.MalformedJWT,
        {
          code: 'MALFORMED_JWT',
          message: 'Malformed JWT'
        }
      )
    })

    await tap.test('invalid JSON in header', async () => {
      const [header, payload, signature] = (await jwt.sign({}, keyStore)).split(
        '.'
      )
      const token = `${header}123.${payload}.${signature}`
      await assertVerifyFailure(
        token,
        keyStore,
        undefined,
        errors.InvalidJSON,
        {
          code: 'INVALID_JSON',
          message: 'Invalid JSON in header',
          type: 'header'
        }
      )
    })

    await tap.test('invalid JSON in payload', async () => {
      const [header, payload, signature] = (await jwt.sign({}, keyStore)).split(
        '.'
      )
      const token = `${header}.${payload}123.${signature}`
      await assertVerifyFailure(
        token,
        keyStore,
        undefined,
        errors.InvalidJSON,
        {
          code: 'INVALID_JSON',
          message: 'Invalid JSON in payload',
          type: 'payload'
        }
      )
    })

    await tap.test('non-object header', async () => {
      const [, payload, signature] = (await jwt.sign({}, keyStore)).split('.')
      const header = btoa(JSON.stringify('test'))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/g, '')
      const token = `${header}.${payload}.${signature}`
      await assertVerifyFailure(
        token,
        keyStore,
        undefined,
        errors.MalformedJWT,
        {
          code: 'MALFORMED_JWT',
          message: 'Malformed JWT'
        }
      )
    })

    await tap.test('non-object payload', async () => {
      const [header, , signature] = (await jwt.sign({}, keyStore)).split('.')
      const payload = btoa(JSON.stringify('test'))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/g, '')
      const token = `${header}.${payload}.${signature}`
      await assertVerifyFailure(
        token,
        keyStore,
        undefined,
        errors.MalformedJWT,
        {
          code: 'MALFORMED_JWT',
          message: 'Malformed JWT'
        }
      )
    })

    await tap.test('non-string kid', async () => {
      const [, payload, signature] = (await jwt.sign({}, keyStore)).split('.')
      const header = btoa(JSON.stringify({ kid: ['id'] }))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/g, '')
      const token = `${header}.${payload}.${signature}`
      await assertVerifyFailure(
        token,
        keyStore,
        undefined,
        errors.InvalidKeyId,
        {
          code: 'INVALID_KEY_ID',
          message: 'Invalid kid in token header'
        }
      )
    })
    await tap.test('non-string alg', async () => {
      const [, payload, signature] = (await jwt.sign({}, keyStore)).split('.')
      const header = btoa(JSON.stringify({ alg: ['HS256'] }))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/g, '')
      const token = `${header}.${payload}.${signature}`
      await assertVerifyFailure(
        token,
        keyStore,
        undefined,
        errors.InvalidAlgorithm,
        {
          code: 'INVALID_ALGORITHM',
          message: 'Invalid alg in token header'
        }
      )
    })
  })
})

async function getKeyStore () {
  // @ts-ignore
  const filepath = new URL('./fixtures/jwks.json', import.meta.url)
  const jwks = JSON.parse(await fs.promises.readFile(filepath, 'utf8'))
  return fromJWKS(jwks)
}

/**
 * @param {string} token
 * @param {import('../src/key').Key} key
 * @param {import('jsonwebtoken').VerifyOptions} [options]
 */
async function verifyExternal (token, key, options = {}) {
  const verifyingKey = Buffer.from(await key.verifyingKey())
  return jsonwebtoken.verify(token, verifyingKey, {
    algorithms: [key.alg],
    ...options
  })
}

/**
 * @param {object} payload
 * @param {import('../src/key').Key} key
 * @param {import('jsonwebtoken').SignOptions} options
 */
async function signExternal (payload, key, options = {}) {
  const signingKey = Buffer.from(await key.signingKey())
  return jsonwebtoken.sign(payload, signingKey, {
    algorithm: key.alg,
    keyid: key.kid,
    ...options
  })
}

/**
 * @param {string} token
 * @param {import('../src/key-store').KeyStore} keyStore
 * @param {import('../src/jwt').VerifyOptions|undefined} options
 * @param {any} expectedPayload
 */
async function assertVerifySuccess (token, keyStore, options, expectedPayload) {
  assert.deepStrictEqual(
    await jwt.verify(token, keyStore, options),
    expectedPayload
  )
  assert.deepStrictEqual(await jwt.verifySafe(token, keyStore, options), {
    success: true,
    payload: expectedPayload
  })
}

/**
 * @param {string} token
 * @param {import('../src/key-store').KeyStore} keyStore
 * @param {import('../src/jwt').VerifyOptions|undefined} options
 * @param {function} errorType
 * @param {{[key: string]: any}} errorProps
 */
async function assertVerifyFailure (
  token,
  keyStore,
  options,
  errorType,
  errorProps
) {
  await assert.rejects(
    jwt.verify(token, keyStore, options),
    errors.JsonWebTokenError
  )
  await assert.rejects(jwt.verify(token, keyStore, options), errorType)
  await assert.rejects(jwt.verify(token, keyStore, options), errorProps)
  await assert.doesNotReject(jwt.verifySafe(token, keyStore, options))
  const result = await jwt.verifySafe(token, keyStore, options)
  assert.strictEqual(
    result.success,
    false,
    'verifySafe was successful when it was supposed to fail'
  )
  assert.strictEqual(
    // @ts-ignore
    result.error instanceof errors.JsonWebTokenError,
    true,
    'verifySafe error was not a JsonWebTokenError'
  )
  assert.strictEqual(
    // @ts-ignore
    result.error instanceof errorType,
    true,
    `verifySafe error was not a ${errorType.name}`
  )
  Object.entries(errorProps).forEach(([key, value]) => {
    assert.deepStrictEqual(
      value,
      // @ts-ignore
      result.error[key],
      `verifySafe().error.${key} did not get expected value ${value}`
    )
  })
}
