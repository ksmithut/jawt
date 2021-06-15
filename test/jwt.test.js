import assert from 'assert'
import fs from 'fs'
import tap from 'tap'
import jsonwebtoken from 'jsonwebtoken'
import { jwt, fromJWKS } from '../src/index.js'

tap.test('jwt', async tap => {
  const keyStore = await getKeyStore()

  await tap.test('signs and verifies jwt', async tap => {
    const now = new Date(1609025188322)
    const token = await jwt.sign({}, keyStore, { now })
    assert.strictEqual(typeof token, 'string', 'token was not a string')
    assert.deepStrictEqual(await jwt.verify(token, keyStore), {
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
    assert.deepStrictEqual(await jwt.verify(token, keyStore), {
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
    assert.deepStrictEqual(await jwt.verify(token, keyStore), {
      iat: 1609025188
    })
  })

  await tap.test('iss', async tap => {
    await tap.test('verifies claim', async () => {
      const now = new Date(1609025188322)
      const token = await jwt.sign({}, keyStore, { now, issuer: 'iss-test' })
      assert.deepStrictEqual(
        await jwt.verify(token, keyStore, { issuer: 'iss-test' }),
        { iss: 'iss-test', iat: 1609025188 }
      )
      assert.deepStrictEqual(
        await jwt.verify(token, keyStore, { issuer: ['foo', 'iss-test'] }),
        { iss: 'iss-test', iat: 1609025188 }
      )
    })
    await tap.test('fails claim', async () => {
      const now = new Date(1609025188322)
      const token = await jwt.sign({}, keyStore, { now, issuer: 'iss-test' })
      await assert.rejects(jwt.verify(token, keyStore, { issuer: 'foo' }), {
        message: 'Given "iss" was not accepted',
        code: 'ISSUER_NOT_ACCEPTED'
      })
      await assert.rejects(jwt.verify(token, keyStore, { issuer: ['foo'] }), {
        message: 'Given "iss" was not accepted',
        code: 'ISSUER_NOT_ACCEPTED'
      })
    })
    await tap.test('fails invalid claim', async () => {
      const now = new Date(1609025188322)
      const token = await jwt.sign({ iss: ['invalid'] }, keyStore, { now })
      await assert.rejects(
        jwt.verify(token, keyStore, { issuer: 'iss-test' }),
        { message: 'Invalid claim: iss', code: 'INVALID_CLAIM' }
      )
    })
  })

  await tap.test('sub', async tap => {
    await tap.test('verifies claim', async () => {
      const now = new Date(1609025188322)
      const token = await jwt.sign({}, keyStore, { now, subject: 'sub-test' })
      assert.deepStrictEqual(
        await jwt.verify(token, keyStore, { subject: 'sub-test' }),
        { sub: 'sub-test', iat: 1609025188 }
      )
    })
    await tap.test('fails claim', async () => {
      const now = new Date(1609025188322)
      const token = await jwt.sign({}, keyStore, { now, subject: 'sub-test' })
      assert.rejects(jwt.verify(token, keyStore, { subject: 'foo' }), {
        message: 'Given "sub" was not accepted',
        code: 'SUBJECT_NOT_ACCEPTED'
      })
    })
    await tap.test('fails invalid claim', async () => {
      const now = new Date(1609025188322)
      const token = await jwt.sign({ sub: ['sub-test'] }, keyStore, { now })
      await assert.rejects(
        jwt.verify(token, keyStore, { subject: 'sub-test' }),
        { message: 'Invalid claim: sub', code: 'INVALID_CLAIM' }
      )
    })
  })

  await tap.test('aud', async tap => {
    await tap.test('verifies claim', async () => {
      const now = new Date(1609025188322)
      const token = await jwt.sign({}, keyStore, { now, audience: 'aud-test' })
      assert.deepStrictEqual(
        await jwt.verify(token, keyStore, { audience: 'aud-test' }),
        { aud: 'aud-test', iat: 1609025188 }
      )
      assert.deepStrictEqual(
        await jwt.verify(token, keyStore, { audience: ['foo', 'aud-test'] }),
        { aud: 'aud-test', iat: 1609025188 }
      )
      assert.deepStrictEqual(
        await jwt.verify(token, keyStore, { audience: /^aud-/ }),
        { aud: 'aud-test', iat: 1609025188 }
      )
      assert.deepStrictEqual(
        await jwt.verify(token, keyStore, { audience: ['foo', /^aud-/] }),
        { aud: 'aud-test', iat: 1609025188 }
      )
    })
    await tap.test('fails claim', async () => {
      const now = new Date(1609025188322)
      const token = await jwt.sign({}, keyStore, { now, audience: 'aud-test' })
      await assert.rejects(jwt.verify(token, keyStore, { audience: 'foo' }), {
        message: 'Given "aud" was not accepted',
        code: 'AUDIENCE_NOT_ACCEPTED'
      })
      await assert.rejects(jwt.verify(token, keyStore, { audience: ['foo'] }), {
        message: 'Given "aud" was not accepted',
        code: 'AUDIENCE_NOT_ACCEPTED'
      })
    })
    await tap.test('fails invalid claim', async () => {
      const now = new Date(1609025188322)
      const token = await jwt.sign({ aud: 5 }, keyStore, { now })
      await assert.rejects(
        jwt.verify(token, keyStore, { audience: 'aud-test' }),
        { message: 'Invalid claim: aud', code: 'INVALID_CLAIM' }
      )
    })
  })

  await tap.test('exp', async tap => {
    await tap.test('verifies claim with expiresIn', async () => {
      const now = new Date(1609025188322)
      const token = await jwt.sign({}, keyStore, { now, expiresIn: 60 })
      assert.deepStrictEqual(
        await jwt.verify(token, keyStore, {
          now: new Date(now.getTime() + 30_000)
        }),
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
      assert.deepStrictEqual(
        await jwt.verify(token1, keyStore, {
          now: new Date(now.getTime() + 30_000)
        }),
        { exp: 1609025248, iat: 1609025188 }
      )
      assert.deepStrictEqual(
        await jwt.verify(token2, keyStore, {
          now: new Date(now.getTime() + 30_000)
        }),
        { exp: 1609025248, iat: 1609025188 }
      )
    })
    await tap.test('fails claim', async () => {
      const now = new Date(1609025188322)
      const token = await jwt.sign({}, keyStore, { now, expiresIn: 60 })
      await assert.rejects(
        jwt.verify(token, keyStore, {
          now: new Date(now.getTime() + 61_000)
        }),
        { code: 'TOKEN_EXPIRED', message: 'Token has expired' }
      )
    })
    await tap.test('fails invalid claim', async () => {
      const now = new Date(1609025188322)
      const token = await jwt.sign({ exp: '500' }, keyStore, { now })
      await assert.rejects(jwt.verify(token, keyStore, {}), {
        code: 'INVALID_CLAIM',
        message: 'Invalid claim: exp'
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
      assert.deepStrictEqual(
        await jwt.verify(token1, keyStore, {
          now: new Date(now.getTime() + 61_000)
        }),
        { nbf: 1609025248, iat: 1609025188 }
      )
      assert.deepStrictEqual(
        await jwt.verify(token2, keyStore, {
          now: new Date(now.getTime() + 61_000)
        }),
        { nbf: 1609025248, iat: 1609025188 }
      )
    })
    await tap.test('fails claim', async () => {
      const now = new Date(1609025188322)
      const token = await jwt.sign({}, keyStore, {
        now,
        notBefore: new Date(now.getTime() + 60_000)
      })
      await assert.rejects(
        jwt.verify(token, keyStore, {
          now: new Date(now.getTime() + 30_000)
        }),
        { code: 'NOT_BEFORE', message: 'Token is not yet active' }
      )
    })
    await tap.test('fails invalid claim', async () => {
      const now = new Date(1609025188322)
      const token = await jwt.sign({ nbf: '500' }, keyStore)
      await assert.rejects(
        jwt.verify(token, keyStore, {
          now: new Date(now.getTime() + 30_000)
        }),
        { code: 'INVALID_CLAIM', message: 'Invalid claim: nbf' }
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
      assert.deepStrictEqual(
        await jwt.verify(token, keyStore, {
          now: new Date(now.getTime() + 30_000),
          maxAge: 60
        }),
        { iat: 1609025188 }
      )
    })
    await tap.test('verifies maxAge', async () => {
      const now = new Date(1609025188322)
      const token = await jwt.sign({}, keyStore, { issuedAt: 1609025188 })
      assert.deepStrictEqual(
        await jwt.verify(token, keyStore, {
          now: new Date(now.getTime() + 30_000),
          maxAge: 60
        }),
        { iat: 1609025188 }
      )
    })
    await tap.test('fails maxAge', async () => {
      const now = new Date(1609025188322)
      const token = await jwt.sign({}, keyStore, { now })
      await assert.rejects(
        jwt.verify(token, keyStore, {
          now: new Date(now.getTime() + 30_000),
          maxAge: 20
        }),
        { code: 'AGE_NOT_ACCEPTABLE', message: 'Token is too old' }
      )
    })
    await tap.test('invalid claim if no iat and maxAge send', async () => {
      const token = await jwt.sign({}, keyStore, { issuedAt: false })
      await assert.rejects(jwt.verify(token, keyStore, { maxAge: 20 }), {
        code: 'INVALID_CLAIM',
        message: 'Invalid claim: iat'
      })
    })
    await tap.test('fails invalid claim', async () => {
      const token = await jwt.sign({ iat: '500' }, keyStore, {
        issuedAt: false
      })
      await assert.rejects(jwt.verify(token, keyStore), {
        code: 'INVALID_CLAIM',
        message: 'Invalid claim: iat'
      })
    })
  })
})

async function getKeyStore () {
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
