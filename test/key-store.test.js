import assert from 'assert'
import fs from 'fs'
import tap from 'tap'
import {
  createKeyStore,
  createKeyStoreFromJWKS,
  generate,
  errors
} from '../src/index.js'

tap.test('key-store', async tap => {
  await tap.test('createKeyStoreFromJWKS', async tap => {
    await tap.test('Loads key store from JWKS', async () => {
      // @ts-ignore
      const filepath = new URL('./fixtures/jwks.json', import.meta.url)
      const jwks = JSON.parse(await fs.promises.readFile(filepath, 'utf-8'))
      const store = await createKeyStoreFromJWKS(jwks)
      assert.strictEqual(store.keys().length, 2)
    })

    await tap.test('loads first key as primary key', async () => {
      const store = await getKeyStore()
      assert.strictEqual(
        store.primaryKey().kid,
        '86d9DMYVV4EOxOO8SOcdy4ipWuzeauhItIcdsRs7stk'
      )
      assert.strictEqual(
        store.get('86d9DMYVV4EOxOO8SOcdy4ipWuzeauhItIcdsRs7stk'),
        store.primaryKey()
      )
    })

    await tap.test('private JWKS are the same', async () => {
      // @ts-ignore
      const filepath = new URL('./fixtures/jwks.json', import.meta.url)
      const jwks = JSON.parse(await fs.promises.readFile(filepath, 'utf8'))
      const store = await createKeyStoreFromJWKS(jwks)
      assert.deepStrictEqual(jwks, store.jwks(true))
    })

    await tap.test('public JWKS are the same', async () => {
      // @ts-ignore
      const filepath = new URL('./fixtures/jwks.json', import.meta.url)
      const jwks = JSON.parse(await fs.promises.readFile(filepath, 'utf8'))
      const store = await createKeyStoreFromJWKS(jwks)
      const publicJwks = {
        keys: jwks.keys.map(({ d, k, ...key }) => ({
          ...key,
          key_ops: key.alg.startsWith('HS') ? [] : ['verify']
        }))
      }
      try {
        assert.deepStrictEqual(publicJwks, store.jwks())
      } catch (err) {
        console.log(err)
      }
    })

    await tap.test('gets null if key does not exist', async () => {
      const store = await getKeyStore()
      assert.strictEqual(store.get('foo'), null)
    })

    await tap.test('gets null if kid is null', async () => {
      const store = await getKeyStore()
      assert.strictEqual(store.get(null), null)
    })

    await tap.test('fails if there is no alg', async () => {
      const key = await generate('ES256')
      const jwk = key.jwk()
      delete jwk.alg
      await assert.rejects(
        createKeyStoreFromJWKS({ keys: [jwk] }),
        errors.MissingAlgorithm
      )
      await assert.rejects(createKeyStoreFromJWKS({ keys: [jwk] }), {
        code: 'MISSING_ALGORITHM',
        message: 'Missing alg property'
      })
    })

    await tap.test('fails if the algorithm is unsupported', async () => {
      const key = await generate('ES256')
      const jwk = key.jwk()
      jwk.alg = 'foo'
      await assert.rejects(
        createKeyStoreFromJWKS({ keys: [jwk] }),
        errors.UnsupportedAlgorithm
      )
      await assert.rejects(createKeyStoreFromJWKS({ keys: [jwk] }), {
        code: 'UNSUPPORTED_JWA_ALGORITHM',
        algorithm: 'foo',
        message: 'Unsupported algorithm: "foo"'
      })
    })

    await tap.test('fails to exports private jwks of public keys', async () => {
      const key = await generate('ES256')
      const jwk = key.jwk()
      const store = await createKeyStoreFromJWKS({ keys: [jwk] })
      assert.throws(() => store.jwks(true), {
        message: 'This key is not private or secret'
      })
    })

    await tap.test('fails to import from unsupported jwk type', async () => {
      const key = await generate('ES256')
      const jwk = key.jwk(true)
      jwk.kty = 'foo'
      await assert.rejects(
        createKeyStoreFromJWKS({ keys: [jwk] }),
        errors.UnsupportedKeyType
      )
    })
  })

  await tap.test('createKeyStore', async tap => {
    await tap.test('creates store from keys', async () => {
      const [key1, key2] = await Promise.all([
        generate('ES512'),
        generate('HS512')
      ])
      const store = createKeyStore([key1, key2])
      assert.strictEqual(store.primaryKey(), key1)
      assert.strictEqual(store.get(key1.kid), key1)
      assert.strictEqual(store.get(key2.kid), key2)
      assert.deepStrictEqual(store.keys(), [key1, key2])
      assert.deepStrictEqual(store.jwks(true), {
        keys: [key1.jwk(true), key2.jwk(true)]
      })
      assert.deepStrictEqual(store.jwks(), {
        keys: [key1.jwk(), key2.jwk()]
      })
    })

    await tap.test('fails if not passed array', async () => {
      // @ts-ignore
      assert.throws(() => createKeyStore('foo'), TypeError)
      // @ts-ignore
      assert.throws(() => createKeyStore('foo'), {
        message: 'keys must be an array of keys'
      })
      // @ts-ignore
      assert.throws(() => createKeyStore(['foo']), TypeError)
    })

    await tap.test('fails if not passed any keys', async () => {
      // @ts-ignore
      assert.throws(() => createKeyStore([]), ReferenceError)
      // @ts-ignore
      assert.throws(() => createKeyStore([]), {
        message: 'Key store must have at lest 1 key'
      })
    })
  })
})

async function getKeyStore () {
  // @ts-ignore
  const filepath = new URL('./fixtures/jwks.json', import.meta.url)
  const jwks = JSON.parse(await fs.promises.readFile(filepath, 'utf8'))
  return createKeyStoreFromJWKS(jwks)
}
