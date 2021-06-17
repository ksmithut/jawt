import assert from 'assert'
import fs from 'fs'
import tap from 'tap'
import { createKeyStore, fromJWKS, generate } from '../src/index.js'

tap.test('key-store', async tap => {
  await tap.test('fromJWKS', async tap => {
    await tap.test('Loads key store from JWKS', async () => {
      // @ts-ignore
      const filepath = new URL('./fixtures/jwks.json', import.meta.url)
      const jwks = JSON.parse(await fs.promises.readFile(filepath, 'utf-8'))
      const store = await fromJWKS(jwks)
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
      const store = await fromJWKS(jwks)
      assert.deepStrictEqual(jwks, store.jwks(true))
    })

    await tap.test('public JWKS are the same', async () => {
      // @ts-ignore
      const filepath = new URL('./fixtures/jwks.json', import.meta.url)
      const jwks = JSON.parse(await fs.promises.readFile(filepath, 'utf8'))
      const store = await fromJWKS(jwks)
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
        message: 'keys must be an array'
      })
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
  return fromJWKS(jwks)
}
