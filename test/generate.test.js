import assert from 'assert'
import tap from 'tap'
import { generate, errors } from '../src/index.js'

tap.test('generate', async tap => {
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
    'ES512'
  ]
  for (const alg of algorithms) {
    await tap.test(`can generate ${alg} key`, async () => {
      // @ts-ignore
      const key = await generate(alg)
      assert.strictEqual(key.alg, alg)
      const data = 'foo'
      const buffer = stringToArrayBuffer(data)
      const signedData = await key.sign(buffer)
      assert.strictEqual(await key.verify(buffer, signedData), true)
    })
  }

  await tap.test('Fails generating unsupported algorithm', async () => {
    // @ts-ignore
    await assert.rejects(generate('FOO'), errors.UnsupportedAlgorithm)
    // @ts-ignore
    await assert.rejects(generate('ES256K'), errors.UnsupportedAlgorithm)
    // @ts-ignore
    await assert.rejects(generate('EdDSA'), errors.UnsupportedAlgorithm)
  })

  await tap.test('can export HS256 signing Key', async () => {
    const key = await generate('HS256')
    assert.ok(await key.signingKey())
  })

  await tap.test('fails if the modulus is less than 2048', async () => {
    await assert.rejects(
      generate('RS512', { modulusLength: 2047 }),
      errors.InvalidModulusLength
    )
  })

  await tap.test('fails if the modulus is not a number', async () => {
    await assert.rejects(
      // @ts-ignore
      generate('RS512', { modulusLength: 'foo' }),
      errors.InvalidModulusLength
    )
  })

  await tap.test('fails if the modulus is infinity', async () => [
    await assert.rejects(
      generate('RS512', { modulusLength: Infinity }),
      errors.InvalidModulusLength
    )
  ])

  await tap.test('fails if the modulus is NaN', async () => {
    await assert.rejects(
      generate('RS512', { modulusLength: NaN }),
      errors.InvalidModulusLength
    )
  })
})

/**
 * @param {string} str
 * @returns {ArrayBuffer}
 */
export function stringToArrayBuffer (str) {
  return Uint8Array.from(str, c => c.codePointAt(0) ?? 0).buffer
}

/**
 * @param {ArrayBuffer} arrayBuffer
 * @returns {string}
 */
export function arrayBufferToString (arrayBuffer) {
  return String.fromCodePoint(...new Uint8Array(arrayBuffer))
}
