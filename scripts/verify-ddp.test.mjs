import assert from 'node:assert/strict'
import { createHash, generateKeyPairSync, sign } from 'node:crypto'
import test from 'node:test'
import { deflateRawSync } from 'node:zlib'
import { verifyDdpBuffer } from './verify-ddp.mjs'

const sha256Hex = (buf) => createHash('sha256').update(buf).digest('hex')

const buildZipBuffer = (rawEntries) => {
  const localParts = []
  const centralParts = []
  let localOffset = 0

  for (const item of rawEntries) {
    const nameBytes = Buffer.from(item.name, 'utf8')
    const uncompressed = Buffer.isBuffer(item.data) ? item.data : Buffer.from(item.data, 'utf8')
    const method = item.deflate ? 8 : 0
    const compressed = method === 8 ? deflateRawSync(uncompressed) : uncompressed

    const localHeader = Buffer.alloc(30 + nameBytes.length)
    localHeader.writeUInt32LE(0x04034b50, 0)
    localHeader.writeUInt16LE(20, 4)
    localHeader.writeUInt16LE(0, 6)
    localHeader.writeUInt16LE(method, 8)
    localHeader.writeUInt16LE(0, 10)
    localHeader.writeUInt16LE(0, 12)
    localHeader.writeUInt32LE(0, 14)
    localHeader.writeUInt32LE(compressed.length, 18)
    localHeader.writeUInt32LE(uncompressed.length, 22)
    localHeader.writeUInt16LE(nameBytes.length, 26)
    localHeader.writeUInt16LE(0, 28)
    nameBytes.copy(localHeader, 30)

    const centralHeader = Buffer.alloc(46 + nameBytes.length)
    centralHeader.writeUInt32LE(0x02014b50, 0)
    centralHeader.writeUInt16LE(20, 4)
    centralHeader.writeUInt16LE(20, 6)
    centralHeader.writeUInt16LE(0, 8)
    centralHeader.writeUInt16LE(method, 10)
    centralHeader.writeUInt16LE(0, 12)
    centralHeader.writeUInt16LE(0, 14)
    centralHeader.writeUInt32LE(0, 16)
    centralHeader.writeUInt32LE(compressed.length, 20)
    centralHeader.writeUInt32LE(uncompressed.length, 24)
    centralHeader.writeUInt16LE(nameBytes.length, 28)
    centralHeader.writeUInt16LE(0, 30)
    centralHeader.writeUInt16LE(0, 32)
    centralHeader.writeUInt16LE(0, 34)
    centralHeader.writeUInt16LE(0, 36)
    centralHeader.writeUInt32LE(0, 38)
    centralHeader.writeUInt32LE(localOffset, 42)
    nameBytes.copy(centralHeader, 46)

    localParts.push(localHeader, compressed)
    centralParts.push(centralHeader)
    localOffset += localHeader.length + compressed.length
  }

  const centralDir = Buffer.concat(centralParts)
  const eocd = Buffer.alloc(22)
  eocd.writeUInt32LE(0x06054b50, 0)
  eocd.writeUInt16LE(0, 4)
  eocd.writeUInt16LE(0, 6)
  eocd.writeUInt16LE(rawEntries.length, 8)
  eocd.writeUInt16LE(rawEntries.length, 10)
  eocd.writeUInt32LE(centralDir.length, 12)
  eocd.writeUInt32LE(localOffset, 16)
  eocd.writeUInt16LE(0, 20)

  return Buffer.concat([...localParts, centralDir, eocd])
}

const createSignedDdp = ({
  manifest = {
    id: 'io.github.whywood.superpi.plugin.demo',
    version: '1.2.3',
    apiLevel: 7,
    minHostVersion: '2.0.0',
  },
  extraEntries = [],
  tamperAfterSign = null,
  overrideKeyId = null,
} = {}) => {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519')
  const publicKeyDer = publicKey.export({ format: 'der', type: 'spki' })
  const keyId = overrideKeyId ?? `ed25519:${sha256Hex(publicKeyDer)}`

  const payloadEntries = [
    { name: 'assets/plugin.json', data: Buffer.from(JSON.stringify(manifest), 'utf8'), deflate: true },
    { name: 'classes.dex', data: Buffer.from('dex\n035\0demo-bytecode', 'utf8'), deflate: false },
    ...extraEntries,
  ]

  const canonical = [...payloadEntries]
    .sort((a, b) => Buffer.compare(Buffer.from(a.name, 'utf8'), Buffer.from(b.name, 'utf8')))
    .map((entry) => {
      const buf = Buffer.isBuffer(entry.data) ? entry.data : Buffer.from(entry.data, 'utf8')
      return `${sha256Hex(buf)} ${buf.length} ${entry.name}\n`
    })
    .join('')

  const signature = sign(null, Buffer.from(canonical, 'utf8'), privateKey)
  if (tamperAfterSign) {
    tamperAfterSign(payloadEntries)
  }

  const signatureJson = {
    algorithm: 'Ed25519',
    keyId,
    publicKey: publicKeyDer.toString('base64'),
    signature: signature.toString('base64'),
  }

  const buffer = buildZipBuffer([
    ...payloadEntries,
    { name: 'META-INF/plugin-signature.json', data: Buffer.from(JSON.stringify(signatureJson), 'utf8'), deflate: true },
  ])

  return { buffer, keyId, manifest }
}

test('verifyDdpBuffer accepts a valid signed .ddp bundle', () => {
  const { buffer, keyId, manifest } = createSignedDdp({
    extraEntries: [{ name: 'assets/中文说明.txt', data: 'hello', deflate: true }],
  })
  const result = verifyDdpBuffer(buffer, {
    id: manifest.id,
    version: manifest.version,
    apiLevel: manifest.apiLevel,
    minHostVersion: manifest.minHostVersion,
    publisherKeyId: keyId,
  })
  assert.equal(result.ok, true)
  assert.equal(result.keyId, keyId)
  assert.equal(result.manifest.id, manifest.id)
})

test('verifyDdpBuffer rejects tampered entry content', () => {
  const { buffer, keyId, manifest } = createSignedDdp({
    tamperAfterSign: (entries) => {
      entries[1].data = Buffer.from('dex\n035\0tampered-bytecode', 'utf8')
    },
  })
  assert.throws(
    () =>
      verifyDdpBuffer(buffer, {
        id: manifest.id,
        version: manifest.version,
        apiLevel: manifest.apiLevel,
        minHostVersion: manifest.minHostVersion,
        publisherKeyId: keyId,
      }),
    /Ed25519 signature verification failed/,
  )
})

test('verifyDdpBuffer rejects manifest metadata mismatch', () => {
  const { buffer, keyId, manifest } = createSignedDdp()
  assert.throws(
    () =>
      verifyDdpBuffer(buffer, {
        id: manifest.id,
        version: '9.9.9',
        apiLevel: manifest.apiLevel,
        minHostVersion: manifest.minHostVersion,
        publisherKeyId: keyId,
      }),
    /manifest version mismatch/,
  )
})

test('verifyDdpBuffer rejects publisherKeyId mismatch', () => {
  const { buffer, manifest } = createSignedDdp()
  assert.throws(
    () =>
      verifyDdpBuffer(buffer, {
        id: manifest.id,
        version: manifest.version,
        apiLevel: manifest.apiLevel,
        minHostVersion: manifest.minHostVersion,
        publisherKeyId: `ed25519:${'0'.repeat(64)}`,
      }),
    /publisherKeyId mismatch/,
  )
})

test('verifyDdpBuffer rejects bundle missing classes.dex', () => {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519')
  const publicKeyDer = publicKey.export({ format: 'der', type: 'spki' })
  const keyId = `ed25519:${sha256Hex(publicKeyDer)}`
  const manifestData = Buffer.from(
    JSON.stringify({ id: 'io.example.nodex', version: '1.0.0', apiLevel: 7, minHostVersion: '2.0.0' }),
    'utf8',
  )
  const canonical = `${sha256Hex(manifestData)} ${manifestData.length} assets/plugin.json\n`
  const signature = sign(null, Buffer.from(canonical, 'utf8'), privateKey)
  const buffer = buildZipBuffer([
    { name: 'assets/plugin.json', data: manifestData },
    {
      name: 'META-INF/plugin-signature.json',
      data: JSON.stringify({
        algorithm: 'Ed25519',
        keyId,
        publicKey: publicKeyDer.toString('base64'),
        signature: signature.toString('base64'),
      }),
    },
  ])
  assert.throws(() => verifyDdpBuffer(buffer), /missing classes\*\.dex/)
})
