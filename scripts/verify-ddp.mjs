import { createHash, createPublicKey, verify } from 'node:crypto'
import { inflateRawSync } from 'node:zlib'

const EOCD_SIG = 0x06054b50
const CEN_SIG = 0x02014b50
const LOC_SIG = 0x04034b50
const DEX_ENTRY_RE = /^classes[0-9]*\.dex$/

const sha256Hex = (buf) => createHash('sha256').update(buf).digest('hex')

const validateZipEntryName = (name) => {
  if (!name || typeof name !== 'string' || name.trim().length === 0) {
    throw new Error('blank zip entry name')
  }
  if (name.startsWith('/')) {
    throw new Error(`absolute zip entry name: ${name}`)
  }
  if (name.includes('..')) {
    throw new Error(`zip entry name must not contain '..': ${name}`)
  }
  if (name.includes('\\')) {
    throw new Error(`zip entry name must use forward slashes: ${name}`)
  }
  if (name.includes('\u0000')) {
    throw new Error(`zip entry name must not contain NUL: ${name}`)
  }
  if (name.includes(':')) {
    throw new Error(`zip entry name must not contain ':': ${name}`)
  }
}

const findEocdOffset = (buf) => {
  if (buf.length < 22) {
    throw new Error('archive is too small to be a valid ZIP')
  }
  const minOffset = Math.max(0, buf.length - 0xffff - 22)
  for (let offset = buf.length - 22; offset >= minOffset; offset -= 1) {
    if (buf.readUInt32LE(offset) === EOCD_SIG) {
      const commentLen = buf.readUInt16LE(offset + 20)
      if (offset + 22 + commentLen === buf.length) {
        return offset
      }
    }
  }
  throw new Error('ZIP End of Central Directory record not found')
}

export const readZipEntries = (buffer) => {
  const buf = Buffer.isBuffer(buffer) ? buffer : Buffer.from(buffer)
  const eocdOffset = findEocdOffset(buf)
  const totalEntries = buf.readUInt16LE(eocdOffset + 10)
  const cdSize = buf.readUInt32LE(eocdOffset + 12)
  const cdOffset = buf.readUInt32LE(eocdOffset + 16)

  if (cdOffset + cdSize > eocdOffset) {
    throw new Error('ZIP Central Directory bounds are invalid')
  }

  const entries = new Map()
  let cursor = cdOffset

  for (let i = 0; i < totalEntries; i += 1) {
    if (cursor + 46 > eocdOffset || buf.readUInt32LE(cursor) !== CEN_SIG) {
      throw new Error(`invalid Central Directory header at entry ${i}`)
    }
    const flags = buf.readUInt16LE(cursor + 8)
    if ((flags & 0x01) !== 0) {
      throw new Error('encrypted ZIP entries are not supported')
    }
    const method = buf.readUInt16LE(cursor + 10)
    const compressedSize = buf.readUInt32LE(cursor + 20)
    const uncompressedSize = buf.readUInt32LE(cursor + 24)
    const nameLen = buf.readUInt16LE(cursor + 28)
    const extraLen = buf.readUInt16LE(cursor + 30)
    const commentLen = buf.readUInt16LE(cursor + 32)
    const localHeaderOffset = buf.readUInt32LE(cursor + 42)

    const nameStart = cursor + 46
    const nameEnd = nameStart + nameLen
    if (nameEnd + extraLen + commentLen > eocdOffset) {
      throw new Error(`truncated Central Directory entry at ${i}`)
    }
    const nameBytes = buf.subarray(nameStart, nameEnd)
    const name = nameBytes.toString('utf8')
    cursor = nameEnd + extraLen + commentLen

    if (name.endsWith('/')) {
      continue
    }
    validateZipEntryName(name)
    if (entries.has(name)) {
      throw new Error(`duplicate zip entry: ${name}`)
    }

    if (localHeaderOffset + 30 > cdOffset || buf.readUInt32LE(localHeaderOffset) !== LOC_SIG) {
      throw new Error(`invalid Local File Header for ${name}`)
    }
    const localNameLen = buf.readUInt16LE(localHeaderOffset + 26)
    const localExtraLen = buf.readUInt16LE(localHeaderOffset + 28)
    const dataStart = localHeaderOffset + 30 + localNameLen + localExtraLen
    const dataEnd = dataStart + compressedSize
    if (dataEnd > cdOffset) {
      throw new Error(`entry data out of bounds for ${name}`)
    }

    const compressed = buf.subarray(dataStart, dataEnd)
    let data
    if (method === 0) {
      data = compressed
    } else if (method === 8) {
      data = inflateRawSync(compressed)
    } else {
      throw new Error(`unsupported ZIP compression method ${method} for ${name}`)
    }

    if (data.length !== uncompressedSize) {
      throw new Error(`uncompressed size mismatch for ${name}: expected ${uncompressedSize}, got ${data.length}`)
    }

    entries.set(name, {
      name,
      nameBytes,
      size: data.length,
      data,
      sha256: sha256Hex(data),
    })
  }

  return entries
}

export const verifyDdpBuffer = (buffer, expected = {}) => {
  const entries = readZipEntries(buffer)

  const manifestEntry = entries.get('assets/plugin.json')
  if (!manifestEntry) {
    throw new Error('missing assets/plugin.json')
  }
  const signatureEntry = entries.get('META-INF/plugin-signature.json')
  if (!signatureEntry) {
    throw new Error('missing META-INF/plugin-signature.json')
  }

  const hasDex = [...entries.keys()].some((name) => DEX_ENTRY_RE.test(name))
  if (!hasDex) {
    throw new Error('missing classes*.dex')
  }

  let manifest
  try {
    manifest = JSON.parse(manifestEntry.data.toString('utf8'))
  } catch (err) {
    throw new Error(`assets/plugin.json is not valid JSON: ${err.message}`)
  }

  if (expected.id !== undefined && manifest.id !== expected.id) {
    throw new Error(`manifest id mismatch: expected ${expected.id}, got ${manifest.id}`)
  }
  if (expected.version !== undefined && manifest.version !== expected.version) {
    throw new Error(`manifest version mismatch: expected ${expected.version}, got ${manifest.version}`)
  }
  if (expected.apiLevel !== undefined && manifest.apiLevel !== expected.apiLevel) {
    throw new Error(`manifest apiLevel mismatch: expected ${expected.apiLevel}, got ${manifest.apiLevel}`)
  }
  if (expected.minHostVersion !== undefined && manifest.minHostVersion !== expected.minHostVersion) {
    throw new Error(
      `manifest minHostVersion mismatch: expected ${expected.minHostVersion}, got ${manifest.minHostVersion}`,
    )
  }

  let signatureJson
  try {
    signatureJson = JSON.parse(signatureEntry.data.toString('utf8'))
  } catch (err) {
    throw new Error(`META-INF/plugin-signature.json is not valid JSON: ${err.message}`)
  }

  if (signatureJson.algorithm !== 'Ed25519') {
    throw new Error(`unsupported signature algorithm: ${signatureJson.algorithm}`)
  }
  if (typeof signatureJson.publicKey !== 'string' || !signatureJson.publicKey) {
    throw new Error('missing publicKey in META-INF/plugin-signature.json')
  }
  if (typeof signatureJson.signature !== 'string' || !signatureJson.signature) {
    throw new Error('missing signature in META-INF/plugin-signature.json')
  }

  const publicKeyDer = Buffer.from(signatureJson.publicKey, 'base64')
  const computedKeyId = `ed25519:${sha256Hex(publicKeyDer)}`
  if (signatureJson.keyId !== computedKeyId) {
    throw new Error(`signature keyId mismatch: declared ${signatureJson.keyId}, computed ${computedKeyId}`)
  }
  if (expected.publisherKeyId !== undefined && computedKeyId !== expected.publisherKeyId) {
    throw new Error(`publisherKeyId mismatch: expected ${expected.publisherKeyId}, got ${computedKeyId}`)
  }

  const signatureBytes = Buffer.from(signatureJson.signature, 'base64')
  if (signatureBytes.length !== 64) {
    throw new Error(`invalid Ed25519 signature length: ${signatureBytes.length}`)
  }

  const payloadEntries = [...entries.values()]
    .filter((entry) => !entry.name.startsWith('META-INF/'))
    .sort((a, b) => Buffer.compare(a.nameBytes, b.nameBytes))

  const canonicalText = payloadEntries
    .map((entry) => `${entry.sha256} ${entry.size} ${entry.name}\n`)
    .join('')
  const canonicalPayload = Buffer.from(canonicalText, 'utf8')

  const publicKey = createPublicKey({
    key: publicKeyDer,
    format: 'der',
    type: 'spki',
  })

  if (!verify(null, canonicalPayload, publicKey, signatureBytes)) {
    throw new Error('Ed25519 signature verification failed')
  }

  return {
    ok: true,
    manifest,
    keyId: computedKeyId,
    entryDigest: sha256Hex(canonicalPayload),
  }
}
