import { describe, test, expect } from 'vitest'
import { parseDerSignature } from './der'
import { DerParsingError } from '../errors'

describe('parseDerSignature', () => {
  test('should parse valid DER signature with 32-byte r and s', () => {
    // #given
    // r = all 0x11, s = all 0x22
    const validDer = new Uint8Array([
      0x30, 0x44, // SEQUENCE, length 68
      0x02, 0x20, // INTEGER, length 32 (r)
      ...Array(32).fill(0x11), // r value
      0x02, 0x20, // INTEGER, length 32 (s)
      ...Array(32).fill(0x22)  // s value
    ])

    // #when
    const result = parseDerSignature(validDer)

    // #then
    expect(result.r).toHaveLength(32)
    expect(result.s).toHaveLength(32)
    expect(result.r[0]).toBe(0x11)
    expect(result.s[0]).toBe(0x22)
  })

  test('should remove leading 0x00 from 33-byte r value', () => {
    // #given
    // r is 33 bytes (0x00 + 32 bytes)
    const derWith33Bytes = new Uint8Array([
      0x30, 0x45, // SEQUENCE, length 69
      0x02, 0x21, // INTEGER, length 33 (r)
      0x00, ...Array(32).fill(0x11), // leading 0x00 + r
      0x02, 0x20, // INTEGER, length 32 (s)
      ...Array(32).fill(0x22)
    ])

    // #when
    const result = parseDerSignature(derWith33Bytes)

    // #then
    expect(result.r).toHaveLength(32)
    expect(result.r[0]).toBe(0x11) // leading 0x00 removed
    expect(result.s).toHaveLength(32)
  })

  test('should remove leading 0x00 from 33-byte s value', () => {
    // #given
    // s is 33 bytes (0x00 + 32 bytes)
    const derWith33Bytes = new Uint8Array([
      0x30, 0x45, // SEQUENCE, length 69
      0x02, 0x20, // INTEGER, length 32 (r)
      ...Array(32).fill(0x11),
      0x02, 0x21, // INTEGER, length 33 (s)
      0x00, ...Array(32).fill(0x22) // leading 0x00 + s
    ])

    // #when
    const result = parseDerSignature(derWith33Bytes)

    // #then
    expect(result.r).toHaveLength(32)
    expect(result.s).toHaveLength(32)
    expect(result.s[0]).toBe(0x22) // leading 0x00 removed
  })

  test('should pad r value to 32 bytes when less than 32 bytes', () => {
    // #given
    // r is 31 bytes (should be left-padded with zero)
    const derWithShortR = new Uint8Array([
      0x30, 0x43, // SEQUENCE, length 67
      0x02, 0x1f, // INTEGER, length 31 (r)
      ...Array(31).fill(0x11), // r value (31 bytes)
      0x02, 0x20, // INTEGER, length 32 (s)
      ...Array(32).fill(0x22)
    ])

    // #when
    const result = parseDerSignature(derWithShortR)

    // #then
    expect(result.r).toHaveLength(32)
    expect(result.r[0]).toBe(0x00) // left-padded with zero
    expect(result.r[1]).toBe(0x11)
    expect(result.s).toHaveLength(32)
  })

  test('should pad s value to 32 bytes when less than 32 bytes', () => {
    // #given
    // s is 30 bytes (should be left-padded with zeros)
    const derWithShortS = new Uint8Array([
      0x30, 0x42, // SEQUENCE, length 66
      0x02, 0x20, // INTEGER, length 32 (r)
      ...Array(32).fill(0x11),
      0x02, 0x1e, // INTEGER, length 30 (s)
      ...Array(30).fill(0x22) // s value (30 bytes)
    ])

    // #when
    const result = parseDerSignature(derWithShortS)

    // #then
    expect(result.r).toHaveLength(32)
    expect(result.s).toHaveLength(32)
    expect(result.s[0]).toBe(0x00) // left-padded with zero
    expect(result.s[1]).toBe(0x00)
    expect(result.s[2]).toBe(0x22)
  })

  test('should throw DerParsingError when SEQUENCE tag is missing', () => {
    // #given
    // Invalid DER starting with 0x31 instead of 0x30
    const invalidDer = new Uint8Array([
      0x31, 0x44, // Invalid SEQUENCE tag
      0x02, 0x20,
      ...Array(32).fill(0x11),
      0x02, 0x20,
      ...Array(32).fill(0x22)
    ])

    // #when & #then
    expect(() => parseDerSignature(invalidDer)).toThrow(DerParsingError)
    expect(() => parseDerSignature(invalidDer)).toThrow('expected SEQUENCE tag')
  })

  test('should throw DerParsingError when r INTEGER tag is missing', () => {
    // #given
    // Invalid DER with wrong tag for r
    const invalidDer = new Uint8Array([
      0x30, 0x44, // SEQUENCE
      0x03, 0x20, // Wrong tag (0x03 instead of 0x02)
      ...Array(32).fill(0x11),
      0x02, 0x20,
      ...Array(32).fill(0x22)
    ])

    // #when & #then
    expect(() => parseDerSignature(invalidDer)).toThrow(DerParsingError)
    expect(() => parseDerSignature(invalidDer)).toThrow('expected INTEGER tag')
    expect(() => parseDerSignature(invalidDer)).toThrow('for r')
  })

  test('should throw DerParsingError when s INTEGER tag is missing', () => {
    // #given
    // Invalid DER with wrong tag for s
    const invalidDer = new Uint8Array([
      0x30, 0x44, // SEQUENCE
      0x02, 0x20, // r INTEGER
      ...Array(32).fill(0x11),
      0x03, 0x20, // Wrong tag for s (0x03 instead of 0x02)
      ...Array(32).fill(0x22)
    ])

    // #when & #then
    expect(() => parseDerSignature(invalidDer)).toThrow(DerParsingError)
    expect(() => parseDerSignature(invalidDer)).toThrow('expected INTEGER tag')
    expect(() => parseDerSignature(invalidDer)).toThrow('for s')
  })
})
