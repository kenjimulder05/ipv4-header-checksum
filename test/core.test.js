import { test } from 'node:test';
import assert from 'node:assert/strict';
import { computeChecksum, validateChecksum } from '../src/index.js';

/**
 * Build a minimal IPv4 header (20 bytes, IHL=5) with the given fields.
 * The checksum field is left zero; callers set it as needed.
 */
function buildHeader(fields) {
  const h = new Uint8Array(20);
  // Version 4, IHL 5 -> 0x45
  h[0] = 0x45;
  // DSCP/ECN
  h[1] = fields.dscpEcn ?? 0x00;
  // Total length (big-endian)
  h[2] = (fields.totalLength >> 8) & 0xff;
  h[3] = fields.totalLength & 0xff;
  // Identification
  h[4] = (fields.identification >> 8) & 0xff;
  h[5] = fields.identification & 0xff;
  // Flags + fragment offset
  h[6] = ((fields.flags ?? 0) << 5) | ((fields.fragmentOffset >> 8) & 0x1f);
  h[7] = fields.fragmentOffset & 0xff;
  // TTL
  h[8] = fields.ttl ?? 64;
  // Protocol
  h[9] = fields.protocol ?? 6;
  // Checksum (bytes 10-11) set by caller
  // Source IP
  h[12] = fields.src[0]; h[13] = fields.src[1];
  h[14] = fields.src[2]; h[15] = fields.src[3];
  // Destination IP
  h[16] = fields.dst[0]; h[17] = fields.dst[1];
  h[18] = fields.dst[2]; h[19] = fields.dst[3];
  return h;
}

test('computeChecksum returns a number in [0, 0xFFFF]', () => {
  const h = buildHeader({
    totalLength: 20,
    identification: 0x1234,
    fragmentOffset: 0,
    src: [192, 168, 1, 1],
    dst: [192, 168, 1, 2],
  });
  const cs = computeChecksum(h);
  assert.equal(typeof cs, 'number');
  assert.ok(cs >= 0 && cs <= 0xffff, 'checksum out of 16-bit range: ' + cs);
});

test('computeChecksum on a known header matches the expected value', () => {
  // Header: 45 00 00 73 00 00 40 00 40 11 ?? 00 00 00 00 00 00 00 00 00
  // Classic textbook example (src/dst all zeros, protocol 17/UDP).
  const h = buildHeader({
    dscpEcn: 0x00,
    totalLength: 0x0073,
    identification: 0x0000,
    flags: 2, // Don't Fragment
    fragmentOffset: 0,
    ttl: 0x40,
    protocol: 0x11,
    src: [0, 0, 0, 0],
    dst: [0, 0, 0, 0],
  });
  // With flags=2 (DF), byte 6 = 0x40, byte 7 = 0x00.
  // Sum of words (checksum field zeroed):
  // 0x4500 + 0x0073 + 0x0000 + 0x0000 + 0x4000 + 0x4011 + 0x0000 + 0x0000 + 0x0000 + 0x0000
  // = 0xC584
  // ~0xC584 & 0xFFFF = 0x3A7B
  const cs = computeChecksum(h);
  assert.equal(cs, 0x3a7b);
});

test('validateChecksum returns true for a header with the correct checksum', () => {
  const h = buildHeader({
    totalLength: 0x0073,
    identification: 0x0000,
    flags: 2,
    fragmentOffset: 0,
    ttl: 0x40,
    protocol: 0x11,
    src: [0, 0, 0, 0],
    dst: [0, 0, 0, 0],
  });
  const cs = computeChecksum(h);
  h[10] = (cs >> 8) & 0xff;
  h[11] = cs & 0xff;
  assert.equal(validateChecksum(h), true);
});

test('validateChecksum returns false for a corrupted header', () => {
  const h = buildHeader({
    totalLength: 0x0073,
    identification: 0x0000,
    flags: 2,
    fragmentOffset: 0,
    ttl: 0x40,
    protocol: 0x11,
    src: [0, 0, 0, 0],
    dst: [0, 0, 0, 0],
  });
  const cs = computeChecksum(h);
  h[10] = (cs >> 8) & 0xff;
  h[11] = cs & 0xff;
  // Flip a bit in the TTL field
  h[8] ^= 0x01;
  assert.equal(validateChecksum(h), false);
});

test('computeChecksum does not mutate the input buffer', () => {
  const h = buildHeader({
    totalLength: 20,
    identification: 1,
    fragmentOffset: 0,
    src: [10, 0, 0, 1],
    dst: [10, 0, 0, 2],
  });
  const before = new Uint8Array(h);
  computeChecksum(h);
  assert.deepEqual(h, before);
});

test('computeChecksum throws TypeError for non-Uint8Array', () => {
  assert.throws(
    () => computeChecksum([]),
    { name: 'TypeError' }
  );
});

test('computeChecksum throws RangeError for a too-short buffer', () => {
  assert.throws(
    () => computeChecksum(new Uint8Array(10)),
    { name: 'RangeError' }
  );
});

test('computeChecksum throws RangeError when buffer is shorter than IHL*4', () => {
  // IHL=6 means 24 bytes, but we only provide 20.
  const h = buildHeader({
    totalLength: 24,
    identification: 0,
    fragmentOffset: 0,
    src: [1, 2, 3, 4],
    dst: [5, 6, 7, 8],
  });
  h[0] = 0x46; // IHL = 6
  assert.throws(
    () => computeChecksum(h),
    { name: 'RangeError' }
  );
});

test('computeChecksum honours IHL and includes option bytes', () => {
  // 24-byte header with one 4-byte option word of 0x01010400.
  const h = new Uint8Array(24);
  h[0] = 0x46; // version 4, IHL 6
  h[1] = 0x00;
  h[2] = 0x00; h[3] = 0x18; // total length 24
  h[4] = 0x00; h[5] = 0x01; // identification
  h[6] = 0x00; h[7] = 0x00; // flags/frag
  h[8] = 0x40; h[9] = 0x06; // TTL 64, protocol TCP
  // checksum 10-11 left zero
  h[12] = 192; h[13] = 168; h[14] = 1; h[15] = 1;
  h[16] = 192; h[17] = 168; h[18] = 1; h[19] = 2;
  // Option word
  h[20] = 0x01; h[21] = 0x01; h[22] = 0x04; h[23] = 0x00;

  const cs = computeChecksum(h);
  // Place it and validate
  h[10] = (cs >> 8) & 0xff;
  h[11] = cs & 0xff;
  assert.equal(validateChecksum(h), true);
});

test('validateChecksum throws TypeError for non-Uint8Array', () => {
  assert.throws(
    () => validateChecksum(null),
    { name: 'TypeError' }
  );
});

test('validateChecksum throws RangeError for a too-short buffer', () => {
  assert.throws(
    () => validateChecksum(new Uint8Array(5)),
    { name: 'RangeError' }
  );
});

test('a header with an all-zero checksum field validates only if computeChecksum returns 0', () => {
  // Construct a header whose computed checksum is exactly 0x0000.
  // Start from a base, compute, then XOR the checksum field into another
  // word so the sum becomes 0xFFFF -> complement 0x0000.
  // Simpler: find a header where computeChecksum returns 0.
  // We can craft one: make the sum of all words (checksum zeroed) equal 0xFFFF.
  // 0x4500 + 0x0000 + ... we tune the source IP last byte.
  const h = buildHeader({
    totalLength: 20,
    identification: 0,
    fragmentOffset: 0,
    ttl: 64,
    protocol: 6,
    src: [0, 0, 0, 0],
    dst: [0, 0, 0, 0],
  });
  // Current sum (without checksum) for this header:
  // 0x4500 + 0x0014 + 0x0000 + 0x0000 + 0x0000 + 0x4006 + 0x0000 + 0x0000 + 0x0000 + 0x0000
  // = 0x851A. ~0x851A = 0x7AE5. We want sum = 0xFFFF so checksum = 0.
  // Need to add 0xFFFF - 0x851A = 0x7AE5 to the sum via the dst IP.
  // Set dst so that the last word (bytes 16-17) contributes the extra.
  // Current bytes 16-17 = 0x0000. Set them to 0x7AE5.
  h[16] = 0x7a; h[17] = 0xe5;
  const cs = computeChecksum(h);
  assert.equal(cs, 0x0000);
  // With checksum field still zero, validate should pass.
  assert.equal(validateChecksum(h), true);
});
