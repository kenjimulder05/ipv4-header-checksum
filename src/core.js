/**
 * IPv4 header checksum: compute and validate.
 *
 * The algorithm is the classic 16-bit one's-complement sum used across
 * IPv4, TCP, UDP, and ICMP. We sum all 16-bit words of the header in
 * ones-complement, fold the carries back into the low 16 bits, and take
 * the one's complement of that for the final value.
 *
 * The checksum field itself (bytes 10-11) is treated as zero during
 * computation, which is what makes the scheme self-validating: summing a
 * valid header (checksum included) yields 0xFFFF.
 */

/**
 * Compute the IPv4 header checksum over a raw datagram buffer.
 *
 * The buffer must contain at least the 20-byte fixed IPv4 header. The
 * Internet Header Length (IHL) field in the first byte's low nibble is
 * honoured, so options are included when present. The checksum field at
 * bytes 10-11 is read as zero during summation (the buffer is not
 * mutated).
 *
 * @param {Uint8Array} header - Raw IPv4 header bytes (length >= 20, length >= IHL*4).
 * @returns {number} The 16-bit checksum as an unsigned integer in [0, 0xFFFF].
 * @throws {TypeError} If header is not a Uint8Array.
 * @throws {RangeError} If header is shorter than 20 bytes or shorter than IHL*4.
 */
export function computeChecksum(header) {
  if (!(header instanceof Uint8Array)) {
    throw new TypeError('header must be a Uint8Array');
  }
  if (header.length < 20) {
    throw new RangeError('header must be at least 20 bytes (got ' + header.length + ')');
  }

  // IHL is in 32-bit words; the low nibble of byte 0. Minimum legal value
  // is 5 (20 bytes). We accept any IHL >= 5 as long as the buffer is long
  // enough; we do not enforce the protocol's maximum of 15 because a
  // caller may be working with a truncated or crafted buffer for testing.
  const ihl = header[0] & 0x0f;
  const headerLen = ihl * 4;
  if (header.length < headerLen) {
    throw new RangeError(
      'header length ' + header.length + ' is less than IHL*4 (' + headerLen + ')'
    );
  }

  let sum = 0;
  for (let i = 0; i < headerLen; i += 2) {
    // Skip the checksum field (bytes 10-11) by treating it as zero.
    // This is what makes the checksum self-validating: a recomputation
    // over a header with the correct checksum in place yields the same
    // value, and a validation sum yields 0xFFFF.
    if (i === 10) continue;
    const hi = header[i];
    const lo = header[i + 1];
    sum += (hi << 8) | lo;
  }

  // Fold 32-bit accumulator down to 16 bits. One fold is enough for a
  // 20-byte header (max sum ~0x9C784, carry fits in one pass), but we loop
  // so options and large buffers are handled correctly too.
  while (sum > 0xffff) {
    sum = (sum & 0xffff) + (sum >>> 16);
  }

  // One's complement. The >>> 0 keeps the result unsigned.
  return (~sum >>> 0) & 0xffff;
}

/**
 * Validate an IPv4 header's checksum in place.
 *
 * Sums the entire header (checksum field included). A valid header sums
 * to 0xFFFF in one's-complement arithmetic, so the one's complement of
 * the sum is 0x0000.
 *
 * @param {Uint8Array} header - Raw IPv4 header bytes with the checksum field populated.
 * @returns {boolean} True if the checksum is valid, false otherwise.
 */
export function validateChecksum(header) {
  if (!(header instanceof Uint8Array)) {
    throw new TypeError('header must be a Uint8Array');
  }
  if (header.length < 20) {
    throw new RangeError('header must be at least 20 bytes (got ' + header.length + ')');
  }

  const ihl = header[0] & 0x0f;
  const headerLen = ihl * 4;
  if (header.length < headerLen) {
    throw new RangeError(
      'header length ' + header.length + ' is less than IHL*4 (' + headerLen + ')'
    );
  }

  let sum = 0;
  for (let i = 0; i < headerLen; i += 2) {
    const hi = header[i];
    lo = header[i + 1];
    sum += (hi << 8) | lo;
  }

  while (sum > 0xffff) {
    sum = (sum & 0xffff) + (sum >>> 16);
  }

  return (~sum & 0xffff) === 0x0000;
}

var lo;
