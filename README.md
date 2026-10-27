# IPv4 Header Checksum

A small, zero-dependency TypeScript library that computes and validates the IPv4 header checksum over a raw datagram buffer.

## Usage

```typescript
import { computeChecksum, validateChecksum } from 'ipv4-header-checksum';

const header = new Uint8Array([
  0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00,
  0x40, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
]);

const checksum = computeChecksum(header); // 0x3a7b
header[10] = (checksum >> 8) & 0xff;
header[11] = checksum & 0xff;

console.log(validateChecksum(header)); // true
```

## Why

This library exists to provide a single, well-tested implementation of the IPv4 header checksum without pulling in a full networking stack. The trade-off is that it only handles the header checksum — not TCP, UDP, or ICMP body checksums, and not IPv6 (which has no header checksum).

## Edge cases

The implementation honours the Internet Header Length (IHL) field, so IP options are included in the sum when present. It does **not** enforce IHL's maximum value of 15; a buffer with IHL set beyond what the protocol allows will still be summed as long as the buffer is long enough. The checksum field (bytes 10–11) is read as zero during computation and is never mutated.

## Performance

The window keeps a bounded buffer, so `push` is constant time and memory does not
grow with the length of the stream. `peak` and `trough` are linear in the window
size, which is the trade that keeps `push` cheap.

## Limitations

Values are coerced to floats, so very large integers lose precision. If you need
exact integer aggregates over a window, this is the wrong tool.

