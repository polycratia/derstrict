# derstrict

A DER reader that refuses everything DER already forbids.

X.509 has a long history of certificates that two implementations read
differently. The cause is almost never the cryptography. It is that BER allows
several encodings of the same value, DER picks exactly one, and a lenient parser
quietly accepts the others — so two parsers end up disagreeing about what a
certificate says, which is where signature bypasses come from.

```console
$ make demo
well formed                accepted: 1.2.840.113549.1.1.11
indefinite length          refused: indefinite length is BER, not DER
length written long-form   refused: the length is encoded the long way
oid ending mid-arc         refused: the object identifier ends mid-arc
bytes after the element    refused: bytes remain after the element
```

## What it refuses

| | |
|---|---|
| Indefinite length (`0x80`) | BER only. A DER document cannot contain one, and guessing where the element ends is how parsers diverge. |
| Non-minimal length | `0x81 0x05` and `0x05` mean the same thing. DER allows only the short form, and only one encoding may exist. |
| Padded integers | A leading `0x00` is a sign byte in front of a high bit, and padding everywhere else. Padding gives one number two encodings. |
| Trailing data | Bytes after the outermost element mean somebody else read this document differently from you. |
| Unterminated OID arcs | A final byte with the continuation bit set. |
| High-tag-number form | Legal DER, but no field this reaches uses it — refused rather than guessed at. |

## Use

```cpp
#include "derstrict/derstrict.hpp"

derstrict::parser outer{data, size};
const auto seq = outer.expect(derstrict::tag::sequence);
if (!seq) return derstrict::describe(outer.failure());

auto inner = outer.into(*seq);
const auto algorithm = inner.oid();
if (!inner.at_end() || !outer.at_end()) return "trailing data";
```

Failures are sticky, so a run of reads can be checked once. `remaining()` is the
exact number of bytes not yet read — it never underflows, and it is zero once a
read has failed, because a failed parser reads nothing more. `content` points
into the caller's buffer: nothing is copied and nothing is owned.

Header-only, C++17, no allocation, no exceptions.

## What it is not

**Not an X.509 parser.** It reads the encoding, not the semantics. There is no
certificate structure here, no chain building, no signature verification — those
are much larger jobs and pretending otherwise would be the dangerous kind of
convenience.

**Not a general ASN.1 toolkit.** No schema compiler, no BER, no CER, no encoder.
It reads the subset a certificate is built from and says so when it meets
anything else.

**Not a replacement for a reviewed library** in a codebase that already has one.
It is for the case where the alternative is a hand-rolled loop over a buffer.

## Status

| | |
|---|---|
| Implemented | a cursor with a sticky error and an exact `remaining()`, tag-length-value reading, strict length rules, `INTEGER` as unsigned 64-bit, `OBJECT IDENTIFIER` in dotted form, descent into constructed elements, end-of-input enforcement |
| Not yet | `BIT STRING` with its unused-bits byte, `UTCTime` and `GeneralizedTime`, negative and big integers, string types with their character-set rules, context-specific tags |

## Development

```bash
make test   # 74 checks under AddressSanitizer and UndefinedBehaviorSanitizer
make demo
```

Every refusal above has a test built from hand-written bytes, because the whole
value of this library is in what it declines to accept.

## License

MIT

Written by [polycratia](https://polycratia.com).
