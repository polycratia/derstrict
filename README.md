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
| Reserved length (`0xFF`) | X.690 reserves it, so it announces no byte count at all. Reading it as "127 length bytes follow" would be a parser inventing a meaning. |
| A length past the end | Measured against the enclosing element before any content is read, so an inner element cannot reach into bytes its parent does not cover. |
| Padded integers | A leading `0x00` is a sign byte only in front of a set top bit, and a leading `0xFF` is sign extension only in front of a clear one. Anywhere else the byte gives one number two encodings. |
| Trailing data | Bytes after the last element — of the document, or of the content of a constructed element a walk has finished — mean somebody else read this document differently from you. |
| Unsorted set elements | The order of a `SET`'s components carries no meaning, so DER fixes one: ascending by encoding, compared as octet strings. A reader that takes any order takes several documents where DER defines one. |
| Unterminated OID arcs | A final byte with the continuation bit set. |
| Padded OID arcs | An arc is a base-128 number, and base 128 has no leading zero digit any more than base ten does: `0x80 0x01` and `0x01` are one arc written two ways. |
| A dishonest unused-bits count | It counts the bits the last byte of a `BIT STRING` does not use, so it is at most seven, it is zero when there is no last byte, and the bits it counts are zero. |
| High-tag-number form | Legal DER, but no field this reaches uses it — refused rather than guessed at. |

## Use

```cpp
#include "derstrict/derstrict.hpp"

derstrict::parser document{data, size};
auto algorithm = document.sequence();   // the element, and a reader over its children
if (!algorithm) return derstrict::describe(document.failure());

const auto oid = algorithm->oid();
if (!oid) return derstrict::describe(algorithm->failure());
if (!algorithm->at_end() || !document.at_end()) return "trailing data";
```

`sequence()` and `set()` read the element and hand back a reader over its
content; `into()` does the same for an element already in hand. A walk of an
unknown number of children is driven by `more()`:

```cpp
while (children.more()) {
    const auto child = children.next();
    if (!child) break;
}
if (!children.at_end()) return derstrict::describe(children.failure());
```

`more()` is true while bytes are left and nothing has refused, so the walk ends
where the content ends: a byte after the last child is read as the element it
claims to be and refused for not being one, rather than stepped over. A child
the caller never asked for is refused by `at_end()` for the same reason. A
`SET`'s children carry DER's ordering rule with them, and `into()` carries it
too, so a descent written by hand is no less strict than one through `set()`.

Failures are sticky, so a run of reads can be checked once. `remaining()` is the
exact number of bytes not yet read — it never underflows, and it is zero once a
read has failed, because a failed parser reads nothing more. `content` points
into the caller's buffer: nothing is copied and nothing is owned, and
`encoding()` widens that view back over the tag and length bytes, which is what
DER orders a set by.

`unsigned_integer()` is for the small fields. `integer()` reads one of any width
or sign and hands back a view of the encoding: `negative()`, and `magnitude()`
for a non-negative value's bytes where they already lie. A negative value's
magnitude is not in the document — the document holds its two's complement — so
`magnitude_into()` writes that one into a buffer the caller owns, because this
library owns no memory to write it into.

`bits()` reads a `BIT STRING` as the bytes after its unused-bits count, with
`bit()` numbering them the way X.690 does: most significant bit of the first
byte first.

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
| Implemented | a cursor with a sticky error and an exact `remaining()`, tag-length-value reading, strict length rules decided before any content is read, `INTEGER` as unsigned 64-bit or as a big-integer view of any width and either sign, `OBJECT IDENTIFIER` in dotted form with minimal arcs, `BIT STRING` with its unused-bits byte, `SEQUENCE` and `SET` walkers that refuse bytes left after the last child and check DER's set ordering as the children are read, end-of-input enforcement |
| Not yet | `UTCTime` and `GeneralizedTime`, string types with their character-set rules, context-specific tags |

## Development

```bash
make test   # 255 checks under AddressSanitizer and UndefinedBehaviorSanitizer
make demo
```

Every refusal above has a test built from hand-written bytes, because the whole
value of this library is in what it declines to accept.

## License

MIT

Written by [polycratia](https://polycratia.com).
