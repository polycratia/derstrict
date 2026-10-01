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

## What strict means

Strictness here is a property of the encoding and of nothing else. Every refusal
answers one question: are these the bytes DER defines for this value, or are
they bytes some other encoding allows? Whether the value itself is a sensible
one is a question for a schema, a clock, or a key, and none of those are here.

Three rules follow from that, and the whole library is them applied field by
field.

**One encoding per value.** Where a second spelling of a value exists — a length
written the long way, a padded OID arc, a fraction with a trailing zero, a set
written in some other order — it is refused rather than normalised into the
first. Normalising is the step where two readers can land on different values,
and a reader that accepts both spellings accepts two documents where DER defines
one.

**Refuse, not repair.** A signature covers the bytes on the wire. A parser that
repairs a document reads something nobody wrote and nobody signed, so the
document it checks and the document it verified are no longer the same one. The
only safe treatment of a malformed encoding is to stop at it.

**Refuse, not guess.** Where DER leaves nothing to decide, a reader that decides
anyway is inventing a meaning: a reserved length byte that announces no count, a
multi-byte first OID subidentifier, an hour `24` that could be the end of one day
or the start of the next. Each is refused under its own name — the `error` enum
and `describe()` say which rule was broken — rather than read on an assumption
about what the writer probably meant.

The line is the element. Anything decidable from the bytes and X.690's rules for
them — a tag, a length, a digit, an ordering — is decided here. Everything that
needs to know what the bytes are *for* is not.

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
| A time without seconds | `9912312359Z` leaves a reader to decide whether the seconds are zero or merely unwritten. DER's times carry them. |
| A time that is not `Z` | DER writes one zone. An offset, or a bare local time, is an instant two readers place differently depending on what they assume about the writer. |
| Fractional seconds in a `UTCTime` | The type has no place for them. A `GeneralizedTime` may carry them, but not with a trailing zero, and not at all when they are zero — X.690 drops the point along with them. |
| A comma decimal mark | BER's option. DER's decimal mark is the point. |
| A date the calendar does not have | `February 30` is refused rather than rolled over into March or clamped to the 28th, which are two readings of one string. Hour `24` goes the same way: midnight is `000000` of the next day. |
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

`utc_time()` and `generalized_time()` read a time only in the shape DER writes
it, and `time()` reads either one, for the `CHOICE` a validity period is. `year`
is the full year: a `GeneralizedTime` writes all four digits of it, and a
`UTCTime` writes two, which have no century of their own and are read on the
1950-2049 window X.509 fixes for them. A `GeneralizedTime`'s fractional digits
come back where they lie, because how much of a fraction matters is a question
the caller's schema answers and a number here would answer for it.

Header-only, C++17, no allocation, no exceptions.

## What it is not

**Not an X.509 parser.** It reads the encoding, not the semantics. There is no
certificate structure here, no chain building, no path validation, no signature
verification, no revocation checking — those are much larger jobs and pretending
otherwise would be the dangerous kind of convenience.

**Not a verdict on a certificate.** A document that reads is well encoded, which
is not the same as trustworthy: nothing here weighs a validity period against a
clock, a name against a policy, a key against a size floor, or an extension
against the `critical` flag it carries. Every certificate this library accepts
still has to be judged, and the judging happens above it.

**Not a general ASN.1 toolkit.** No schema compiler, no BER, no CER, no encoder.
It reads the subset a certificate is built from and says so when it meets
anything else.

**Not a replacement for a reviewed library** in a codebase that already has one.
It is for the case where the alternative is a hand-rolled loop over a buffer.

## Status

| | |
|---|---|
| Implemented | a cursor with a sticky error and an exact `remaining()`, tag-length-value reading, strict length rules decided before any content is read, `INTEGER` as unsigned 64-bit or as a big-integer view of any width and either sign, `OBJECT IDENTIFIER` in dotted form with minimal arcs, `BIT STRING` with its unused-bits byte, `UTCTime` and `GeneralizedTime` checked digit by digit — seconds required, zone `Z`, one spelling of a fraction, and a date the calendar has — `SEQUENCE` and `SET` walkers that refuse bytes left after the last child and check DER's set ordering as the children are read, end-of-input enforcement |
| Not yet | string types with their character-set rules, context-specific tags |

## Development

```bash
make test   # every check under AddressSanitizer and UndefinedBehaviorSanitizer
make fuzz   # the corpus as seeds for libFuzzer; wants CXX=clang++
make demo
```

Every refusal above has a test built from hand-written bytes, because the whole
value of this library is in what it declines to accept.

`tests/corpus.hpp` carries that idea at document scale: encodings shaped after
the certificates that have split parsers in the field — a length counted past
the end, a BER indefinite length inside a DER document, bytes appended after the
last element — each named with the refusal it is expected to earn, and each read
to its end by a walk with no schema to lean on.
`fuzz/fuzz_derstrict.cpp` reads arbitrary bytes that same way, so `make fuzz`
starts from those encodings rather than from noise: an input that reads outside
its buffer, or that reads two ways, is a crash.

## License

MIT

Written by [polycratia](https://polycratia.com).
