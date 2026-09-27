// derstrict — a DER reader that refuses everything DER already forbids.
//
// X.509 parsing has a long history of certificates that two implementations
// read differently. The cause is almost never the hard cryptography; it is that
// BER allows several encodings of the same value, DER picks exactly one, and a
// lenient parser quietly accepts the others. Two parsers that disagree about
// what a certificate says are a signature-bypass waiting to be written.
//
// So this refuses, rather than repairs:
//
//   * indefinite lengths      — BER only; a DER document cannot contain one
//   * non-minimal lengths     — 0x81 0x05 says "five" the long way
//   * lengths past the end    — refused before a content byte is read
//   * padded integers         — a leading 0x00 or 0xFF the next byte implies
//   * trailing bytes          — content after the outermost element
//   * unterminated OID arcs   — a final byte with the continuation bit set
//   * non-minimal OID arcs    — 0x80 0x01 pads an arc that already fits
//   * lying unused-bit counts — a bit string that leaves set bits unused
//   * unsorted set elements   — DER sorts a set's elements by their encodings
//   * loose time strings      — missing seconds, a zone that is not Z, a
//                               fraction with a second spelling, or a date the
//                               calendar does not have
//
// Header-only, C++17, no allocation, no exceptions.
#ifndef DERSTRICT_DERSTRICT_HPP
#define DERSTRICT_DERSTRICT_HPP

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace derstrict {

/// Universal tag numbers, the handful a certificate is built from.
enum class tag : std::uint8_t {
    boolean = 0x01,
    integer = 0x02,
    bit_string = 0x03,
    octet_string = 0x04,
    null_value = 0x05,
    object_identifier = 0x06,
    utf8_string = 0x0C,
    utc_time = 0x17,
    generalized_time = 0x18,
    sequence = 0x30,  // constructed
    set = 0x31,       // constructed
};

enum class error {
    none,
    truncated,
    indefinite_length,
    non_minimal_length,
    reserved_length,
    length_too_large,
    unexpected_tag,
    padded_integer,
    sign_extended_integer,
    negative_integer,
    empty_integer,
    malformed_oid,
    non_minimal_oid_arc,
    missing_unused_bits,
    unused_bits_out_of_range,
    unused_bits_without_content,
    non_zero_unused_bits,
    unsorted_set,
    malformed_time,
    time_not_digits,
    time_missing_seconds,
    time_not_zulu,
    time_fractional_seconds,
    non_minimal_time_fraction,
    time_out_of_range,
    trailing_data,
};

[[nodiscard]] inline const char* describe(error e) noexcept {
    switch (e) {
        case error::none: return "no error";
        case error::truncated: return "the element claims more bytes than the document holds";
        case error::indefinite_length: return "indefinite length is BER, not DER";
        case error::non_minimal_length: return "the length is encoded the long way";
        case error::reserved_length: return "0xFF is reserved and encodes no length at all";
        case error::length_too_large: return "the length does not fit in this platform's size type";
        case error::unexpected_tag: return "a different tag was required here";
        case error::padded_integer: return "the integer carries a leading zero that is not a sign byte";
        case error::sign_extended_integer: return "the integer repeats a sign byte its next byte already implies";
        case error::negative_integer: return "the integer is negative and an unsigned value was required";
        case error::empty_integer: return "an integer must have at least one content byte";
        case error::malformed_oid: return "the object identifier ends mid-arc";
        case error::non_minimal_oid_arc: return "an object identifier arc carries a leading padding byte";
        case error::missing_unused_bits: return "the bit string has no unused-bits byte";
        case error::unused_bits_out_of_range: return "a bit string cannot leave more than seven bits unused";
        case error::unused_bits_without_content: return "an empty bit string leaves unused bits that are not there";
        case error::non_zero_unused_bits: return "the bit string's unused bits are not zero";
        case error::unsorted_set: return "the set's elements are not in the order DER requires";
        case error::malformed_time: return "the time is not the fixed shape DER writes";
        case error::time_not_digits: return "a time field holds something that is not a digit";
        case error::time_missing_seconds: return "the time leaves out its seconds";
        case error::time_not_zulu: return "the time does not end in Z, the only zone DER writes";
        case error::time_fractional_seconds: return "a UTCTime cannot carry fractional seconds";
        case error::non_minimal_time_fraction: return "the fractional seconds end in a zero DER leaves out";
        case error::time_out_of_range: return "a time field names a value the calendar does not have";
        case error::trailing_data: return "bytes remain after the element";
    }
    return "unknown";
}

/// One tag-length-value element. `content` points into the caller's buffer;
/// nothing is copied and nothing is owned.
struct element {
    std::uint8_t raw_tag = 0;
    const std::uint8_t* content = nullptr;
    std::size_t length = 0;
    std::size_t header = 0;

    [[nodiscard]] bool is(tag expected) const noexcept {
        return raw_tag == static_cast<std::uint8_t>(expected);
    }
    [[nodiscard]] bool constructed() const noexcept { return (raw_tag & 0x20) != 0; }

    /// The element as it was written, tag and length bytes included: DER orders
    /// a SET by these bytes and not by the values behind them.
    [[nodiscard]] const std::uint8_t* encoding() const noexcept {
        return content == nullptr ? nullptr : content - header;
    }
    [[nodiscard]] std::size_t encoded_size() const noexcept { return header + length; }
};

/// An INTEGER's content as DER wrote it: two's complement, big-endian, minimal,
/// pointing into the caller's buffer.
///
/// A non-negative value's magnitude is written down in the document, so
/// `magnitude()` hands back a pointer to it and copies nothing. A negative
/// value's is not — the document holds the complement of it — so it has to be
/// computed, and this library owns no memory: `magnitude_into()` writes it
/// into a buffer the caller provides.
struct big_integer {
    const std::uint8_t* bytes = nullptr;
    std::size_t size = 0;

    [[nodiscard]] bool negative() const noexcept { return size != 0 && (bytes[0] & 0x80) != 0; }
    [[nodiscard]] bool is_zero() const noexcept { return size == 1 && bytes[0] == 0x00; }

    /// The bytes of |value|, big-endian and without leading zeros, in place.
    /// Null for a negative value, whose magnitude appears nowhere in the
    /// document; `magnitude_into()` is the way to read that one.
    [[nodiscard]] const std::uint8_t* magnitude() const noexcept {
        if (size == 0 || negative()) return nullptr;
        return bytes[0] == 0x00 ? bytes + 1 : bytes;
    }

    /// How many bytes |value| occupies, for either sign. Zero for the value
    /// zero, which has no magnitude bytes at all.
    [[nodiscard]] std::size_t magnitude_size() const noexcept {
        if (size == 0) return 0;
        if (!negative()) return bytes[0] == 0x00 ? size - 1 : size;
        // Negating loses the top byte only when it is 0xFF and the carry out of
        // the lower bytes never reaches it: 0xFF 0x01 is -255, one byte wide,
        // while 0xFF 0x00 is -256 and stays two.
        if (bytes[0] != 0xFF) return size;
        for (std::size_t i = 1; i < size; ++i) {
            if (bytes[i] != 0x00) return size - 1;
        }
        return size;
    }

    /// Write |value| big-endian into `out`, for either sign. False, and `out`
    /// untouched, if it does not hold `magnitude_size()` bytes.
    [[nodiscard]] bool magnitude_into(std::uint8_t* out, std::size_t capacity) const noexcept {
        const std::size_t needed = magnitude_size();
        if (capacity < needed) return false;
        if (needed == 0) return true;
        if (out == nullptr) return false;

        if (!negative()) {
            const std::uint8_t* const from = magnitude();
            for (std::size_t i = 0; i < needed; ++i) out[i] = from[i];
            return true;
        }

        // Two's complement negation, least significant byte first. The dropped
        // top byte, if there is one, is the zero that negation produces.
        const std::size_t skipped = size - needed;
        std::uint8_t carry = 1;
        for (std::size_t i = size; i-- > 0;) {
            const unsigned int sum =
                static_cast<unsigned int>(static_cast<std::uint8_t>(~bytes[i])) + carry;
            carry = static_cast<std::uint8_t>(sum >> 8);
            if (i >= skipped) out[i - skipped] = static_cast<std::uint8_t>(sum & 0xFFu);
        }
        return true;
    }
};

/// A BIT STRING's content as DER wrote it, pointing into the caller's buffer.
/// `bytes` is what follows the unused-bits byte, and `unused` is how many bits
/// of the last of them are not part of the value.
struct bit_string {
    const std::uint8_t* bytes = nullptr;
    std::size_t size = 0;
    std::uint8_t unused = 0;

    [[nodiscard]] bool empty() const noexcept { return size == 0; }
    [[nodiscard]] std::size_t bit_count() const noexcept { return size * 8 - unused; }

    /// Bit `index` counted from the most significant bit of the first byte,
    /// which is the order X.690 numbers them in. False past the last bit.
    [[nodiscard]] bool bit(std::size_t index) const noexcept {
        if (index >= bit_count()) return false;
        return (bytes[index / 8] & (0x80u >> (index % 8))) != 0;
    }
};

/// A UTCTime or GeneralizedTime taken apart, every field already checked to be
/// digits and to name a date the calendar has.
///
/// `year` is the full year. A GeneralizedTime writes all four digits of it; a
/// UTCTime writes two, which have no century of their own, so they are read on
/// the 1950-2049 window X.509 fixes for them.
///
/// `fraction` is the digits after a GeneralizedTime's decimal point, pointing
/// into the caller's buffer. What a fraction of a second means for a given
/// field is the schema's business, and turning it into a number here would
/// decide that and lose digits doing it.
struct date_time {
    std::uint16_t year = 0;
    std::uint8_t month = 0;
    std::uint8_t day = 0;
    std::uint8_t hour = 0;
    std::uint8_t minute = 0;
    std::uint8_t second = 0;
    const std::uint8_t* fraction = nullptr;
    std::size_t fraction_digits = 0;

    [[nodiscard]] bool has_fraction() const noexcept { return fraction_digits != 0; }
};

/// A cursor over a byte span: the only thing here that touches memory.
///
/// It keeps the first error and reads nothing afterwards, so a run of reads can
/// be checked once at the end instead of at every step — the check that gets
/// skipped is always the one that mattered.
class cursor {
  public:
    /// A span the caller described but did not provide is an empty one.
    cursor(const std::uint8_t* data, std::size_t size) noexcept
        : data_(data), size_(data == nullptr ? 0 : size) {}

    [[nodiscard]] bool ok() const noexcept { return error_ == error::none; }
    [[nodiscard]] error failure() const noexcept { return error_; }

    /// Bytes still readable. The subtraction cannot underflow: nothing advances
    /// the offset without asking `has()` first, so it never passes the size.
    /// Zero once the cursor has failed, because a failed cursor reads no more.
    [[nodiscard]] std::size_t remaining() const noexcept { return ok() ? size_ - offset_ : 0; }

    /// How many bytes have been read, counted from the start of the span.
    [[nodiscard]] std::size_t position() const noexcept { return offset_; }

    /// Whether `count` more bytes can be read. Every read goes through here,
    /// which is what makes a failure stick.
    [[nodiscard]] bool has(std::size_t count) const noexcept { return count <= remaining(); }

    [[nodiscard]] std::optional<std::uint8_t> byte() noexcept {
        if (!has(1)) return fail(error::truncated);
        return data_[offset_++];
    }

    /// Take `count` bytes and return where they are, leaving the cursor where
    /// it was if it cannot. Ask `ok()` rather than testing the pointer, which
    /// is also null for an empty span.
    [[nodiscard]] const std::uint8_t* take(std::size_t count) noexcept {
        if (!has(count)) {
            (void)fail(error::truncated);
            return nullptr;
        }
        const std::uint8_t* const at = data_ + offset_;
        offset_ += count;
        return at;
    }

    /// Require that nothing follows. Bytes after the last element mean somebody
    /// else read this span differently from you.
    [[nodiscard]] bool at_end() noexcept {
        if (!ok()) return false;
        if (remaining() != 0) {
            (void)fail(error::trailing_data);
            return false;
        }
        return true;
    }

    /// Record a failure. The first one wins: whatever goes wrong afterwards is
    /// a consequence of it, and the first is what describes the document.
    std::nullopt_t fail(error e) noexcept {
        if (error_ == error::none) error_ = e;
        return std::nullopt;
    }

  private:
    const std::uint8_t* data_;
    std::size_t size_;
    std::size_t offset_ = 0;
    error error_ = error::none;
};

/// A reader for DER elements, over a cursor.
class parser {
  public:
    parser(const std::uint8_t* data, std::size_t size) noexcept : cur_(data, size) {}

    [[nodiscard]] bool ok() const noexcept { return cur_.ok(); }
    [[nodiscard]] error failure() const noexcept { return cur_.failure(); }
    [[nodiscard]] std::size_t remaining() const noexcept { return cur_.remaining(); }

    /// Whether another element is there: bytes left, and nothing has refused
    /// yet. A walk driven by this ends where the content ends, so bytes left
    /// over after the last element meet a read rather than being stepped over.
    [[nodiscard]] bool more() const noexcept { return ok() && remaining() != 0; }

    /// Read the next element, whatever it is.
    [[nodiscard]] std::optional<element> next() noexcept {
        const std::size_t start = cur_.position();
        const auto raw_tag = cur_.byte();
        if (!raw_tag) return std::nullopt;

        element out{};
        out.raw_tag = *raw_tag;

        // High-tag-number form (0x1F) is legal DER but no certificate field
        // this parser reaches uses it, so it is refused rather than guessed at.
        if ((out.raw_tag & 0x1F) == 0x1F) return fail(error::unexpected_tag);

        // The length is settled before a content byte is touched: what comes
        // back from here is a count this span can already cover.
        const auto length = read_length();
        if (!length) return std::nullopt;
        out.header = cur_.position() - start;

        const std::uint8_t* const content = cur_.take(*length);
        if (!ok()) return std::nullopt;

        out.content = content;
        out.length = *length;

        if (sorted_ && !in_order(out)) return std::nullopt;
        return out;
    }

    /// Read the next element and require its tag.
    [[nodiscard]] std::optional<element> expect(tag wanted) noexcept {
        const auto found = next();
        if (!found) return std::nullopt;
        if (!found->is(wanted)) return fail(error::unexpected_tag);
        return found;
    }

    /// Descend into a constructed element. A SET's children carry DER's
    /// ordering rule with them, so a descent written by hand is no less strict
    /// than one that went through `set()`.
    [[nodiscard]] parser into(const element& e) const noexcept {
        return parser{e.content, e.length, e.is(tag::set)};
    }

    /// Read a SEQUENCE and hand back a reader over its children.
    [[nodiscard]] std::optional<parser> sequence() noexcept {
        const auto e = expect(tag::sequence);
        if (!e) return std::nullopt;
        return into(*e);
    }

    /// Read a SET and hand back a reader over its children, which have to
    /// arrive in the order DER sorts them into.
    [[nodiscard]] std::optional<parser> set() noexcept {
        const auto e = expect(tag::set);
        if (!e) return std::nullopt;
        return into(*e);
    }

    /// Require that nothing follows. A document with trailing bytes has been
    /// interpreted by somebody differently from you.
    [[nodiscard]] bool at_end() noexcept { return cur_.at_end(); }

    /// Read an INTEGER of any width or sign as a view of its encoding. Nothing
    /// is copied: a serial number stays where the caller put it.
    [[nodiscard]] std::optional<big_integer> integer() noexcept {
        const auto e = expect(tag::integer);
        if (!e) return std::nullopt;
        if (!minimal(*e)) return std::nullopt;
        return big_integer{e->content, e->length};
    }

    /// Read an INTEGER as an unsigned 64-bit value, refusing the encodings DER
    /// does not allow and the values this result type cannot hold.
    [[nodiscard]] std::optional<std::uint64_t> unsigned_integer() noexcept {
        const auto number = integer();
        if (!number) return std::nullopt;
        if (number->negative()) return fail_value(error::negative_integer);

        const std::size_t width = number->magnitude_size();
        if (width > sizeof(std::uint64_t)) return fail_value(error::length_too_large);

        const std::uint8_t* const from = number->magnitude();
        std::uint64_t value = 0;
        for (std::size_t i = 0; i < width; ++i) value = (value << 8) | from[i];
        return value;
    }

    /// Read a BIT STRING as a view of the bytes after its unused-bits count.
    [[nodiscard]] std::optional<bit_string> bits() noexcept {
        const auto e = expect(tag::bit_string);
        if (!e) return std::nullopt;
        // The first content byte is the count of unused bits, so a BIT STRING
        // with no content byte has not said how many bits it holds.
        if (e->length == 0) return fail_bits(error::missing_unused_bits);

        const std::uint8_t unused = e->content[0];
        // The count is of bits left over in one byte, so eight of them names a
        // byte that would not be there.
        if (unused > 7) return fail_bits(error::unused_bits_out_of_range);
        // With nothing after the count there is no final byte to leave bits
        // unused in, so any count but zero describes bits that do not exist.
        if (e->length == 1 && unused != 0) return fail_bits(error::unused_bits_without_content);
        // X.690 11.2.1: the unused bits are zero. Left to carry anything they
        // give one bit string a second encoding, which is room for two parsers
        // to read the same value differently.
        if (unused != 0 && (e->content[e->length - 1] & ((1u << unused) - 1u)) != 0) {
            return fail_bits(error::non_zero_unused_bits);
        }

        return bit_string{e->content + 1, e->length - 1, unused};
    }

    /// Read an OBJECT IDENTIFIER in dotted form.
    [[nodiscard]] std::optional<std::string> oid() noexcept {
        const auto e = expect(tag::object_identifier);
        if (!e) return std::nullopt;
        if (e->length == 0) return fail_string(error::malformed_oid);

        std::string out;
        // The first byte packs two arcs: 40 * first + second. A first byte with
        // the continuation bit set means the packed value exceeds 127 — a
        // multi-byte first subidentifier, which this parser does not decode.
        // Splitting it as first/40 and first%40 would silently produce a
        // different OID, and a parser that reads a different identifier than
        // its peers is the disagreement this library exists to prevent.
        const std::uint8_t first = e->content[0];
        if ((first & 0x80) != 0) return fail_string(error::malformed_oid);
        out += std::to_string(first / 40);
        out += '.';
        out += std::to_string(first % 40);

        std::uint64_t arc = 0;
        bool in_arc = false;
        for (std::size_t i = 1; i < e->length; ++i) {
            const std::uint8_t byte = e->content[i];
            // A subidentifier is base 128, and base 128 has no leading zero
            // digit any more than base ten does: 0x80 opening one pads a value
            // that already has an encoding.
            if (!in_arc && byte == 0x80) return fail_string(error::non_minimal_oid_arc);
            if (arc > (UINT64_MAX >> 7)) return fail_string(error::length_too_large);
            arc = (arc << 7) | (byte & 0x7F);
            in_arc = (byte & 0x80) != 0;
            if (!in_arc) {
                out += '.';
                out += std::to_string(arc);
                arc = 0;
            }
        }
        // The last byte must have closed its arc.
        if (in_arc) return fail_string(error::malformed_oid);
        return out;
    }

    /// Read a UTCTime. DER writes one shape of it — YYMMDDHHMMSSZ — so the
    /// seconds are there, the zone is Z, and there is no fraction. Every other
    /// spelling of the same instant is refused rather than normalised, because
    /// normalising is where two readers pick different instants.
    [[nodiscard]] std::optional<date_time> utc_time() noexcept {
        const auto e = expect(tag::utc_time);
        if (!e) return std::nullopt;
        return decode_utc(*e);
    }

    /// Read a GeneralizedTime: YYYYMMDDHHMMSSZ, with the fractional seconds
    /// X.690 does allow here, written the one way it allows them.
    [[nodiscard]] std::optional<date_time> generalized_time() noexcept {
        const auto e = expect(tag::generalized_time);
        if (!e) return std::nullopt;
        return decode_generalized(*e);
    }

    /// Read either time, for the CHOICE a validity period is written as. Each
    /// is held to its own grammar, so taking both costs no strictness.
    [[nodiscard]] std::optional<date_time> time() noexcept {
        const auto e = next();
        if (!e) return std::nullopt;
        if (e->is(tag::utc_time)) return decode_utc(*e);
        if (e->is(tag::generalized_time)) return decode_generalized(*e);
        return fail_time(error::unexpected_tag);
    }

  private:
    parser(const std::uint8_t* data, std::size_t size, bool sorted) noexcept
        : cur_(data, size), sorted_(sorted) {}

    /// DER sorts a SET's elements by their encodings, so each one is measured
    /// against the one before it while both are still in reach. Equal
    /// encodings are in order: sorting does not forbid a repeat, and whether a
    /// repeated value means anything is the schema's business, not the
    /// encoding's.
    [[nodiscard]] bool in_order(const element& e) noexcept {
        const std::uint8_t* const encoding = e.encoding();
        const std::size_t width = e.encoded_size();
        if (previous_ != nullptr && set_order(previous_, previous_size_, encoding, width) > 0) {
            (void)fail(error::unsorted_set);
            return false;
        }
        previous_ = encoding;
        previous_size_ = width;
        return true;
    }

    /// Compare two elements the way X.690 11.6 orders a set: as octet strings,
    /// the shorter one padded at its trailing end with zero bytes.
    [[nodiscard]] static int set_order(const std::uint8_t* a, std::size_t a_size,
                                      const std::uint8_t* b, std::size_t b_size) noexcept {
        const std::size_t shared = a_size < b_size ? a_size : b_size;
        for (std::size_t i = 0; i < shared; ++i) {
            if (a[i] != b[i]) return a[i] < b[i] ? -1 : 1;
        }
        // Past the shorter one the padding is zero, so the longer one is the
        // greater at the first byte it has left that is not zero, and they are
        // equal if it has none.
        const bool a_longer = a_size > b_size;
        const std::uint8_t* const rest = (a_longer ? a : b) + shared;
        const std::size_t rest_size = (a_longer ? a_size : b_size) - shared;
        for (std::size_t i = 0; i < rest_size; ++i) {
            if (rest[i] != 0x00) return a_longer ? 1 : -1;
        }
        return 0;
    }

    /// DER writes an integer as the shortest two's complement there is. A
    /// leading 0x00 is a sign byte only in front of a set top bit, and a
    /// leading 0xFF is sign extension only in front of a clear one. Either way
    /// the extra byte is a second encoding of a number that already has one.
    [[nodiscard]] bool minimal(const element& e) noexcept {
        if (e.length == 0) {
            (void)fail(error::empty_integer);
            return false;
        }
        if (e.length == 1) return true;
        if (e.content[0] == 0x00 && (e.content[1] & 0x80) == 0) {
            (void)fail(error::padded_integer);
            return false;
        }
        if (e.content[0] == 0xFF && (e.content[1] & 0x80) != 0) {
            (void)fail(error::sign_extended_integer);
            return false;
        }
        return true;
    }

    [[nodiscard]] static bool digit(std::uint8_t c) noexcept { return c >= '0' && c <= '9'; }

    [[nodiscard]] static bool all_digits(const std::uint8_t* at, std::size_t count) noexcept {
        for (std::size_t i = 0; i < count; ++i) {
            if (!digit(at[i])) return false;
        }
        return true;
    }

    [[nodiscard]] static unsigned field(const std::uint8_t* at, std::size_t count) noexcept {
        unsigned value = 0;
        for (std::size_t i = 0; i < count; ++i) {
            value = value * 10 + static_cast<unsigned>(at[i] - '0');
        }
        return value;
    }

    /// Where the decimal mark is, or the length if there is none. Both marks are
    /// looked for: the comma is BER's option, and finding it here is what lets
    /// it be refused as a comma rather than as some stray byte.
    [[nodiscard]] static std::size_t decimal_mark(const element& e) noexcept {
        for (std::size_t i = 0; i < e.length; ++i) {
            if (e.content[i] == '.' || e.content[i] == ',') return i;
        }
        return e.length;
    }

    /// DER writes one zone, Z. A local time, or an offset from one, is an
    /// instant two readers place differently depending on what they assume
    /// about the writer.
    [[nodiscard]] bool ends_in_zulu(const element& e) noexcept {
        if (e.length == 0) {
            (void)fail(error::malformed_time);
            return false;
        }
        if (e.content[e.length - 1] != 'Z') {
            (void)fail(error::time_not_zulu);
            return false;
        }
        return true;
    }

    [[nodiscard]] static bool leap_year(std::uint16_t year) noexcept {
        return year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    }

    [[nodiscard]] static std::uint8_t days_in_month(std::uint16_t year,
                                                   std::uint8_t month) noexcept {
        static constexpr std::uint8_t lengths[12] = {31, 28, 31, 30, 31, 30,
                                                    31, 31, 30, 31, 30, 31};
        if (month == 2 && leap_year(year)) return 29;
        return lengths[month - 1];
    }

    /// A date the calendar does not have is a string two readers place
    /// differently: one rolls February 30th over into March, another clamps it
    /// to the end of the month. Hour 24 is the same ambiguity, and X.690 writes
    /// midnight as 000000 of the following day instead.
    [[nodiscard]] bool in_calendar(const date_time& t) noexcept {
        const bool fields_hold = t.month >= 1 && t.month <= 12 && t.day >= 1 && t.hour <= 23 &&
                                 t.minute <= 59 && t.second <= 59;
        if (!fields_hold || t.day > days_in_month(t.year, t.month)) {
            (void)fail(error::time_out_of_range);
            return false;
        }
        return true;
    }

    [[nodiscard]] std::optional<date_time> decode_utc(const element& e) noexcept {
        // The type has no fraction in it at all, so a decimal mark is reported
        // as the fraction it opens rather than as a digit that is not one.
        if (decimal_mark(e) != e.length) return fail_time(error::time_fractional_seconds);
        if (!ends_in_zulu(e)) return std::nullopt;

        const std::size_t digits = e.length - 1;
        // YYMMDDHHMM is what a writer produces when it treats the seconds as
        // optional, which leaves a reader to decide whether they are zero or
        // unknown.
        if (digits == 10) return fail_time(error::time_missing_seconds);
        if (digits != 12) return fail_time(error::malformed_time);
        if (!all_digits(e.content, digits)) return fail_time(error::time_not_digits);

        const unsigned two_digit_year = field(e.content, 2);
        date_time out{};
        out.year = static_cast<std::uint16_t>(two_digit_year >= 50 ? 1900 + two_digit_year
                                                                  : 2000 + two_digit_year);
        out.month = static_cast<std::uint8_t>(field(e.content + 2, 2));
        out.day = static_cast<std::uint8_t>(field(e.content + 4, 2));
        out.hour = static_cast<std::uint8_t>(field(e.content + 6, 2));
        out.minute = static_cast<std::uint8_t>(field(e.content + 8, 2));
        out.second = static_cast<std::uint8_t>(field(e.content + 10, 2));
        if (!in_calendar(out)) return std::nullopt;
        return out;
    }

    [[nodiscard]] std::optional<date_time> decode_generalized(const element& e) noexcept {
        if (!ends_in_zulu(e)) return std::nullopt;

        const std::size_t body = e.length - 1;  // everything before the Z
        const std::size_t mark = decimal_mark(e);
        const bool fractional = mark < body;
        // X.690 11.7.4 admits one decimal mark, the point.
        if (fractional && e.content[mark] == ',') return fail_time(error::malformed_time);

        const std::size_t whole = fractional ? mark : body;
        if (whole != 14) {
            // YYYYMMDDHHMM and YYYYMMDDHH are ISO times, fraction or no
            // fraction, and neither ends on the field DER ends on.
            if (whole == 12 || whole == 10) return fail_time(error::time_missing_seconds);
            return fail_time(error::malformed_time);
        }
        if (!all_digits(e.content, whole)) return fail_time(error::time_not_digits);

        date_time out{};
        out.year = static_cast<std::uint16_t>(field(e.content, 4));
        out.month = static_cast<std::uint8_t>(field(e.content + 4, 2));
        out.day = static_cast<std::uint8_t>(field(e.content + 6, 2));
        out.hour = static_cast<std::uint8_t>(field(e.content + 8, 2));
        out.minute = static_cast<std::uint8_t>(field(e.content + 10, 2));
        out.second = static_cast<std::uint8_t>(field(e.content + 12, 2));

        if (fractional) {
            const std::uint8_t* const digits = e.content + mark + 1;
            const std::size_t count = body - mark - 1;
            // A point that opens no digits is not a fraction at all.
            if (count == 0) return fail_time(error::malformed_time);
            if (!all_digits(digits, count)) return fail_time(error::time_not_digits);
            // X.690 11.7.3: a fraction omits its trailing zeros, and a fraction
            // of zero is omitted along with the point, so a final zero digit
            // gives one instant a second encoding.
            if (digits[count - 1] == '0') return fail_time(error::non_minimal_time_fraction);
            out.fraction = digits;
            out.fraction_digits = count;
        }

        if (!in_calendar(out)) return std::nullopt;
        return out;
    }

    /// Read a length and decide it entirely: form, minimality, and whether this
    /// span can cover the count. A value coming back from here is a length that
    /// has already been checked against the bytes that are really present.
    [[nodiscard]] std::optional<std::size_t> read_length() noexcept {
        const auto first = cur_.byte();
        if (!first) return std::nullopt;

        std::size_t value = *first;
        if (*first >= 0x80) {
            if (*first == 0x80) return fail_size(error::indefinite_length);
            // 0xFF would announce 127 length bytes, but X.690 reserves it, so
            // it announces nothing and reading one would be an invention.
            if (*first == 0xFF) return fail_size(error::reserved_length);

            const std::size_t count = *first & 0x7F;
            if (count > sizeof(std::size_t)) return fail_size(error::length_too_large);

            const std::uint8_t* const raw = cur_.take(count);
            if (!ok()) return std::nullopt;

            value = 0;
            for (std::size_t i = 0; i < count; ++i) value = (value << 8) | raw[i];

            // DER admits exactly one encoding of a length: the shortest. 0x81
            // 0x05 and 0x05 both say five, so a count below 128 may not use the
            // long form, and a long form may not open with a padding byte.
            if (raw[0] == 0x00 || value < 0x80) return fail_size(error::non_minimal_length);
        }

        // Checked against the enclosing span before any content is read, so an
        // element that claims more than its parent holds is refused on sight
        // rather than after the bytes have been handed out.
        if (!cur_.has(value)) return fail_size(error::truncated);
        return value;
    }

    std::nullopt_t fail(error e) noexcept { return cur_.fail(e); }
    std::optional<std::size_t> fail_size(error e) noexcept { return fail(e); }
    std::optional<std::uint64_t> fail_value(error e) noexcept { return fail(e); }
    std::optional<std::string> fail_string(error e) noexcept { return fail(e); }
    std::optional<bit_string> fail_bits(error e) noexcept { return fail(e); }
    std::optional<date_time> fail_time(error e) noexcept { return fail(e); }

    cursor cur_;
    const std::uint8_t* previous_ = nullptr;
    std::size_t previous_size_ = 0;
    bool sorted_ = false;
};

}  // namespace derstrict

#endif  // DERSTRICT_DERSTRICT_HPP
