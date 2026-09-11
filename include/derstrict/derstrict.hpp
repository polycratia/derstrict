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
//   * padded integers         — a leading 0x00 or 0xFF the next byte implies
//   * trailing bytes          — content after the outermost element
//   * unterminated OID arcs   — a final byte with the continuation bit set
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
    sequence = 0x30,  // constructed
    set = 0x31,       // constructed
};

enum class error {
    none,
    truncated,
    indefinite_length,
    non_minimal_length,
    length_too_large,
    unexpected_tag,
    padded_integer,
    sign_extended_integer,
    negative_integer,
    empty_integer,
    malformed_oid,
    trailing_data,
};

[[nodiscard]] inline const char* describe(error e) noexcept {
    switch (e) {
        case error::none: return "no error";
        case error::truncated: return "the element claims more bytes than the document holds";
        case error::indefinite_length: return "indefinite length is BER, not DER";
        case error::non_minimal_length: return "the length is encoded the long way";
        case error::length_too_large: return "the length does not fit in this platform's size type";
        case error::unexpected_tag: return "a different tag was required here";
        case error::padded_integer: return "the integer carries a leading zero that is not a sign byte";
        case error::sign_extended_integer: return "the integer repeats a sign byte its next byte already implies";
        case error::negative_integer: return "the integer is negative and an unsigned value was required";
        case error::empty_integer: return "an integer must have at least one content byte";
        case error::malformed_oid: return "the object identifier ends mid-arc";
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

    [[nodiscard]] bool is(tag expected) const noexcept {
        return raw_tag == static_cast<std::uint8_t>(expected);
    }
    [[nodiscard]] bool constructed() const noexcept { return (raw_tag & 0x20) != 0; }
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

    /// Read the next element, whatever it is.
    [[nodiscard]] std::optional<element> next() noexcept {
        const auto raw_tag = cur_.byte();
        if (!raw_tag) return std::nullopt;

        element out{};
        out.raw_tag = *raw_tag;

        // High-tag-number form (0x1F) is legal DER but no certificate field
        // this parser reaches uses it, so it is refused rather than guessed at.
        if ((out.raw_tag & 0x1F) == 0x1F) return fail(error::unexpected_tag);

        const auto length = read_length();
        if (!length) return std::nullopt;

        const std::uint8_t* const content = cur_.take(*length);
        if (!ok()) return std::nullopt;

        out.content = content;
        out.length = *length;
        return out;
    }

    /// Read the next element and require its tag.
    [[nodiscard]] std::optional<element> expect(tag wanted) noexcept {
        const auto found = next();
        if (!found) return std::nullopt;
        if (!found->is(wanted)) return fail(error::unexpected_tag);
        return found;
    }

    /// Descend into a constructed element.
    [[nodiscard]] parser into(const element& e) const noexcept { return parser{e.content, e.length}; }

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

  private:
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

    [[nodiscard]] std::optional<std::size_t> read_length() noexcept {
        const auto first = cur_.byte();
        if (!first) return std::nullopt;

        if (*first < 0x80) return static_cast<std::size_t>(*first);
        if (*first == 0x80) return fail_size(error::indefinite_length);
        if (*first == 0xFF) return fail_size(error::non_minimal_length);

        const std::size_t count = *first & 0x7F;
        if (count > sizeof(std::size_t)) return fail_size(error::length_too_large);

        const std::uint8_t* const raw = cur_.take(count);
        if (!ok()) return std::nullopt;

        std::size_t value = 0;
        for (std::size_t i = 0; i < count; ++i) value = (value << 8) | raw[i];

        // DER admits exactly one encoding of a length: the shortest. 0x81 0x05
        // and 0x05 mean the same thing, so only one of them may appear.
        if (value < 0x80) return fail_size(error::non_minimal_length);
        if (raw[0] == 0x00) return fail_size(error::non_minimal_length);
        return value;
    }

    std::nullopt_t fail(error e) noexcept { return cur_.fail(e); }
    std::optional<std::size_t> fail_size(error e) noexcept { return fail(e); }
    std::optional<std::uint64_t> fail_value(error e) noexcept { return fail(e); }
    std::optional<std::string> fail_string(error e) noexcept { return fail(e); }

    cursor cur_;
};

}  // namespace derstrict

#endif  // DERSTRICT_DERSTRICT_HPP
