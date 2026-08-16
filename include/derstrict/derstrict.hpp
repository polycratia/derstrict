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
//   * padded integers         — a leading 0x00 that is not a sign byte
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

/// A cursor over DER, with a sticky error like every parser should have.
class parser {
  public:
    parser(const std::uint8_t* data, std::size_t size) noexcept : data_(data), size_(size) {}

    [[nodiscard]] bool ok() const noexcept { return error_ == error::none; }
    [[nodiscard]] error failure() const noexcept { return error_; }
    [[nodiscard]] std::size_t remaining() const noexcept { return ok() ? size_ - offset_ : 0; }

    /// Read the next element, whatever it is.
    [[nodiscard]] std::optional<element> next() noexcept {
        if (!ok()) return std::nullopt;
        if (offset_ >= size_) return fail(error::truncated);

        element out{};
        out.raw_tag = data_[offset_++];

        // High-tag-number form (0x1F) is legal DER but no certificate field
        // this parser reaches uses it, so it is refused rather than guessed at.
        if ((out.raw_tag & 0x1F) == 0x1F) return fail(error::unexpected_tag);

        const auto length = read_length();
        if (!length) return std::nullopt;
        if (*length > size_ - offset_) return fail(error::truncated);

        out.content = data_ + offset_;
        out.length = *length;
        offset_ += *length;
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
    [[nodiscard]] bool at_end() noexcept {
        if (!ok()) return false;
        if (offset_ != size_) {
            (void)fail(error::trailing_data);
            return false;
        }
        return true;
    }

    /// Read an INTEGER as an unsigned 64-bit value, refusing the encodings DER
    /// does not allow.
    [[nodiscard]] std::optional<std::uint64_t> unsigned_integer() noexcept {
        const auto e = expect(tag::integer);
        if (!e) return std::nullopt;
        if (e->length == 0) return fail_value(error::empty_integer);

        std::size_t start = 0;
        if (e->content[0] == 0x00) {
            // A single 0x00 is the integer zero. A 0x00 in front of a byte whose
            // top bit is clear is padding, which DER forbids.
            if (e->length == 1) return std::uint64_t{0};
            if ((e->content[1] & 0x80) == 0) return fail_value(error::padded_integer);
            start = 1;
        } else if ((e->content[0] & 0x80) != 0) {
            // Negative in DER's two's complement; not representable here.
            return fail_value(error::unexpected_tag);
        }

        if (e->length - start > sizeof(std::uint64_t)) return fail_value(error::length_too_large);

        std::uint64_t value = 0;
        for (std::size_t i = start; i < e->length; ++i) {
            value = (value << 8) | e->content[i];
        }
        return value;
    }

    /// Read an OBJECT IDENTIFIER in dotted form.
    [[nodiscard]] std::optional<std::string> oid() noexcept {
        const auto e = expect(tag::object_identifier);
        if (!e) return std::nullopt;
        if (e->length == 0) return fail_string(error::malformed_oid);

        std::string out;
        // The first byte packs two arcs: 40 * first + second.
        const std::uint8_t first = e->content[0];
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
    [[nodiscard]] std::optional<std::size_t> read_length() noexcept {
        if (offset_ >= size_) return fail_size(error::truncated);
        const std::uint8_t first = data_[offset_++];

        if (first < 0x80) return static_cast<std::size_t>(first);
        if (first == 0x80) return fail_size(error::indefinite_length);
        if (first == 0xFF) return fail_size(error::non_minimal_length);

        const std::size_t count = first & 0x7F;
        if (count > size_ - offset_) return fail_size(error::truncated);
        if (count > sizeof(std::size_t)) return fail_size(error::length_too_large);

        std::size_t value = 0;
        for (std::size_t i = 0; i < count; ++i) value = (value << 8) | data_[offset_ + i];
        offset_ += count;

        // DER admits exactly one encoding of a length: the shortest. 0x81 0x05
        // and 0x05 mean the same thing, so only one of them may appear.
        if (value < 0x80) return fail_size(error::non_minimal_length);
        if (count > 1 && data_[offset_ - count] == 0x00) return fail_size(error::non_minimal_length);
        return value;
    }

    std::nullopt_t fail(error e) noexcept {
        if (error_ == error::none) error_ = e;
        return std::nullopt;
    }
    std::optional<std::size_t> fail_size(error e) noexcept { return fail(e); }
    std::optional<std::uint64_t> fail_value(error e) noexcept { return fail(e); }
    std::optional<std::string> fail_string(error e) noexcept { return fail(e); }

    const std::uint8_t* data_;
    std::size_t size_;
    std::size_t offset_ = 0;
    error error_ = error::none;
};

}  // namespace derstrict

#endif  // DERSTRICT_DERSTRICT_HPP
