// Documents shaped after the encodings that have split parsers in the field: a
// length counted past the end, a BER indefinite length inside a DER document,
// bytes appended after the last element. Each vector names the refusal it is
// expected to earn, because a test that only says "this fails" passes for the
// wrong reason as readily as for the right one.
#pragma once

#include "derstrict/derstrict.hpp"

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <initializer_list>
#include <string>
#include <vector>

namespace corpus {

using bytes = std::vector<std::uint8_t>;

inline bytes of(std::initializer_list<int> values) { return bytes(values.begin(), values.end()); }

/// A header followed by filler: the vector is about the header, and the content
/// only has to be present.
inline bytes filled(bytes head, std::size_t count) {
    head.resize(head.size() + count, 0xAA);
    return head;
}

/// The text of a time in the shortest header that carries it.
inline bytes timed(std::uint8_t raw_tag, const std::string& text) {
    bytes out{raw_tag, static_cast<std::uint8_t>(text.size())};
    out.insert(out.end(), text.begin(), text.end());
    return out;
}

struct sample {
    const char* name;
    bytes encoding;
    derstrict::error expected;
};

/// Reads a document to its end without a schema: one outermost element, every
/// child of every constructed element, and nothing after the last of them.
///
/// A schema decides which element belongs where, and having none here is the
/// point — what is left is the encoding rules, and those hold for every
/// document, which is what lets the same walk read a corpus vector and a
/// fuzzer's bytes.
class reader {
  public:
    /// Deep enough for any certificate, and shallow enough that a document made
    /// of nothing but SEQUENCE headers cannot walk off the stack.
    static constexpr unsigned max_depth = 24;

    [[nodiscard]] derstrict::error read(const std::uint8_t* data, std::size_t size) {
        first_ = derstrict::error::none;
        derstrict::parser document{data, size};
        value(document, data, size, 0);
        if (!document.at_end()) note(document.failure());
        return first_;
    }

  private:
    /// The first refusal wins: whatever goes wrong after it is a consequence of
    /// it, and the first is what describes the document.
    void note(derstrict::error e) {
        if (first_ == derstrict::error::none && e != derstrict::error::none) first_ = e;
    }

    void value(derstrict::parser& p, const std::uint8_t* data, std::size_t size, unsigned depth) {
        if (p.remaining() == 0) {
            (void)p.next();
            note(p.failure());
            return;
        }
        // The tag says which reader to exercise, so it is looked at before the
        // element is read: the typed readers are where most of these rules live,
        // and a walk that only called next() would never reach them.
        const std::uint8_t raw_tag = data[size - p.remaining()];
        switch (raw_tag) {
            case 0x02: {
                const auto number = p.integer();
                if (!number) break;
                std::uint8_t magnitude[64];
                (void)number->magnitude_into(magnitude, sizeof(magnitude));
                break;
            }
            case 0x03: {
                const auto value_bits = p.bits();
                if (!value_bits) break;
                for (std::size_t i = 0; i < value_bits->bit_count(); ++i) (void)value_bits->bit(i);
                break;
            }
            case 0x06: {
                (void)p.oid();
                break;
            }
            case 0x17:
            case 0x18: {
                (void)p.time();
                break;
            }
            case 0x30:
            case 0x31: {
                const auto e = p.next();
                if (!e) break;
                if (depth + 1 >= max_depth) break;
                auto inner = p.into(*e);
                children(inner, e->content, e->length, depth + 1);
                break;
            }
            default: {
                (void)p.next();
                break;
            }
        }
        note(p.failure());
    }

    void children(derstrict::parser& p, const std::uint8_t* data, std::size_t size,
                  unsigned depth) {
        while (p.more()) value(p, data, size, depth);
        if (!p.at_end()) note(p.failure());
    }

    derstrict::error first_ = derstrict::error::none;
};

/// The encodings a permissive parser accepts and a peer does not.
inline std::vector<sample> malformed() {
    using derstrict::error;
    return {
        {"an empty document", of({}), error::truncated},
        {"an indefinite length in a der document", of({0x30, 0x80, 0x05, 0x00, 0x00, 0x00}),
         error::indefinite_length},
        {"a length written the long way", of({0x04, 0x81, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05}),
         error::non_minimal_length},
        {"a long form length opening with a padding byte",
         filled(of({0x04, 0x82, 0x00, 0x80}), 128), error::non_minimal_length},
        {"the reserved length byte", of({0x04, 0xFF, 0x01, 0x02}), error::reserved_length},
        {"a length wider than a size type",
         of({0x04, 0x89, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}),
         error::length_too_large},
        {"a length counted past the end",
         of({0x04, 0x84, 0x7F, 0xFF, 0xFF, 0xFF, 0xAA, 0xAA}), error::truncated},
        {"an element longer than the document", of({0x30, 0x7F, 0x02, 0x01, 0x01}),
         error::truncated},
        {"an inner element reaching past its parent",
         of({0x30, 0x03, 0x02, 0x05, 0x01, 0xAA, 0xAA, 0xAA, 0xAA}), error::truncated},
        {"bytes appended after the document",
         of({0x30, 0x03, 0x02, 0x01, 0x01, 0x05, 0x00}), error::trailing_data},
        {"a byte smuggled after the last child", of({0x30, 0x04, 0x02, 0x01, 0x01, 0x00}),
         error::truncated},
        {"an integer padded with a leading zero", of({0x02, 0x02, 0x00, 0x01}),
         error::padded_integer},
        {"an integer repeating its sign byte", of({0x02, 0x02, 0xFF, 0x80}),
         error::sign_extended_integer},
        {"an integer with no content at all", of({0x02, 0x00}), error::empty_integer},
        {"an object identifier arc padded to two bytes",
         of({0x06, 0x04, 0x2A, 0x80, 0x86, 0x48}), error::non_minimal_oid_arc},
        {"an object identifier ending mid arc", of({0x06, 0x03, 0x2A, 0x86, 0xC8}),
         error::malformed_oid},
        {"an object identifier with a multibyte first subidentifier",
         of({0x06, 0x02, 0x88, 0x37}), error::malformed_oid},
        {"a bit string without its unused bits byte", of({0x03, 0x00}),
         error::missing_unused_bits},
        {"a bit string leaving eight bits unused", of({0x03, 0x02, 0x08, 0x00}),
         error::unused_bits_out_of_range},
        {"an empty bit string leaving bits unused", of({0x03, 0x01, 0x03}),
         error::unused_bits_without_content},
        {"a bit string whose unused bits carry a value", of({0x03, 0x02, 0x05, 0xA1}),
         error::non_zero_unused_bits},
        {"a set written out of order", of({0x31, 0x06, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01}),
         error::unsorted_set},
        {"a tag in the high tag number form", of({0x1F, 0x81, 0x00, 0x01, 0x00}),
         error::unexpected_tag},
        {"a time without its seconds", timed(0x17, "2501011200Z"), error::time_missing_seconds},
        {"a time carrying an offset instead of z", timed(0x17, "250101120000+0200"),
         error::time_not_zulu},
        {"a date the calendar does not have", timed(0x17, "250230120000Z"),
         error::time_out_of_range},
        {"a fraction of seconds ending in a zero", timed(0x18, "19991231235959.50Z"),
         error::non_minimal_time_fraction},
    };
}

/// Documents that read, so that a corpus which refuses everything is visibly
/// not what is being measured.
inline std::vector<sample> accepted() {
    using derstrict::error;
    return {
        {"an algorithm identifier",
         of({0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05,
             0x00}),
         error::none},
        {"an empty sequence", of({0x30, 0x00}), error::none},
        {"a set in the order der sorts it",
         of({0x31, 0x07, 0x02, 0x01, 0x01, 0x03, 0x02, 0x05, 0xA0}), error::none},
        {"an octet string that needs the long form", filled(of({0x04, 0x81, 0x80}), 128),
         error::none},
        {"a negative serial number", of({0x02, 0x02, 0xFF, 0x01}), error::none},
        {"a generalized time with a fraction", timed(0x18, "19991231235959.5Z"), error::none},
    };
}

/// Write every vector out as a file, so a fuzzer starts from the encodings that
/// are already known to matter instead of from random bytes. The directory has
/// to exist; nothing here creates one.
inline int write_to(const std::string& directory) {
    std::vector<sample> everything = malformed();
    const auto readable = accepted();
    everything.insert(everything.end(), readable.begin(), readable.end());

    int index = 0;
    for (const auto& v : everything) {
        std::string path = directory;
        path += '/';
        path += std::to_string(index++);
        path += '-';
        for (const char* c = v.name; *c != '\0'; ++c) path += (*c == ' ' ? '-' : *c);

        std::FILE* out = std::fopen(path.c_str(), "wb");
        if (out == nullptr) {
            std::printf("could not write %s\n", path.c_str());
            return 1;
        }
        if (!v.encoding.empty()) std::fwrite(v.encoding.data(), 1, v.encoding.size(), out);
        std::fclose(out);
    }
    std::printf("corpus: %d vectors written to %s\n", index, directory.c_str());
    return 0;
}

}  // namespace corpus
