// Reading a small AlgorithmIdentifier, then the same document with each of the
// encodings DER forbids.
//
//   make demo
#include "derstrict/derstrict.hpp"

#include <cstdio>
#include <initializer_list>
#include <vector>

namespace {

std::vector<std::uint8_t> bytes(std::initializer_list<int> values) {
    return std::vector<std::uint8_t>(values.begin(), values.end());
}

// SEQUENCE { OID sha256WithRSAEncryption, NULL }
//
// Two parsers are in play — the document and the contents of the SEQUENCE — so
// the report has to name whichever of them actually refused, not whichever one
// is closer to hand.
void read_algorithm(const char* label, const std::vector<std::uint8_t>& document) {
    derstrict::parser outer{document.data(), document.size()};

    const auto seq = outer.expect(derstrict::tag::sequence);
    if (!seq) {
        std::printf("%-26s refused: %s\n", label, derstrict::describe(outer.failure()));
        return;
    }

    auto inner = outer.into(*seq);
    const auto oid = inner.oid();
    const bool complete = oid && inner.expect(derstrict::tag::null_value) && inner.at_end();
    if (!complete) {
        std::printf("%-26s refused: %s\n", label, derstrict::describe(inner.failure()));
        return;
    }
    if (!outer.at_end()) {
        std::printf("%-26s refused: %s\n", label, derstrict::describe(outer.failure()));
        return;
    }
    std::printf("%-26s accepted: %s\n", label, oid->c_str());
}

}  // namespace

int main() {
    read_algorithm("well formed",
                   bytes({0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01,
                          0x0B, 0x05, 0x00}));

    read_algorithm("indefinite length",
                   bytes({0x30, 0x80, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01,
                          0x0B, 0x05, 0x00, 0x00, 0x00}));

    read_algorithm("length written long-form",
                   bytes({0x30, 0x81, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01,
                          0x01, 0x0B, 0x05, 0x00}));

    read_algorithm("oid ending mid-arc",
                   bytes({0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01,
                          0x8B, 0x05, 0x00}));

    read_algorithm("bytes after the element",
                   bytes({0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01,
                          0x0B, 0x05, 0x00, 0xFF}));
    return 0;
}
