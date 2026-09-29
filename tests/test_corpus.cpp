// The corpus read: every malformed vector earns the refusal it names, every
// well formed one reads, and neither a cut nor a one-byte change to a document
// gets a read outside the buffer it was given.
#include "corpus.hpp"

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <string>

#include "harness.hpp"

namespace {

// SEQUENCE { OID sha256WithRSAEncryption, NULL }
corpus::bytes algorithm_identifier() {
    return corpus::of({0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01,
                       0x0B, 0x05, 0x00});
}

void every_malformed_vector_is_refused() {
    corpus::reader reader;
    for (const auto& v : corpus::malformed()) {
        const auto found = reader.read(v.encoding.data(), v.encoding.size());
        CHECK(found == v.expected);
        if (found != v.expected) {
            std::printf("    %s: %s\n", v.name, derstrict::describe(found));
        }
    }
}

void every_well_formed_vector_is_read() {
    corpus::reader reader;
    for (const auto& v : corpus::accepted()) {
        const auto found = reader.read(v.encoding.data(), v.encoding.size());
        CHECK(found == derstrict::error::none);
        if (found != derstrict::error::none) {
            std::printf("    %s: %s\n", v.name, derstrict::describe(found));
        }
    }
}

// A document that reads two ways is the disagreement this library exists to
// prevent, and a reader that answers differently on a second pass is one all by
// itself. The fuzzer checks the same thing on bytes nobody wrote down.
void a_document_reads_the_same_way_twice() {
    corpus::reader reader;
    for (const auto& v : corpus::malformed()) {
        const auto first = reader.read(v.encoding.data(), v.encoding.size());
        const auto again = reader.read(v.encoding.data(), v.encoding.size());
        CHECK(first == again);
    }
}

// The walk that reads the corpus has no schema, so a valid element smuggled in
// where the structure ends is invisible to it. A reader that knows the shape it
// wants refuses the same document, which is where trailing data is caught in a
// real certificate.
void an_element_smuggled_into_a_structure_is_refused() {
    // The algorithm identifier with a second NULL after its parameters.
    const auto data = corpus::of({0x30, 0x0F, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D,
                                  0x01, 0x01, 0x0B, 0x05, 0x00, 0x05, 0x00});

    corpus::reader reader;
    CHECK(reader.read(data.data(), data.size()) == derstrict::error::none);

    derstrict::parser document{data.data(), data.size()};
    const auto opened = document.sequence();
    CHECK(opened.has_value());
    if (!opened) return;

    auto fields = *opened;
    CHECK(fields.oid().has_value());
    CHECK(fields.expect(derstrict::tag::null_value).has_value());
    CHECK(!fields.at_end());
    CHECK(fields.failure() == derstrict::error::trailing_data);
}

// A document cut short is one whose outermost element counts bytes that are not
// there, so no prefix of one reads.
void no_prefix_of_a_document_reads() {
    const auto document = algorithm_identifier();
    corpus::reader reader;
    for (std::size_t size = 0; size < document.size(); ++size) {
        const auto found = reader.read(document.data(), size);
        CHECK(found != derstrict::error::none);
    }
}

// Every one-byte change to a document that reads is still read to an answer,
// inside the buffer it was given. The sanitizers decide the second half of that
// sentence; this is what gives them something to decide it about.
void a_single_byte_change_does_not_escape_the_buffer() {
    const auto document = algorithm_identifier();
    corpus::reader reader;
    for (std::size_t i = 0; i < document.size(); ++i) {
        for (const int replacement : {0x00, 0x01, 0x1F, 0x7F, 0x80, 0xFF}) {
            auto mutated = document;
            mutated[i] = static_cast<std::uint8_t>(replacement);
            const auto found = reader.read(mutated.data(), mutated.size());
            CHECK(derstrict::describe(found)[0] != '\0');
        }
    }
}

}  // namespace

int main(int argc, char** argv) {
    // The corpus is also the fuzzer's seeds, and writing it from here keeps one
    // list of vectors rather than two that drift apart.
    if (argc == 3 && std::string(argv[1]) == "--write") return corpus::write_to(argv[2]);

    every_malformed_vector_is_refused();
    every_well_formed_vector_is_read();
    a_document_reads_the_same_way_twice();
    an_element_smuggled_into_a_structure_is_refused();
    no_prefix_of_a_document_reads();
    a_single_byte_change_does_not_escape_the_buffer();
    return harness::report("derstrict corpus");
}
