#include "derstrict/derstrict.hpp"

#include <cstdint>
#include <initializer_list>
#include <vector>

#include "harness.hpp"

using namespace derstrict;

namespace {

std::vector<std::uint8_t> bytes(std::initializer_list<int> values) {
    return std::vector<std::uint8_t>(values.begin(), values.end());
}

parser over(const std::vector<std::uint8_t>& data) { return parser{data.data(), data.size()}; }

// The cursor is the only place that touches memory, so its arithmetic is the
// bounds check the rest of the library rests on.
void a_cursor_counts_what_is_left() {
    const auto data = bytes({1, 2, 3, 4});
    cursor c{data.data(), data.size()};
    CHECK(c.remaining() == 4u);

    CHECK(c.byte() == 1u);
    CHECK(c.remaining() == 3u);
    CHECK(c.take(3) == data.data() + 1);
    CHECK(c.remaining() == 0u);
    CHECK(c.at_end());

    // Reading past the end is a failure, not a wrap-around.
    CHECK(!c.byte().has_value());
    CHECK(c.failure() == error::truncated);
    CHECK(c.remaining() == 0u);
}

void a_cursor_asked_for_more_than_it_has_does_not_underflow() {
    const auto data = bytes({1, 2, 3, 4});
    cursor c{data.data(), data.size()};

    CHECK(c.take(5) == nullptr);
    CHECK(c.failure() == error::truncated);
    CHECK(c.remaining() == 0u);  // not four minus five
    // Sticky: the four bytes that really are there still do not come out.
    CHECK(!c.byte().has_value());

    // A span the caller described but did not provide is an empty one.
    cursor absent{nullptr, 16};
    CHECK(absent.remaining() == 0u);
    CHECK(absent.take(0) == nullptr);
    CHECK(!absent.byte().has_value());
}

void a_parser_says_how_much_is_left() {
    const auto data = bytes({0x30, 0x08, 0x02, 0x01, 0x01, 0x02, 0x03, 0x00, 0xFF, 0xFF});
    auto p = over(data);
    CHECK(p.remaining() == data.size());

    const auto seq = p.expect(tag::sequence);
    CHECK(seq.has_value());
    CHECK(p.remaining() == 0u);

    auto inner = p.into(*seq);
    CHECK(inner.remaining() == 8u);
    CHECK(inner.unsigned_integer() == 1u);
    CHECK(inner.remaining() == 5u);

    // Once a read has failed the rest cannot be read, so nothing remains.
    CHECK(!inner.expect(tag::sequence).has_value());
    CHECK(inner.remaining() == 0u);
}

void reads_a_sequence_of_integers() {
    // SEQUENCE { INTEGER 1, INTEGER 65535 }
    const auto data = bytes({0x30, 0x08, 0x02, 0x01, 0x01, 0x02, 0x03, 0x00, 0xFF, 0xFF});
    auto p = over(data);

    const auto seq = p.expect(tag::sequence);
    CHECK(seq.has_value());
    CHECK(seq->constructed());
    CHECK(p.at_end());

    auto inner = p.into(*seq);
    CHECK(inner.unsigned_integer() == 1u);
    CHECK(inner.unsigned_integer() == 65535u);
    CHECK(inner.at_end());
}

// Indefinite length is BER. A DER document containing one has been produced by
// something that is not writing DER, and guessing where it ends is how two
// parsers come to disagree.
void indefinite_length_is_refused() {
    const auto data = bytes({0x30, 0x80, 0x02, 0x01, 0x01, 0x00, 0x00});
    auto p = over(data);

    CHECK(!p.next().has_value());
    CHECK(p.failure() == error::indefinite_length);
}

// 0x81 0x05 and 0x05 mean the same length. DER allows only the short one.
void a_length_written_the_long_way_is_refused() {
    const auto data = bytes({0x04, 0x81, 0x05, 1, 2, 3, 4, 5});
    auto p = over(data);

    CHECK(!p.next().has_value());
    CHECK(p.failure() == error::non_minimal_length);
}

void a_long_form_length_with_a_leading_zero_is_refused() {
    // 0x82 0x00 0x80 encodes 128 in two bytes where one would do.
    auto data = bytes({0x04, 0x82, 0x00, 0x80});
    data.resize(4 + 128, 0xAA);
    auto p = over(data);

    CHECK(!p.next().has_value());
    CHECK(p.failure() == error::non_minimal_length);
}

void a_genuinely_long_length_is_accepted() {
    // 0x81 0x80 is 128 bytes, which needs the long form.
    auto data = bytes({0x04, 0x81, 0x80});
    data.resize(3 + 128, 0xAA);
    auto p = over(data);

    const auto e = p.next();
    CHECK(e.has_value());
    CHECK(e->length == 128);
    CHECK(p.at_end());
}

void an_element_longer_than_the_document_is_refused() {
    const auto data = bytes({0x04, 0x10, 0x01, 0x02});
    auto p = over(data);

    CHECK(!p.next().has_value());
    CHECK(p.failure() == error::truncated);
}

// A leading zero is a sign byte only in front of a byte whose top bit is set.
// Anywhere else it is padding, and padding is how the same number gets two
// encodings.
void a_padded_integer_is_refused() {
    const auto padded = bytes({0x02, 0x02, 0x00, 0x01});
    auto p = over(padded);
    CHECK(!p.unsigned_integer().has_value());
    CHECK(p.failure() == error::padded_integer);

    // The same shape where the zero is genuinely a sign byte is fine.
    const auto signed_form = bytes({0x02, 0x02, 0x00, 0x80});
    auto q = over(signed_form);
    CHECK(q.unsigned_integer() == 0x80u);
}

void integer_zero_and_an_empty_integer() {
    const auto zero = bytes({0x02, 0x01, 0x00});
    auto p = over(zero);
    CHECK(p.unsigned_integer() == 0u);

    const auto empty = bytes({0x02, 0x00});
    auto q = over(empty);
    CHECK(!q.unsigned_integer().has_value());
    CHECK(q.failure() == error::empty_integer);
}

void an_integer_too_wide_for_the_result_type_is_refused() {
    const auto wide = bytes({0x02, 0x09, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF});
    auto p = over(wide);
    CHECK(p.unsigned_integer() == UINT64_MAX);  // nine bytes, first is a sign byte

    const auto too_wide = bytes({0x02, 0x09, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF});
    auto q = over(too_wide);
    CHECK(!q.unsigned_integer().has_value());
    CHECK(q.failure() == error::length_too_large);
}

void reads_an_object_identifier() {
    // 1.2.840.113549.1.1.11 — sha256WithRSAEncryption
    const auto data = bytes({0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B});
    auto p = over(data);

    const auto oid = p.oid();
    CHECK(oid.has_value());
    CHECK(*oid == "1.2.840.113549.1.1.11");
}

void an_oid_that_ends_mid_arc_is_refused() {
    // The last byte has the continuation bit set and nothing follows.
    const auto data = bytes({0x06, 0x03, 0x2A, 0x86, 0x48 | 0x80});
    auto p = over(data);

    CHECK(!p.oid().has_value());
    CHECK(p.failure() == error::malformed_oid);
}

// A first byte with the continuation bit set is a multi-byte first
// subidentifier (arc two above 47). Decoding it as 40*x+y would silently
// produce a different OID — refused instead, because a parser that reads a
// different identifier than its peers is the disagreement this library exists
// to prevent.
void a_multibyte_first_subidentifier_is_refused_not_misread() {
    // 0x88 0x37 encodes the single subidentifier 1079, i.e. the OID 2.999.
    const auto data = bytes({0x06, 0x02, 0x88, 0x37});
    auto p = over(data);

    CHECK(!p.oid().has_value());
    CHECK(p.failure() == error::malformed_oid);
}

// Bytes after the outermost element mean somebody else read this document
// differently from you.
void trailing_data_is_refused() {
    const auto data = bytes({0x02, 0x01, 0x01, 0xFF});
    auto p = over(data);

    CHECK(p.unsigned_integer() == 1u);
    CHECK(!p.at_end());
    CHECK(p.failure() == error::trailing_data);
}

void the_wrong_tag_is_refused_and_the_failure_sticks() {
    const auto data = bytes({0x04, 0x01, 0x41, 0x02, 0x01, 0x01});
    auto p = over(data);

    CHECK(!p.expect(tag::integer).has_value());
    CHECK(p.failure() == error::unexpected_tag);
    // Sticky: the integer that really is next still does not come out.
    CHECK(!p.unsigned_integer().has_value());
    CHECK(!p.ok());
}

void high_tag_numbers_are_refused_rather_than_guessed() {
    const auto data = bytes({0x1F, 0x81, 0x00, 0x01, 0x00});
    auto p = over(data);

    CHECK(!p.next().has_value());
    CHECK(p.failure() == error::unexpected_tag);
}

void every_error_has_words() {
    for (auto e : {error::truncated, error::indefinite_length, error::non_minimal_length,
                   error::length_too_large, error::unexpected_tag, error::padded_integer,
                   error::empty_integer, error::malformed_oid, error::trailing_data}) {
        CHECK(describe(e)[0] != '\0');
    }
}

}  // namespace

int main() {
    a_cursor_counts_what_is_left();
    a_cursor_asked_for_more_than_it_has_does_not_underflow();
    a_parser_says_how_much_is_left();
    reads_a_sequence_of_integers();
    indefinite_length_is_refused();
    a_length_written_the_long_way_is_refused();
    a_long_form_length_with_a_leading_zero_is_refused();
    a_genuinely_long_length_is_accepted();
    an_element_longer_than_the_document_is_refused();
    a_padded_integer_is_refused();
    integer_zero_and_an_empty_integer();
    an_integer_too_wide_for_the_result_type_is_refused();
    reads_an_object_identifier();
    an_oid_that_ends_mid_arc_is_refused();
    a_multibyte_first_subidentifier_is_refused_not_misread();
    trailing_data_is_refused();
    the_wrong_tag_is_refused_and_the_failure_sticks();
    high_tag_numbers_are_refused_rather_than_guessed();
    every_error_has_words();
    return harness::report("derstrict");
}
