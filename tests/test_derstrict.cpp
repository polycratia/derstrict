#include "derstrict/derstrict.hpp"

#include <algorithm>
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

// 127 is the largest count the short form carries, so it is also the largest
// the long form may not carry. The content is present, so the refusal is about
// the encoding and nothing else.
void the_largest_short_form_length_may_not_use_the_long_form() {
    auto data = bytes({0x04, 0x81, 0x7F});
    data.resize(3 + 127, 0xAA);
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

// 0xFF is reserved by X.690: it announces no byte count at all. Reading it as
// "127 length bytes follow" would be a parser inventing a meaning.
void a_reserved_length_byte_is_refused() {
    const auto data = bytes({0x04, 0xFF, 0x01, 0x02});
    auto p = over(data);

    CHECK(!p.next().has_value());
    CHECK(p.failure() == error::reserved_length);
}

void a_length_wider_than_a_size_type_is_refused() {
    // 0x89 announces nine length bytes, which no size type here can hold.
    const auto data = bytes({0x04, 0x89, 0x01, 0, 0, 0, 0, 0, 0, 0, 0});
    auto p = over(data);

    CHECK(!p.next().has_value());
    CHECK(p.failure() == error::length_too_large);
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

void a_zero_length_element_reads_no_content() {
    const auto data = bytes({0x05, 0x00});
    auto p = over(data);

    const auto e = p.next();
    CHECK(e.has_value());
    CHECK(e->length == 0u);
    CHECK(p.at_end());
}

void an_element_longer_than_the_document_is_refused() {
    const auto data = bytes({0x04, 0x10, 0x01, 0x02});
    auto p = over(data);

    CHECK(!p.next().has_value());
    CHECK(p.failure() == error::truncated);
}

// The length is measured against the document before any content is read, so a
// count in the millions costs nothing and moves nothing.
void a_length_far_past_the_end_is_refused_before_the_content() {
    const auto data = bytes({0x04, 0x84, 0x7F, 0xFF, 0xFF, 0xFF, 0xAA, 0xAA});
    auto p = over(data);

    CHECK(!p.next().has_value());
    CHECK(p.failure() == error::truncated);
    CHECK(p.remaining() == 0u);
}

// A length is bounded by the element that contains it, not by the document. An
// inner element reaching past its parent is the classic overrun, and the bytes
// it reaches for really are present in the outer buffer.
void an_inner_length_cannot_reach_past_its_parent() {
    // SEQUENCE of three bytes holding an INTEGER that claims five.
    const auto data = bytes({0x30, 0x03, 0x02, 0x05, 0x01, 0xAA, 0xAA, 0xAA, 0xAA});
    auto p = over(data);

    const auto seq = p.expect(tag::sequence);
    CHECK(seq.has_value());
    CHECK(p.remaining() == 4u);  // the bytes the inner element wanted are there

    auto inner = p.into(*seq);
    CHECK(!inner.integer().has_value());
    CHECK(inner.failure() == error::truncated);
    CHECK(inner.remaining() == 0u);
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

    // The rule belongs to the encoding, not to the result type, so the
    // big-integer view refuses the same bytes.
    auto r = over(padded);
    CHECK(!r.integer().has_value());
    CHECK(r.failure() == error::padded_integer);
}

// 0xFF 0x80 and 0x80 are both -128. DER writes the shorter one.
void a_sign_extended_integer_is_refused() {
    const auto extended = bytes({0x02, 0x02, 0xFF, 0x80});
    auto p = over(extended);
    CHECK(!p.integer().has_value());
    CHECK(p.failure() == error::sign_extended_integer);

    // The same shape where the 0xFF carries information is fine: -255.
    const auto minimal = bytes({0x02, 0x02, 0xFF, 0x01});
    auto q = over(minimal);
    const auto number = q.integer();
    CHECK(number.has_value());
    CHECK(number->magnitude_size() == 1u);
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

// A number too wide for any result type is still readable as an encoding, and
// reading it copies nothing: the magnitude is where the caller's bytes are.
void a_big_integer_view_points_into_the_document() {
    const auto data = bytes({0x02, 0x09, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF});
    auto p = over(data);

    const auto number = p.integer();
    CHECK(number.has_value());
    CHECK(!number->negative());
    CHECK(number->magnitude_size() == 8u);
    CHECK(number->magnitude() == data.data() + 3);  // past the sign byte, not a copy of it
    CHECK(p.at_end());
}

void a_big_integer_view_of_zero_has_no_magnitude() {
    const auto data = bytes({0x02, 0x01, 0x00});
    auto p = over(data);

    const auto number = p.integer();
    CHECK(number.has_value());
    CHECK(number->is_zero());
    CHECK(!number->negative());
    CHECK(number->magnitude_size() == 0u);
}

// A negative value's magnitude is not in the document — the document holds its
// two's complement — so it is computed into a buffer the caller owns.
void a_negative_integer_yields_its_magnitude() {
    struct testcase {
        std::vector<std::uint8_t> encoded;
        std::vector<std::uint8_t> magnitude;
    };
    const testcase cases[] = {
        {bytes({0x02, 0x01, 0xFF}), bytes({0x01})},                 // -1
        {bytes({0x02, 0x01, 0x80}), bytes({0x80})},                 // -128
        {bytes({0x02, 0x02, 0xFF, 0x01}), bytes({0xFF})},           // -255, one byte wide
        {bytes({0x02, 0x02, 0xFF, 0x00}), bytes({0x01, 0x00})},     // -256, two
        {bytes({0x02, 0x02, 0x80, 0x00}), bytes({0x80, 0x00})},     // -32768
    };

    for (const auto& c : cases) {
        auto p = over(c.encoded);
        const auto number = p.integer();
        CHECK(number.has_value());
        CHECK(number->negative());
        CHECK(number->magnitude() == nullptr);  // nowhere in the document to point at
        CHECK(number->magnitude_size() == c.magnitude.size());

        std::uint8_t out[8] = {};
        CHECK(number->magnitude_into(out, sizeof(out)));
        CHECK(std::equal(c.magnitude.begin(), c.magnitude.end(), out));
    }
}

void a_magnitude_does_not_overrun_the_caller_buffer() {
    const auto data = bytes({0x02, 0x02, 0xFF, 0x00});  // -256, two bytes of magnitude
    auto p = over(data);

    const auto number = p.integer();
    CHECK(number.has_value());
    std::uint8_t one[1] = {0xAA};
    CHECK(!number->magnitude_into(one, sizeof(one)));
    CHECK(one[0] == 0xAA);  // refused, not half-written
}

void a_negative_integer_is_not_an_unsigned_one() {
    const auto data = bytes({0x02, 0x01, 0xFF});
    auto p = over(data);

    CHECK(!p.unsigned_integer().has_value());
    CHECK(p.failure() == error::negative_integer);
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

// An arc is a base-128 number, and base 128 has no leading zero digit any more
// than base ten does. A 0x80 opening one is padding, and padding is a second
// encoding of an identifier that already has one.
void an_oid_arc_written_the_long_way_is_refused() {
    // 840 as 0x80 0x86 0x48 rather than 0x86 0x48.
    const auto first_arc = bytes({0x06, 0x04, 0x2A, 0x80, 0x86, 0x48});
    auto p = over(first_arc);
    CHECK(!p.oid().has_value());
    CHECK(p.failure() == error::non_minimal_oid_arc);

    // The same padding in an arc that is not the first one.
    const auto later_arc = bytes({0x06, 0x05, 0x2A, 0x86, 0x48, 0x80, 0x01});
    auto q = over(later_arc);
    CHECK(!q.oid().has_value());
    CHECK(q.failure() == error::non_minimal_oid_arc);

    // The same identifier written the one way DER allows.
    const auto minimal = bytes({0x06, 0x04, 0x2A, 0x86, 0x48, 0x01});
    auto r = over(minimal);
    const auto oid = r.oid();
    CHECK(oid.has_value());
    CHECK(*oid == "1.2.840.1");
}

// The first content byte counts the bits the last one does not use, so the
// value is the bytes after it.
void reads_a_bit_string() {
    // 05 A0: three bits, 101, the shape a KeyUsage is written in.
    const auto data = bytes({0x03, 0x02, 0x05, 0xA0});
    auto p = over(data);

    const auto value = p.bits();
    CHECK(value.has_value());
    CHECK(value->unused == 5u);
    CHECK(value->size == 1u);
    CHECK(value->bytes == data.data() + 3);  // a view, not a copy
    CHECK(value->bit_count() == 3u);
    CHECK(value->bit(0));
    CHECK(!value->bit(1));
    CHECK(value->bit(2));
    CHECK(!value->bit(3));  // past the last bit, not into the padding
    CHECK(p.at_end());
}

void an_empty_bit_string_holds_no_bits() {
    const auto data = bytes({0x03, 0x01, 0x00});
    auto p = over(data);

    const auto value = p.bits();
    CHECK(value.has_value());
    CHECK(value->empty());
    CHECK(value->size == 0u);
    CHECK(value->bit_count() == 0u);
    CHECK(!value->bit(0));
    CHECK(p.at_end());
}

void a_bit_string_without_its_unused_bits_byte_is_refused() {
    const auto data = bytes({0x03, 0x00});
    auto p = over(data);

    CHECK(!p.bits().has_value());
    CHECK(p.failure() == error::missing_unused_bits);
}

// The count is of bits left over in one byte, so eight of them counts a byte
// that is not there.
void more_than_seven_unused_bits_is_refused() {
    const auto data = bytes({0x03, 0x02, 0x08, 0x00});
    auto p = over(data);

    CHECK(!p.bits().has_value());
    CHECK(p.failure() == error::unused_bits_out_of_range);
}

// With nothing after the count there is no final byte to leave bits unused in.
void an_empty_bit_string_may_not_leave_bits_unused() {
    const auto data = bytes({0x03, 0x01, 0x03});
    auto p = over(data);

    CHECK(!p.bits().has_value());
    CHECK(p.failure() == error::unused_bits_without_content);
}

// Unused bits that carry anything are room for two parsers to read one bit
// string differently.
void unused_bits_that_carry_a_value_are_refused() {
    const auto data = bytes({0x03, 0x02, 0x05, 0xA1});
    auto p = over(data);
    CHECK(!p.bits().has_value());
    CHECK(p.failure() == error::non_zero_unused_bits);

    // Seven unused bits are fine when they really are unused.
    const auto one_bit = bytes({0x03, 0x02, 0x07, 0x80});
    auto q = over(one_bit);
    const auto value = q.bits();
    CHECK(value.has_value());
    CHECK(value->bit_count() == 1u);
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
                   error::reserved_length, error::length_too_large, error::unexpected_tag,
                   error::padded_integer, error::sign_extended_integer, error::negative_integer,
                   error::empty_integer, error::malformed_oid, error::non_minimal_oid_arc,
                   error::missing_unused_bits, error::unused_bits_out_of_range,
                   error::unused_bits_without_content, error::non_zero_unused_bits,
                   error::trailing_data}) {
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
    the_largest_short_form_length_may_not_use_the_long_form();
    a_long_form_length_with_a_leading_zero_is_refused();
    a_reserved_length_byte_is_refused();
    a_length_wider_than_a_size_type_is_refused();
    a_genuinely_long_length_is_accepted();
    a_zero_length_element_reads_no_content();
    an_element_longer_than_the_document_is_refused();
    a_length_far_past_the_end_is_refused_before_the_content();
    an_inner_length_cannot_reach_past_its_parent();
    a_padded_integer_is_refused();
    a_sign_extended_integer_is_refused();
    integer_zero_and_an_empty_integer();
    an_integer_too_wide_for_the_result_type_is_refused();
    a_big_integer_view_points_into_the_document();
    a_big_integer_view_of_zero_has_no_magnitude();
    a_negative_integer_yields_its_magnitude();
    a_magnitude_does_not_overrun_the_caller_buffer();
    a_negative_integer_is_not_an_unsigned_one();
    reads_an_object_identifier();
    an_oid_that_ends_mid_arc_is_refused();
    an_oid_arc_written_the_long_way_is_refused();
    reads_a_bit_string();
    an_empty_bit_string_holds_no_bits();
    a_bit_string_without_its_unused_bits_byte_is_refused();
    more_than_seven_unused_bits_is_refused();
    an_empty_bit_string_may_not_leave_bits_unused();
    unused_bits_that_carry_a_value_are_refused();
    a_multibyte_first_subidentifier_is_refused_not_misread();
    trailing_data_is_refused();
    the_wrong_tag_is_refused_and_the_failure_sticks();
    high_tag_numbers_are_refused_rather_than_guessed();
    every_error_has_words();
    return harness::report("derstrict");
}
