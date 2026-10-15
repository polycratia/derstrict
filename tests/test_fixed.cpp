// BOOLEAN and NULL: the two types whose content DER fixes completely. One is a
// single byte with two legal values, the other has no content at all, so every
// other byte sequence under those tags is a second encoding of something that
// already has one.
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

void reads_a_boolean() {
    const auto no = bytes({0x01, 0x01, 0x00});
    auto p = over(no);
    const auto first = p.boolean();
    CHECK(first.has_value());
    if (first) CHECK(*first == false);
    CHECK(p.at_end());

    const auto yes = bytes({0x01, 0x01, 0xFF});
    auto q = over(yes);
    const auto second = q.boolean();
    CHECK(second.has_value());
    if (second) CHECK(*second == true);
    CHECK(q.at_end());
}

// DER writes true as 0xFF, and BER reads every non-zero byte as true: 0x01 is
// its second spelling of a value that already has one. Taking any of them would
// read 254 documents as the one DER defines.
void a_boolean_in_any_other_spelling_is_refused() {
    for (int value = 0x00; value <= 0xFF; ++value) {
        if (value == 0x00 || value == 0xFF) continue;
        const auto data = bytes({0x01, 0x01, value});
        auto p = over(data);
        CHECK(!p.boolean().has_value());
        CHECK(p.failure() == error::non_canonical_boolean);
    }
}

// The content is one byte: none of them says nothing, and two of them leave a
// reader to decide which one is the value.
void a_boolean_that_is_not_one_byte_is_refused() {
    const auto empty = bytes({0x01, 0x00});
    auto p = over(empty);
    CHECK(!p.boolean().has_value());
    CHECK(p.failure() == error::malformed_boolean);

    const auto two = bytes({0x01, 0x02, 0x00, 0xFF});
    auto q = over(two);
    CHECK(!q.boolean().has_value());
    CHECK(q.failure() == error::malformed_boolean);
}

void reads_a_null() {
    const auto data = bytes({0x05, 0x00});
    auto p = over(data);

    CHECK(p.null_value());
    CHECK(p.at_end());
}

// A NULL's value is its presence, so any content byte carries something the
// type cannot hold — a zero included, which reads like an empty value and is
// not one.
void a_null_carrying_content_is_refused() {
    const auto zero = bytes({0x05, 0x01, 0x00});
    auto p = over(zero);
    CHECK(!p.null_value());
    CHECK(p.failure() == error::malformed_null);

    const auto wider = bytes({0x05, 0x02, 0xAA, 0xAA});
    auto q = over(wider);
    CHECK(!q.null_value());
    CHECK(q.failure() == error::malformed_null);
}

void a_boolean_is_not_a_null() {
    const auto null_document = bytes({0x05, 0x00});
    auto p = over(null_document);
    CHECK(!p.boolean().has_value());
    CHECK(p.failure() == error::unexpected_tag);

    const auto boolean_document = bytes({0x01, 0x01, 0xFF});
    auto q = over(boolean_document);
    CHECK(!q.null_value());
    CHECK(q.failure() == error::unexpected_tag);
}

// Both are read out of an element, so the length rules are decided first: one
// that spells its length the long way never reaches its content.
void the_fixed_types_inherit_the_element_rules() {
    const auto boolean_document = bytes({0x01, 0x81, 0x01, 0xFF});
    auto p = over(boolean_document);
    CHECK(!p.boolean().has_value());
    CHECK(p.failure() == error::non_minimal_length);

    const auto null_document = bytes({0x05, 0x80});
    auto q = over(null_document);
    CHECK(!q.null_value());
    CHECK(q.failure() == error::indefinite_length);
}

// A NULL is what an AlgorithmIdentifier writes for absent parameters, which is
// where these two readers actually meet a certificate.
void the_fixed_types_read_as_children() {
    // SEQUENCE { BOOLEAN TRUE, NULL }
    const auto data = bytes({0x30, 0x05, 0x01, 0x01, 0xFF, 0x05, 0x00});
    auto p = over(data);

    const auto opened = p.sequence();
    CHECK(opened.has_value());
    if (!opened) return;

    auto children = *opened;
    CHECK(children.boolean() == true);
    CHECK(children.null_value());
    CHECK(children.at_end());
    CHECK(p.at_end());
}

void every_fixed_error_has_words() {
    for (auto e : {error::malformed_boolean, error::non_canonical_boolean, error::malformed_null}) {
        CHECK(describe(e)[0] != '\0');
    }
}

}  // namespace

int main() {
    reads_a_boolean();
    a_boolean_in_any_other_spelling_is_refused();
    a_boolean_that_is_not_one_byte_is_refused();
    reads_a_null();
    a_null_carrying_content_is_refused();
    a_boolean_is_not_a_null();
    the_fixed_types_inherit_the_element_rules();
    the_fixed_types_read_as_children();
    every_fixed_error_has_words();
    return harness::report("derstrict fixed");
}
