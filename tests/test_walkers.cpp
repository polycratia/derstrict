// The SEQUENCE and SET walkers: children read one at a time, bytes left after
// the last one refused, and a SET's ordering rule enforced as it is walked.
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

void walks_the_children_of_a_sequence() {
    // SEQUENCE { INTEGER 1, OCTET STRING "A", NULL }
    const auto data = bytes({0x30, 0x08, 0x02, 0x01, 0x01, 0x04, 0x01, 0x41, 0x05, 0x00});
    auto p = over(data);

    const auto opened = p.sequence();
    CHECK(opened.has_value());
    if (!opened) return;
    CHECK(p.at_end());

    auto children = *opened;
    std::vector<std::uint8_t> tags;
    while (children.more()) {
        const auto child = children.next();
        CHECK(child.has_value());
        if (!child) break;
        tags.push_back(child->raw_tag);
    }
    CHECK(tags == bytes({0x02, 0x04, 0x05}));
    CHECK(children.at_end());
}

void an_empty_sequence_has_no_children() {
    const auto data = bytes({0x30, 0x00});
    auto p = over(data);

    const auto opened = p.sequence();
    CHECK(opened.has_value());
    if (!opened) return;

    auto children = *opened;
    CHECK(!children.more());
    CHECK(children.at_end());
    CHECK(p.at_end());
}

// A byte left over inside a SEQUENCE is not the end of the walk: it is read as
// the element it claims to be, and refused for not being one.
void a_byte_after_the_last_child_is_refused() {
    const auto data = bytes({0x30, 0x04, 0x02, 0x01, 0x01, 0x00});
    auto p = over(data);

    const auto opened = p.sequence();
    CHECK(opened.has_value());
    if (!opened) return;

    auto children = *opened;
    CHECK(children.next().has_value());
    CHECK(children.more());
    CHECK(!children.next().has_value());
    CHECK(children.failure() == error::truncated);
    CHECK(!children.more());
    CHECK(!children.at_end());
}

// A whole element the caller did not ask for is trailing data all the same.
void a_child_the_caller_did_not_read_is_trailing_data() {
    // SEQUENCE { INTEGER 1, INTEGER 2 } read as if it held one integer.
    const auto data = bytes({0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02});
    auto p = over(data);

    const auto opened = p.sequence();
    CHECK(opened.has_value());
    if (!opened) return;

    auto children = *opened;
    CHECK(children.unsigned_integer() == 1u);
    CHECK(!children.at_end());
    CHECK(children.failure() == error::trailing_data);
}

void a_set_in_order_is_accepted() {
    // SET { INTEGER 1, INTEGER 2 }
    const auto data = bytes({0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02});
    auto p = over(data);

    const auto opened = p.set();
    CHECK(opened.has_value());
    if (!opened) return;

    auto children = *opened;
    CHECK(children.unsigned_integer() == 1u);
    CHECK(children.unsigned_integer() == 2u);
    CHECK(children.at_end());
    CHECK(p.at_end());
}

// The order of a SET's elements carries no meaning, so DER fixes it. A reader
// that takes any order takes two documents where DER defines one.
void a_set_out_of_order_is_refused() {
    const auto data = bytes({0x31, 0x06, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01});
    auto p = over(data);

    const auto opened = p.set();
    CHECK(opened.has_value());
    if (!opened) return;

    auto children = *opened;
    CHECK(children.unsigned_integer() == 2u);
    CHECK(!children.unsigned_integer().has_value());
    CHECK(children.failure() == error::unsorted_set);
}

// Each element is measured against the one before it, not against the first, so
// a set that starts in order does not earn the rest of the walk.
void ordering_is_measured_against_the_element_before() {
    // SET { INTEGER 1, INTEGER 3, INTEGER 2 }
    const auto data = bytes({0x31, 0x09, 0x02, 0x01, 0x01, 0x02, 0x01, 0x03, 0x02, 0x01, 0x02});
    auto p = over(data);

    const auto opened = p.set();
    CHECK(opened.has_value());
    if (!opened) return;

    auto children = *opened;
    CHECK(children.unsigned_integer() == 1u);
    CHECK(children.unsigned_integer() == 3u);
    CHECK(!children.unsigned_integer().has_value());
    CHECK(children.failure() == error::unsorted_set);
}

// The comparison is of encodings, so the tag byte decides before the value does.
void a_set_is_sorted_by_its_encodings_not_by_its_values() {
    // SET { INTEGER 2, OCTET STRING "A" } — 0x02 opens before 0x04.
    const auto ordered = bytes({0x31, 0x06, 0x02, 0x01, 0x02, 0x04, 0x01, 0x41});
    auto p = over(ordered);
    const auto opened = p.set();
    CHECK(opened.has_value());
    if (!opened) return;
    auto children = *opened;
    CHECK(children.next().has_value());
    CHECK(children.next().has_value());
    CHECK(children.at_end());

    // The same two elements the other way round.
    const auto reversed = bytes({0x31, 0x06, 0x04, 0x01, 0x41, 0x02, 0x01, 0x02});
    auto q = over(reversed);
    const auto other = q.set();
    CHECK(other.has_value());
    if (!other) return;
    auto rest = *other;
    CHECK(rest.next().has_value());
    CHECK(!rest.next().has_value());
    CHECK(rest.failure() == error::unsorted_set);
}

// Sorting does not forbid a repeat: equal encodings are in order, and whether a
// repeated value means anything is the schema's business.
void a_set_may_repeat_an_encoding() {
    const auto data = bytes({0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01});
    auto p = over(data);

    const auto opened = p.set();
    CHECK(opened.has_value());
    if (!opened) return;

    auto children = *opened;
    CHECK(children.unsigned_integer() == 1u);
    CHECK(children.unsigned_integer() == 1u);
    CHECK(children.at_end());
}

// The rule rides on the descent, so a walk written by hand is no less strict.
void set_ordering_holds_through_a_plain_descent() {
    const auto data = bytes({0x31, 0x06, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01});
    auto p = over(data);

    const auto e = p.expect(tag::set);
    CHECK(e.has_value());
    if (!e) return;

    auto inner = p.into(*e);
    CHECK(inner.next().has_value());
    CHECK(!inner.next().has_value());
    CHECK(inner.failure() == error::unsorted_set);
}

// The rule belongs to the set, not to everything inside it: a SEQUENCE that is a
// set's child keeps the order its schema gave it.
void set_ordering_does_not_reach_into_a_child() {
    // SET { SEQUENCE { INTEGER 2, INTEGER 1 } }
    const auto data = bytes({0x31, 0x08, 0x30, 0x06, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01});
    auto p = over(data);

    const auto opened = p.set();
    CHECK(opened.has_value());
    if (!opened) return;

    auto children = *opened;
    const auto child = children.expect(tag::sequence);
    CHECK(child.has_value());
    if (!child) return;

    auto inner = children.into(*child);
    CHECK(inner.unsigned_integer() == 2u);
    CHECK(inner.unsigned_integer() == 1u);
    CHECK(inner.at_end());
    CHECK(children.at_end());
}

// A SEQUENCE's order is the schema's, not the encoding's.
void a_sequence_keeps_the_order_it_was_written_in() {
    const auto data = bytes({0x30, 0x06, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01});
    auto p = over(data);

    const auto opened = p.sequence();
    CHECK(opened.has_value());
    if (!opened) return;

    auto children = *opened;
    CHECK(children.unsigned_integer() == 2u);
    CHECK(children.unsigned_integer() == 1u);
    CHECK(children.at_end());
}

void a_set_is_not_a_sequence() {
    const auto set_document = bytes({0x31, 0x03, 0x02, 0x01, 0x01});
    auto p = over(set_document);
    CHECK(!p.sequence().has_value());
    CHECK(p.failure() == error::unexpected_tag);

    const auto sequence_document = bytes({0x30, 0x03, 0x02, 0x01, 0x01});
    auto q = over(sequence_document);
    CHECK(!q.set().has_value());
    CHECK(q.failure() == error::unexpected_tag);
}

// The ordering rule compares whole encodings, so an element has to know where
// its own tag byte is and not only where its content starts.
void an_element_carries_its_own_encoding() {
    const auto data = bytes({0x30, 0x03, 0x02, 0x01, 0x01});
    auto p = over(data);

    const auto seq = p.expect(tag::sequence);
    CHECK(seq.has_value());
    if (!seq) return;
    CHECK(seq->encoding() == data.data());
    CHECK(seq->encoded_size() == data.size());
    CHECK(seq->content == data.data() + 2);

    // A long-form length makes the header longer; the span still starts at the
    // tag byte.
    auto long_form = bytes({0x04, 0x81, 0x80});
    long_form.resize(3 + 128, 0xAA);
    auto q = over(long_form);

    const auto e = q.next();
    CHECK(e.has_value());
    if (!e) return;
    CHECK(e->encoding() == long_form.data());
    CHECK(e->encoded_size() == 131u);
}

}  // namespace

int main() {
    walks_the_children_of_a_sequence();
    an_empty_sequence_has_no_children();
    a_byte_after_the_last_child_is_refused();
    a_child_the_caller_did_not_read_is_trailing_data();
    a_set_in_order_is_accepted();
    a_set_out_of_order_is_refused();
    ordering_is_measured_against_the_element_before();
    a_set_is_sorted_by_its_encodings_not_by_its_values();
    a_set_may_repeat_an_encoding();
    set_ordering_holds_through_a_plain_descent();
    set_ordering_does_not_reach_into_a_child();
    a_sequence_keeps_the_order_it_was_written_in();
    a_set_is_not_a_sequence();
    an_element_carries_its_own_encoding();
    return harness::report("derstrict walkers");
}
