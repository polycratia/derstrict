// The identifier octet taken apart: the class whose numbering the tag came
// from, the form, and the number — and the one form X.690 gives a universal
// tag, which is a rule about that byte and so holds with or without a schema.
#include "derstrict/derstrict.hpp"

#include <cstdint>
#include <cstdio>
#include <initializer_list>
#include <vector>

#include "harness.hpp"

using namespace derstrict;

namespace {

std::vector<std::uint8_t> bytes(std::initializer_list<int> values) {
    return std::vector<std::uint8_t>(values.begin(), values.end());
}

parser over(const std::vector<std::uint8_t>& data) { return parser{data.data(), data.size()}; }

void the_identifier_octet_splits_into_three_fields() {
    const auto data = bytes({0x30, 0x03, 0x02, 0x01, 0x01});
    auto p = over(data);

    const auto seq = p.next();
    CHECK(seq.has_value());
    if (!seq) return;
    CHECK(seq->universal());
    CHECK(seq->element_class() == tag_class::universal);
    CHECK(seq->constructed());
    CHECK(seq->number() == 16u);

    auto inner = p.into(*seq);
    const auto child = inner.next();
    CHECK(child.has_value());
    if (!child) return;
    CHECK(!child->constructed());
    CHECK(child->number() == 2u);

    // The same number under each of the four numberings: only the class bits
    // differ, which is why they are read rather than assumed.
    struct classed {
        int raw_tag;
        tag_class expected;
    };
    const classed cases[] = {
        {0x02, tag_class::universal},
        {0x42, tag_class::application},
        {0x82, tag_class::context_specific},
        {0xC2, tag_class::private_class},
    };
    for (const auto& c : cases) {
        const auto one = bytes({c.raw_tag, 0x01, 0x01});
        auto q = over(one);
        const auto e = q.next();
        CHECK(e.has_value());
        if (!e) continue;
        CHECK(e->element_class() == c.expected);
        CHECK(e->number() == 2u);
        CHECK(q.at_end());
    }
}

// X.680 gives each of its types one form, so the other one is not that type: a
// constructed INTEGER or OCTET STRING is BER's fragmentation of something DER
// writes whole, and a primitive SEQUENCE claims a value where there are
// children.
void a_universal_tag_in_the_wrong_form_is_refused() {
    struct refusal {
        const char* what;
        std::vector<std::uint8_t> encoding;
    };
    const refusal cases[] = {
        {"a constructed boolean", bytes({0x21, 0x03, 0x01, 0x01, 0xFF})},
        {"a constructed integer", bytes({0x22, 0x03, 0x02, 0x01, 0x01})},
        {"a fragmented bit string", bytes({0x23, 0x06, 0x03, 0x01, 0x00, 0x03, 0x01, 0x00})},
        {"a fragmented octet string", bytes({0x24, 0x06, 0x04, 0x01, 0x41, 0x04, 0x01, 0x42})},
        {"a constructed null", bytes({0x25, 0x00})},
        {"a constructed object identifier", bytes({0x26, 0x03, 0x2A, 0x86, 0x48})},
        {"a constructed utf8 string", bytes({0x2C, 0x03, 0x04, 0x01, 0x41})},
        {"a constructed utc time", bytes({0x37, 0x02, 0x17, 0x00})},
        {"a primitive sequence", bytes({0x10, 0x03, 0x02, 0x01, 0x01})},
        {"a primitive set", bytes({0x11, 0x03, 0x02, 0x01, 0x01})},
    };

    for (const auto& c : cases) {
        auto p = over(c.encoding);
        CHECK(!p.next().has_value());
        CHECK(p.failure() == error::wrong_tag_form);
        if (p.failure() != error::wrong_tag_form) {
            std::printf("    %s: %s\n", c.what, describe(p.failure()));
        }
    }
}

// The rule is decided on the identifier octet, so a typed read meets it before
// the tag it wanted is weighed: the refusal names the form and not the tag.
void the_form_is_decided_before_the_tag_is_wanted() {
    const auto data = bytes({0x22, 0x03, 0x02, 0x01, 0x01});
    auto p = over(data);

    CHECK(!p.integer().has_value());
    CHECK(p.failure() == error::wrong_tag_form);
}

// An untyped walk has no schema to say what the element should have been, and
// it refuses the same bytes, which is what keeps the rule out of the callers.
void the_form_rule_holds_in_an_untyped_walk() {
    // SEQUENCE { constructed OCTET STRING { OCTET STRING "A" } }
    const auto data = bytes({0x30, 0x05, 0x24, 0x03, 0x04, 0x01, 0x41});
    auto p = over(data);

    const auto opened = p.sequence();
    CHECK(opened.has_value());
    if (!opened) return;

    auto children = *opened;
    CHECK(children.more());
    CHECK(!children.next().has_value());
    CHECK(children.failure() == error::wrong_tag_form);
}

// The rule is X.680's numbering, so it reaches only the class that numbering
// belongs to. A schema picks the form of its own tags — [0] holding an element
// is constructed, [0] holding a value is primitive — and both are written.
void a_tag_of_another_class_keeps_both_forms() {
    for (const int raw_tag : {0x80, 0xA0, 0x40, 0x60, 0xC0, 0xE0}) {
        const auto data = bytes({raw_tag, 0x03, 0x02, 0x01, 0x01});
        auto p = over(data);
        CHECK(p.next().has_value());
        CHECK(p.at_end());
    }
}

// No type has been assigned every universal number, and a reader that fixed a
// form for an unassigned one would be refusing on an assumption rather than on
// a rule, so those keep the bytes they were written with.
void a_universal_number_without_an_assigned_form_is_left_alone() {
    CHECK(!universal_form(15).has_value());
    for (const int raw_tag : {0x0F, 0x2F}) {
        const auto data = bytes({raw_tag, 0x00});
        auto p = over(data);
        CHECK(p.next().has_value());
        CHECK(p.at_end());
    }
}

// A context-specific number is the schema's, so the element is asked for by
// number. Both tagging styles arrive: [0] wrapping an element, and [2] retagging
// one, which the encoding does not distinguish.
void a_context_specific_element_is_asked_for_by_number() {
    // SEQUENCE { [0] { INTEGER 1 }, [2] 0x41 }
    const auto data = bytes({0x30, 0x08, 0xA0, 0x03, 0x02, 0x01, 0x01, 0x82, 0x01, 0x41});
    auto p = over(data);

    const auto opened = p.sequence();
    CHECK(opened.has_value());
    if (!opened) return;
    auto fields = *opened;

    const auto wrapper = fields.context(0);
    CHECK(wrapper.has_value());
    if (!wrapper) return;
    CHECK(wrapper->constructed());
    auto wrapped = fields.into(*wrapper);
    CHECK(wrapped.unsigned_integer() == 1u);
    CHECK(wrapped.at_end());

    const auto retagged = fields.context(2);
    CHECK(retagged.has_value());
    if (!retagged) return;
    CHECK(!retagged->constructed());
    CHECK(retagged->length == 1u);
    CHECK(retagged->content[0] == 0x41);

    CHECK(fields.at_end());
    CHECK(p.at_end());
}

// Another number, or the same number from another numbering, is not the element
// that was asked for — which is the whole reason the class is read.
void a_tag_with_another_number_or_class_is_not_the_one_asked_for() {
    const auto other_number = bytes({0xA1, 0x03, 0x02, 0x01, 0x01});
    auto p = over(other_number);
    CHECK(!p.context(0).has_value());
    CHECK(p.failure() == error::unexpected_tag);

    // An application tag numbered 2 differs from [2] only in the class bits.
    const auto other_class = bytes({0x62, 0x03, 0x02, 0x01, 0x01});
    auto q = over(other_class);
    CHECK(!q.context(2).has_value());
    CHECK(q.failure() == error::unexpected_tag);

    // And 0x02 numbers an INTEGER in X.680's class, not in the schema's.
    const auto universal = bytes({0x02, 0x01, 0x01});
    auto r = over(universal);
    CHECK(!r.context(2).has_value());
    CHECK(r.failure() == error::unexpected_tag);
}

void every_identifier_error_has_words() {
    for (auto e : {error::wrong_tag_form, error::unexpected_tag}) {
        CHECK(describe(e)[0] != '\0');
    }
}

}  // namespace

int main() {
    the_identifier_octet_splits_into_three_fields();
    a_universal_tag_in_the_wrong_form_is_refused();
    the_form_is_decided_before_the_tag_is_wanted();
    the_form_rule_holds_in_an_untyped_walk();
    a_tag_of_another_class_keeps_both_forms();
    a_universal_number_without_an_assigned_form_is_left_alone();
    a_context_specific_element_is_asked_for_by_number();
    a_tag_with_another_number_or_class_is_not_the_one_asked_for();
    every_identifier_error_has_words();
    return harness::report("derstrict identifier");
}
