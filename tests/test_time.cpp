// UTCTime and GeneralizedTime: the grammar checked digit by digit, the seconds
// required, the zone required to be Z, and the date checked against a calendar.
#include "derstrict/derstrict.hpp"

#include <cstdint>
#include <initializer_list>
#include <string>
#include <vector>

#include "harness.hpp"

using namespace derstrict;

namespace {

std::vector<std::uint8_t> bytes(std::initializer_list<int> values) {
    return std::vector<std::uint8_t>(values.begin(), values.end());
}

// The text of a time in the shortest header that carries it.
std::vector<std::uint8_t> timed(std::uint8_t raw_tag, const std::string& text) {
    std::vector<std::uint8_t> out{raw_tag, static_cast<std::uint8_t>(text.size())};
    out.insert(out.end(), text.begin(), text.end());
    return out;
}

std::vector<std::uint8_t> utc(const std::string& text) { return timed(0x17, text); }

std::vector<std::uint8_t> generalized(const std::string& text) { return timed(0x18, text); }

parser over(const std::vector<std::uint8_t>& data) { return parser{data.data(), data.size()}; }

void reads_a_utc_time() {
    const auto data = utc("250101120000Z");
    auto p = over(data);

    const auto t = p.utc_time();
    CHECK(t.has_value());
    if (!t) return;
    CHECK(t->year == 2025);
    CHECK(t->month == 1);
    CHECK(t->day == 1);
    CHECK(t->hour == 12);
    CHECK(t->minute == 0);
    CHECK(t->second == 0);
    CHECK(!t->has_fraction());
    CHECK(p.at_end());
}

void reads_a_generalized_time() {
    const auto data = generalized("19991231235959Z");
    auto p = over(data);

    const auto t = p.generalized_time();
    CHECK(t.has_value());
    if (!t) return;
    CHECK(t->year == 1999);
    CHECK(t->month == 12);
    CHECK(t->day == 31);
    CHECK(t->hour == 23);
    CHECK(t->minute == 59);
    CHECK(t->second == 59);
    CHECK(p.at_end());
}

// The fraction is handed back as the digits it was written as: rounding it into
// a number would decide how much of it matters, which is the schema's business.
void a_fraction_is_handed_back_as_digits() {
    const auto data = generalized("19991231235959.25Z");
    auto p = over(data);

    const auto t = p.generalized_time();
    CHECK(t.has_value());
    if (!t) return;
    CHECK(t->second == 59);
    CHECK(t->has_fraction());
    CHECK(t->fraction_digits == 2u);
    CHECK(t->fraction == data.data() + 17);  // a view into the document
    CHECK(t->fraction[0] == '2');
}

// A two-digit year has no century of its own, so one is supplied: X.509 fixes
// the 1950-2049 window, and reading it any other way dates the same certificate
// differently from every peer.
void a_two_digit_year_is_read_on_the_1950_window() {
    const auto older = utc("500101000000Z");
    auto p = over(older);
    const auto early = p.utc_time();
    CHECK(early.has_value());
    if (early) CHECK(early->year == 1950);

    const auto newer = utc("490101000000Z");
    auto q = over(newer);
    const auto late = q.utc_time();
    CHECK(late.has_value());
    if (late) CHECK(late->year == 2049);
}

// The century rule decides the leap day, so the four-digit year has to reach the
// check that uses it.
void a_leap_day_is_read_on_the_gregorian_rule() {
    const auto leap = utc("240229120000Z");
    auto p = over(leap);
    CHECK(p.utc_time().has_value());

    const auto four_hundred = generalized("20000229120000Z");
    auto q = over(four_hundred);
    CHECK(q.generalized_time().has_value());

    const auto century = generalized("21000229120000Z");
    auto r = over(century);
    CHECK(!r.generalized_time().has_value());
    CHECK(r.failure() == error::time_out_of_range);
}

// Every spelling DER does not write, read through the CHOICE that takes both
// types, so each one is still held to its own grammar.
void a_time_outside_ders_grammar_is_refused() {
    struct refusal {
        std::uint8_t raw_tag;
        const char* text;
        error expected;
    };
    const refusal cases[] = {
        {0x17, "2501011200Z", error::time_missing_seconds},
        {0x17, "250101120000", error::time_not_zulu},
        {0x17, "250101120000+0200", error::time_not_zulu},
        {0x17, "250101120000z", error::time_not_zulu},
        {0x17, "250101120000.5Z", error::time_fractional_seconds},
        {0x17, "2501011200O0Z", error::time_not_digits},  // the letter, not the digit
        {0x17, "251301120000Z", error::time_out_of_range},
        {0x17, "250100120000Z", error::time_out_of_range},
        {0x17, "250101240000Z", error::time_out_of_range},  // midnight is 000000
        {0x17, "250101126000Z", error::time_out_of_range},
        {0x17, "250101120060Z", error::time_out_of_range},
        {0x17, "250230120000Z", error::time_out_of_range},  // February has no 30th
        {0x17, "25010112000Z", error::malformed_time},
        {0x18, "199912312359Z", error::time_missing_seconds},
        {0x18, "1999123123Z", error::time_missing_seconds},
        {0x18, "199912312359.5Z", error::time_missing_seconds},
        {0x18, "19991231235959.50Z", error::non_minimal_time_fraction},
        {0x18, "19991231235959.0Z", error::non_minimal_time_fraction},
        {0x18, "19991231235959.Z", error::malformed_time},
        {0x18, "19991231235959,5Z", error::malformed_time},  // the comma is BER's
        {0x18, "19991231235959", error::time_not_zulu},
        {0x18, "2025 101120000Z", error::time_not_digits},
        {0x18, "Z", error::malformed_time},
        {0x18, "", error::malformed_time},
    };

    for (const auto& c : cases) {
        const auto data = timed(c.raw_tag, c.text);
        auto p = over(data);
        CHECK(!p.time().has_value());
        CHECK(p.failure() == c.expected);
    }
}

// Validity is a CHOICE of the two types, and nothing else is a time.
void either_time_is_read_where_the_choice_allows_both() {
    const auto older = utc("250101120000Z");
    auto p = over(older);
    const auto from_utc = p.time();
    CHECK(from_utc.has_value());
    if (from_utc) CHECK(from_utc->year == 2025);

    const auto newer = generalized("20250101120000Z");
    auto q = over(newer);
    const auto from_generalized = q.time();
    CHECK(from_generalized.has_value());
    if (from_generalized) CHECK(from_generalized->year == 2025);

    const auto integer = bytes({0x02, 0x01, 0x01});
    auto r = over(integer);
    CHECK(!r.time().has_value());
    CHECK(r.failure() == error::unexpected_tag);
}

void a_generalized_time_is_not_a_utc_time() {
    const auto four_digit = generalized("20250101120000Z");
    auto p = over(four_digit);
    CHECK(!p.utc_time().has_value());
    CHECK(p.failure() == error::unexpected_tag);

    const auto two_digit = utc("250101120000Z");
    auto q = over(two_digit);
    CHECK(!q.generalized_time().has_value());
    CHECK(q.failure() == error::unexpected_tag);
}

// A time is read out of an element, so the length rules are decided first: an
// element that spells its length the long way never reaches its content.
void a_time_inherits_the_element_rules() {
    auto data = utc("250101120000Z");
    data[1] = 0x81;
    data.insert(data.begin() + 2, 0x0D);
    auto p = over(data);

    CHECK(!p.utc_time().has_value());
    CHECK(p.failure() == error::non_minimal_length);
}

void every_time_error_has_words() {
    for (auto e : {error::malformed_time, error::time_not_digits, error::time_missing_seconds,
                   error::time_not_zulu, error::time_fractional_seconds,
                   error::non_minimal_time_fraction, error::time_out_of_range}) {
        CHECK(describe(e)[0] != '\0');
    }
}

}  // namespace

int main() {
    reads_a_utc_time();
    reads_a_generalized_time();
    a_fraction_is_handed_back_as_digits();
    a_two_digit_year_is_read_on_the_1950_window();
    a_leap_day_is_read_on_the_gregorian_rule();
    a_time_outside_ders_grammar_is_refused();
    either_time_is_read_where_the_choice_allows_both();
    a_generalized_time_is_not_a_utc_time();
    a_time_inherits_the_element_rules();
    every_time_error_has_words();
    return harness::report("derstrict time");
}
