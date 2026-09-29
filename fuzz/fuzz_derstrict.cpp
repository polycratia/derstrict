// A libFuzzer entry point over the same schema-free walk the corpus is read
// with.
//
//   make fuzz
//
// There is nothing to assert about what arbitrary bytes mean, so what is
// checked is what holds for every input: the walk stays inside the buffer it
// was handed, which the sanitizers decide, and it answers the same way twice,
// because a reader that does not is the disagreement this library exists to
// prevent.
#include "corpus.hpp"

#include <cstddef>
#include <cstdint>
#include <cstdlib>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    corpus::reader reader;
    const auto first = reader.read(data, size);
    const auto again = reader.read(data, size);
    if (first != again) std::abort();
    if (derstrict::describe(first)[0] == '\0') std::abort();
    return 0;
}
