// A test harness small enough to read in one sitting, so that a library with no
// dependencies does not acquire one just to be tested.
#pragma once

#include <cstdio>
#include <string_view>

namespace harness {

inline int checks = 0;
inline int failures = 0;

inline void check(bool ok, std::string_view expression, const char* file, int line) {
    ++checks;
    if (!ok) {
        ++failures;
        std::printf("  FAIL %s:%d\n    %.*s\n", file, line,
                    static_cast<int>(expression.size()), expression.data());
    }
}

inline int report(const char* name) {
    std::printf("%s: %d checks, %d failed\n", name, checks, failures);
    return failures == 0 ? 0 : 1;
}

}  // namespace harness

#define CHECK(expression) harness::check((expression), #expression, __FILE__, __LINE__)
