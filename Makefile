CXX ?= c++
CXXFLAGS ?= -std=c++17 -Wall -Wextra -Werror -Iinclude -Itests
# Tests run under the sanitizers: a bounds-checking library that is only
# checked by its own assertions has proved nothing.
SAN ?= -fsanitize=address,undefined -fno-omit-frame-pointer -g
# libFuzzer is clang's, so `make fuzz` wants CXX=clang++.
FUZZ ?= -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer -g
FUZZ_SECONDS ?= 30

.PHONY: test fuzz demo clean

test:
	@mkdir -p build
	$(CXX) $(CXXFLAGS) $(SAN) tests/test_derstrict.cpp -o build/tests
	$(CXX) $(CXXFLAGS) $(SAN) tests/test_walkers.cpp -o build/tests_walkers
	$(CXX) $(CXXFLAGS) $(SAN) tests/test_time.cpp -o build/tests_time
	$(CXX) $(CXXFLAGS) $(SAN) tests/test_corpus.cpp -o build/tests_corpus
	./build/tests
	./build/tests_walkers
	./build/tests_time
	./build/tests_corpus

# The corpus is written out first: a fuzzer that starts from the encodings that
# have already split parsers spends its time past them rather than rediscovering
# what a tag byte is.
fuzz:
	@mkdir -p build/corpus
	$(CXX) $(CXXFLAGS) $(SAN) tests/test_corpus.cpp -o build/tests_corpus
	./build/tests_corpus --write build/corpus
	$(CXX) $(CXXFLAGS) $(FUZZ) fuzz/fuzz_derstrict.cpp -o build/fuzz
	./build/fuzz build/corpus -max_len=4096 -max_total_time=$(FUZZ_SECONDS)

demo:
	@mkdir -p build
	$(CXX) $(CXXFLAGS) -O2 example/main.cpp -o build/demo
	./build/demo

clean:
	rm -rf build
