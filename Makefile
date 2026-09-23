CXX ?= c++
CXXFLAGS ?= -std=c++17 -Wall -Wextra -Werror -Iinclude -Itests
# Tests run under the sanitizers: a bounds-checking library that is only
# checked by its own assertions has proved nothing.
SAN ?= -fsanitize=address,undefined -fno-omit-frame-pointer -g

.PHONY: test demo clean

test:
	@mkdir -p build
	$(CXX) $(CXXFLAGS) $(SAN) tests/test_derstrict.cpp -o build/tests
	$(CXX) $(CXXFLAGS) $(SAN) tests/test_walkers.cpp -o build/tests_walkers
	./build/tests
	./build/tests_walkers

demo:
	@mkdir -p build
	$(CXX) $(CXXFLAGS) -O2 example/main.cpp -o build/demo
	./build/demo

clean:
	rm -rf build
