# =========================
# Build configuration
# =========================

CXX = g++
CC = gcc

CXXFLAGS = -O2 -std=c++20 -Wall -Wextra -pedantic -pthread
CFLAGS = -O2 -Wall -Wextra -pedantic

MAPPER = mapper
GATHERD = gatherd

.PHONY: all clean run test configure

# Default
all: $(MAPPER) $(GATHERD)

# =========================
# Configure (toolchain check)
# =========================

configure:
	@echo "Checking for gcc..."
	@command -v $(CC) >/dev/null 2>&1 || { echo "ERROR: gcc not found"; exit 1; }

	@echo "Checking for g++..."
	@command -v $(CXX) >/dev/null 2>&1 || { echo "ERROR: g++ not found"; exit 1; }

	@echo "Testing gcc compilation..."
	@echo 'int main(){return 0;}' > test.c
	@$(CC) test.c -o test_gcc || { echo "ERROR: gcc failed"; rm -f test.c test_gcc; exit 1; }

	@echo "Testing g++ compilation..."
	@echo 'int main(){return 0;}' > test.cpp
	@$(CXX) test.cpp -o test_gpp || { echo "ERROR: g++ failed"; rm -f test.cpp test_gpp; exit 1; }

	@rm -f test.c test.cpp test_gcc test_gpp

	@echo "Configure check passed."

# =========================
# Build targets
# =========================

$(MAPPER): mapper.cpp
	$(CXX) $(CXXFLAGS) -o $(MAPPER) mapper.cpp -lm

$(GATHERD): gatherd.c
	$(CC) $(CFLAGS) -o $(GATHERD) gatherd.c

# =========================
# Test (CI-safe)
# =========================

test: all
	@echo "Running gatherd test..."
	./$(GATHERD) -o output.json -json

	@echo "Checking output.json exists..."
	test -f output.json

	@echo "Checking output.json is not empty..."
	test -s output.json

	@echo "Basic test passed."

# =========================
# Run full system
# =========================

run: all
	@echo "Running gatherd..."
	./$(GATHERD) -o output.json -json

	@echo "Starting mapper server on http://localhost:8090 ..."
	./$(MAPPER) --port 8090

# =========================
# Cleanup
# =========================

clean:
	rm -f $(MAPPER) $(GATHERD) *.o output.json
