# =========================
# Build configuration
# =========================

CXX = g++
CC = gcc

CXXFLAGS = -O2 -std=c++20 -Wall -Wextra -pedantic -pthread
CFLAGS = -O2 -Wall -Wextra -pedantic

# Output names
MAPPER = mapper
GATHERD = gatherd

# Default target
.PHONY: all clean run test

all: $(MAPPER) $(GATHERD)

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
