# Compiler settings
CXX = g++
CC = gcc

CXXFLAGS = -O2 -std=c++20 -Wall -Wextra -pedantic -pthread
CFLAGS = -O2 -Wall -Wextra -pedantic

# Targets
all: mapper gatherd

# Build mapper (C++)
mapper: mapper.cpp
	$(CXX) $(CXXFLAGS) -o mapper mapper.cpp -lm

# Build gatherd (C)
gatherd: gatherd.c
	$(CC) $(CFLAGS) -o gatherd gatherd.c

# Clean build artifacts
clean:
	rm -f mapper gatherd *.o a.out

# Run a quick test (optional)
run:
	./gatherd > sample.json
	./mapper sample.json
