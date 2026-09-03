CXX ?= g++
CXXFLAGS ?= -O3 -std=c++17 -march=native -mtune=native -funroll-loops -Wall -Wextra -pthread
LDFLAGS ?= -lsecp256k1 -lcurl -lssl -lcrypto -lpthread -latomic

TARGET = puzzle71_solver
SRC = puzzle71_solver.cpp

.PHONY: all portable clean run benchmark analyze help

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS)
	chmod +x $(TARGET)
	@echo "=========================================================="
	@echo "Build successful: ./$(TARGET)"
	@echo "Run with: ./$(TARGET) --puzzle 71 --user lucky --workers max"
	@echo "=========================================================="

# Portable build without -march=native (for running on older/different CPU architectures)
portable:
	$(CXX) -O3 -std=c++17 -funroll-loops -Wall -Wextra -pthread -o $(TARGET) $(SRC) $(LDFLAGS)
	chmod +x $(TARGET)

run: $(TARGET)
	./$(TARGET) --puzzle 71 --user lucky --workers max

benchmark: $(TARGET)
	./$(TARGET) --benchmark

analyze: $(TARGET)
	./$(TARGET) --puzzle 71 --analyze

clean:
	rm -f $(TARGET) *.o

help:
	@echo "Available make targets:"
	@echo "  make            - Build optimized binary with native architecture flags"
	@echo "  make portable   - Build portable binary (works on any x86_64 CPU)"
	@echo "  make run        - Build and run with user 'lucky' and max workers"
	@echo "  make benchmark  - Run local 1M keys performance test"
	@echo "  make analyze    - Display mathematical analysis for Puzzle 71"
	@echo "  make clean      - Remove binary and intermediate files"
