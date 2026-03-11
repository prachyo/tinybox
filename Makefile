CC = gcc
CFLAGS = -Wall -Wextra -g
SRCS = tinybox.c policy.c helpers.c
TARGET = tinybox

TEST_DIR = tests
TEST_SRCS = $(wildcard $(TEST_DIR)/*.c)
TEST_BINS = $(TEST_SRCS:$(TEST_DIR)/%.c=$(TEST_DIR)/%)

all: $(TARGET) $(TEST_BINS)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRCS)

$(TEST_DIR)/%: $(TEST_DIR)/%.c
	$(CC) $(CFLAGS) -o $@ $<

test: all
	@echo "Starting Tinybox Test Suite..."
	@for test_bin in $(TEST_BINS); do \
		echo "--------------------------------------"; \
		echo "Running: $$test_bin"; \
		./$(TARGET) ./$$test_bin; \
	done
	@echo "--------------------------------------"
	@echo "Tests Completed."

clean:
	rm -f $(TARGET) $(TEST_BINS)

.PHONY: all test clean
