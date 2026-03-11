# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -O2

# Target executable name
TARGET = tinybox

# Source files
SRCS = tinybox.c
OBJS = $(SRCS:.c=.o)

# Default rule: build the project
all: $(TARGET)

# Link the object files to create the executable
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS)

# Compile source files into object files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean rule: remove build artifacts
clean:
	rm -f $(TARGET) $(OBJS)

# Phony targets (targets that aren't actual files)
.PHONY: all clean
