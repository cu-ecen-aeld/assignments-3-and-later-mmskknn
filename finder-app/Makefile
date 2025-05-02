# Compiler prefix (override from command line if needed)
CROSS_COMPILE ?=

# CC will use CROSS_COMPILE prefix, evaluated at runtime
CC = $(CROSS_COMPILE)gcc

# Compiler flags
CFLAGS = -Wall -Wextra -O2

# Target binary and sources
TARGET = writer
SRCS = writer.c
OBJS = $(SRCS:.c=.o)

# Default target
all: $(TARGET)

# Build the target
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

# Clean target
clean:
	rm -f $(TARGET) $(OBJS)

.PHONY: all clean

