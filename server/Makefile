# Compiler prefix (override from command line if needed)
CROSS_COMPILE ?=

# CC will use CROSS_COMPILE prefix, evaluated at runtime
CC ?= $(CROSS_COMPILE)gcc

# Compiler flags
CFLAGS ?= -Wall -Werror -g

# Target binary and sources
TARGET ?= aesdsocket
SRCS = aesdsocket.c
OBJS = $(SRCS:.c=.o)

LDFLAGS ?= -lpthread -lrt

# Default target
all: $(TARGET)

default: all

# Build the target
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(INCLUDES) $(LDFLAGS)

# Clean target
clean:
	rm -f $(TARGET) $(OBJS)

.PHONY: all clean

