CC      = gcc
CFLAGS  = -O2 -Wall -Wextra -std=c11
TARGET  = malscan

SRCS    = textutil.c bytebuf.c pattern.c rule.c malwaredef.c dirwalk.c main.c
OBJS    = $(SRCS:.c=.o)

.PHONY: all clean test debug

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Debug build with sanitizers (memory/UB checking)
debug: $(SRCS)
	$(CC) -O1 -g -fsanitize=address,undefined -Wall -Wextra -std=c11 -o $(TARGET)_debug $(SRCS)

# Note: malscan exits 1 when malware IS found -- that's a successful
# detection, not a failure, so those two lines are prefixed with '-'
# to stop make from aborting the chain on that exit code.
test: all
	-./$(TARGET) samples/malicious1.bin rules
	-./$(TARGET) samples/malicious2.bin rules
	./$(TARGET) samples/clean.txt rules

clean:
	rm -f $(TARGET) $(TARGET)_debug $(OBJS)
