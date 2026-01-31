CC ?= gcc
CFLAGS ?= -std=c11 -Wall -Wextra -g3 -O0 -fno-omit-frame-pointer -fno-inline -fno-pie
LDFLAGS ?= -no-pie -lncurses

all: fast-fingers

fast-fingers: fast_fingers.c
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

.PHONY: clean
clean:
	rm -f fast-fingers
