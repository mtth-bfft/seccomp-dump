CFLAGS ?= -Wall -Wextra -pedantic -Werror -std=gnu11 -Og -g
LDFLAGS ?= -O1 -static

default: seccomp-dump

seccomp-dump: src/main.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

.PHONY: default clean
clean:
	rm -f $(BINARIES)

