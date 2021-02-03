CFLAGS ?= -Wall -Wextra -pedantic -Werror -std=gnu11 -Og -g
LDFLAGS ?= -O1

default: seccomp-dump

seccomp-dump: src/main.c src/hexdump.c src/disassembly.c src/prolog.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

.PHONY: default clean
clean:
	rm -f $(BINARIES)

