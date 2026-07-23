CFLAGS ?= -Wall -Wextra -pedantic -Werror -std=gnu11 -Og -g
LDFLAGS ?= -O1 -static
BINARIES = seccomp-dump

default: $(BINARIES)

%: %.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

.PHONY: default clean
clean:
	rm -f $(BINARIES)

