# seccomp-dump

A small self-contained utility to fetch the seccomp-BPF filter(s) used by a thread from the kernel, and allow you to inspect their raw contents (instructions).

## Requirements

This tool uses the `ptrace(PTRACE_SECCOMP_GET_FILTER)` system call flag available only in Linux 4.4 and above.
Using that API requires `CAP_SYS_ADMIN`, so you will need to execute this helper as root.

## Usage

For instance, if you want to fetch the raw seccomp filters applied by a default podman container:

```
$ podman run -d --rm alpine /bin/sh -c "sleep 60"
$ sudo ./seccomp-dump `pidof sleep` /tmp/podmanfilters
Filter 0 : 1165 instructions
Successfully dumped 1 filter
$ ls /tmp/podmanfilters*
/tmp/podmanfilters.0

$ hexdump -C /tmp/podmanfilters.0
00000000  20 00 00 00 04 00 00 00  15 00 01 00 3e 00 00 c0  | ...........>...|
00000010  05 00 00 00 d1 02 00 00  20 00 00 00 00 00 00 00  |........ .......|
00000020  15 00 82 00 00 00 00 00  15 00 81 00 01 00 00 00  |................|
00000030  15 00 80 00 02 00 00 00  15 00 7f 00 03 00 00 00  |................|
[...]
```

## Compilation

```
$ git clone https://github.com/mtth-bfft/seccomp-dump
$ cd seccomp-dump
$ make
```

## Analysis

Okay, you have a seccomp filter dump, but it is just a binary program.
Want to analyze which system calls it allows? https://github.com/mtth-bfft/seccomp-analyze might help you with that.

## Online resources

- https://www.kernel.org/doc/Documentation/networking/filter.txt
- https://www.kernel.org/doc/Documentation/userspace-api/seccomp_filter.rst
- https://github.com/seccomp/libseccomp
- https://www.freebsd.org/cgi/man.cgi?query=bpf&sektion=4

