# seccomp-dump

A small self-contained utility to fetch the seccomp-BPF filter used by a thread from the kernel, and allow you to inspect what filters are used by different sandboxes.

This tool uses the `ptrace(PTRACE_SECCOMP_GET_FILTER)` system call flag available in Linux 4.4 and above to fetch the binary filter program. It can then render it as a hexadecimal dump, a disassembled program, or a set of prolog facts. Fetching a seccomp filter program requires `CAP_SYS_ADMIN`, so you need to execute this helper as root.

## Compilation

```
> git clone https://github.com/mtth-bfft/seccomp-dump
> cd seccomp-dump
> make
```

## Examples

```
> sudo ./seccomp-dump -d <tid>
    ld [4]
    jneq #3221225534, L1
    ld [0]
    jneq #20, L1
    ret #0x00050001
L1: ret #0x7FFF0000

> sudo ./seccomp-dump -x <tid>
#	CLASS	CODE	JT	JF	K
0	0x00	0x0020	0x00	0x00	0x00000004
1	0x05	0x0015	0x00	0x03	0xC000003E
2	0x00	0x0020	0x00	0x00	0x00000000
3	0x05	0x0015	0x00	0x01	0x00000014
4	0x06	0x0006	0x00	0x00	0x00050001
5	0x06	0x0006	0x00	0x00	0x7FFF0000

> sudo ./seccomp-dump -p <tid>
bpf_op(0, bpf_ld_w_abs, 0x0, 0x0, 0x4).
bpf_op(1, bpf_jmp_jeq_k, 0x0, 0x3, 0xc000003e).
bpf_op(2, bpf_ld_w_abs, 0x0, 0x0, 0x0).
bpf_op(3, bpf_jmp_jeq_k, 0x0, 0x1, 0x14).
bpf_op(4, bpf_ret_k, 0x0, 0x0, 0x50001).
bpf_op(5, bpf_ret_k, 0x0, 0x0, 0x7fff0000).
```

## Online resources

- https://www.kernel.org/doc/Documentation/networking/filter.txt

- https://www.kernel.org/doc/Documentation/userspace-api/seccomp_filter.rst

- https://github.com/seccomp/libseccomp

- https://www.freebsd.org/cgi/man.cgi?query=bpf&sektion=4

