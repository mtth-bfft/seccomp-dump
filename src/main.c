#include <errno.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

typedef enum {
    MODE_BRIEF,
    MODE_HEXDUMP,
    MODE_DISASSEMBLY,
    MODE_PROLOG,
} output_mode_t;

extern void bpf_hexdump(FILE *fout, const struct sock_filter *filter, size_t count);
extern void bpf_disassemble(FILE *fout, struct sock_filter *filter, size_t count);
extern void bpf_prolog(FILE *fout, const struct sock_filter *filter, size_t count);

void print_usage()
{
    fprintf(stderr, "Usage: seccomp-dump                <thread id> (brief summary)\n");
    fprintf(stderr, "       seccomp-dump [-o <path>] -x <thread id> (show as hexdump)\n");
    fprintf(stderr, "       seccomp-dump [-o <path>] -d <thread id> (show as disassembly)\n");
    fprintf(stderr, "       seccomp-dump [-o <path>] -p <thread id> (show as prolog facts)\n");
}

int main(int argc, char* argv[])
{
    int opt;
    int mode = MODE_BRIEF;
    FILE *fout = stdout;
    int res = 0;
    pid_t tid = 0;
    int wstatus = 0;
    size_t total_size = sizeof(struct sock_fprog*);
    size_t filter_count = 0;
    struct sock_fprog **progs = NULL;

    while ((opt = getopt(argc, argv, "xdpo:")) != -1)
    {
        switch (opt) {
	case 'x':
            mode = MODE_HEXDUMP;
	    break;
        case 'd':
            mode = MODE_DISASSEMBLY;
	    break;
	case 'p':
	    mode = MODE_PROLOG;
	    break;
	case 'o':
            fout = fopen(optarg, "w");
            if (fout == NULL)
            {
                perror("fopen()");
                res = errno;
                goto cleanup;
            }
	    break;
	default:
	    print_usage();
	    return 1;
	}
    }

    tid = (pid_t)atol(argv[argc - 1]);
    if (optind != argc - 1 || tid == 0)
    {
	print_usage();
	res = 1;
	goto cleanup;
    }

    res = ptrace(PTRACE_ATTACH, tid, NULL, NULL);
    if (res < 0)
    {
        perror("ptrace(PTRACE_ATTACH)");
        res = errno;
        goto cleanup;
    }

    res = waitpid(tid, &wstatus, 0);
    if (res <= 0)
    {
        perror("waitpid()");
        res = errno;
        goto cleanup;
    }
    else if (!WIFSTOPPED(wstatus))
    {
        fprintf(stderr, "Unable to stop process for inspection: signal delivery failed\n");
        res = 1;
        goto cleanup;
    }

    while (res >= 0)
    {
        res = ptrace(PTRACE_SECCOMP_GET_FILTER, tid, (void*)filter_count, NULL);
        if (res < 0 && errno == ESRCH)
        {
            fprintf(stderr, "Process resumed spuriously, or died during inspection\n");
            res = 1;
            goto cleanup;
        }
        else if (res < 0 && errno == EINVAL)
        {
            fprintf(stderr, "TID %llu has no seccomp filter attached\n", (unsigned long long)tid);
	    goto cleanup;
	}
        else if (res < 0 && errno == ENOENT)
        {
            break; // end of list
        }
        else if (res < 0)
        {
            perror("ptrace(PTRACE_SECCOMP_GET_FILTER, x, NULL)");
            res = errno;
            goto cleanup;
        }
        total_size += sizeof(struct sock_fprog*) + sizeof(struct sock_fprog) + \
            res * sizeof(struct sock_filter);
        filter_count++;
    }

    progs = calloc(total_size, 1);
    if (progs == NULL)
    {
        fprintf(stderr, "Error: out of memory\n");
	_exit(ENOMEM);
    }
    for (size_t filter_idx = 0; filter_idx < filter_count; filter_idx++)
    {
	progs[filter_idx] = ((struct sock_fprog*)&progs[filter_count+1]) + filter_idx;
	progs[filter_idx]->filter = (struct sock_filter*)(
		((struct sock_fprog*)&progs[filter_count+1]) + filter_count);
        res = ptrace(PTRACE_SECCOMP_GET_FILTER, tid, (void*)filter_idx,
	    progs[filter_idx]->filter);
        if (res < 0 && errno == ESRCH)
        {
            fprintf(stderr, "Process resumed spuriously, or died during inspection\n");
            res = 1;
            goto cleanup;
        }
        else if (res < 0 && errno == ENOENT)
        {
            filter_count = filter_idx;
            break;
        }
        else if (res < 0)
        {
            perror("ptrace(PTRACE_SECCOMP_GET_FILTER, x, NULL)");
            res = errno;
            goto cleanup;
        }
        progs[filter_idx]->len = res;
    }

    fprintf(stderr, "TID %zd has %zu filter%s attached\n",
        (size_t)tid, filter_count, filter_count > 1 ? "s" : "");
    for (size_t filter_idx = 0; filter_idx < filter_count; filter_idx++)
    {
        fprintf(stderr, "Filter %zu: %u instruction(s)\n", filter_idx, progs[filter_idx]->len);
        if (mode == MODE_HEXDUMP)
            bpf_hexdump(fout, progs[filter_idx]->filter, progs[filter_idx]->len);
        else if (mode == MODE_DISASSEMBLY)
	    bpf_disassemble(fout, progs[filter_idx]->filter, progs[filter_idx]->len);
        else if (mode == MODE_PROLOG)
	    bpf_prolog(fout, progs[filter_idx]->filter, progs[filter_idx]->len);
    }

cleanup:
    if (progs != NULL)
        free(progs);
    return res;
}
