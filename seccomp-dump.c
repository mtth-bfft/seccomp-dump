#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/wait.h>

const mode_t FILE_MODE = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
const int OPEN_MODE = O_WRONLY | O_CREAT | O_EXCL;

void print_usage()
{
	fprintf(stderr, "Usage: seccomp-dump <thread_id> <output_path>\n");
	fprintf(stderr, "If a directory is provided, the TID will be used as filename.\n");
	fprintf(stderr, "Filter numbers will be appended, starting from 0.\n");
	fprintf(stderr, "\n");
}

int main(int argc, char* argv[])
{
	pid_t tid;
	int out_dir;
	int res;
	int wstatus = 0;
	size_t filter_idx;

	if (argc != 3) {
		print_usage();
		return 1;
	}
	tid = (pid_t)atol(argv[1]);
	if (tid == 0) {
		fprintf(stderr, "Error: invalid thread ID\n");
		print_usage();
		return 1;
	}

	// Is the output_path a directory?
	out_dir = open(argv[2], O_PATH | O_DIRECTORY);

	res = ptrace(PTRACE_ATTACH, tid, NULL, NULL);
	if (res < 0) {
		res = errno;
		perror("ptrace(PTRACE_ATTACH)");
		goto cleanup;
	}
	res = waitpid(tid, &wstatus, 0);
	if (res <= 0) {
		res = errno;
		perror("waitpid()");
		goto cleanup;
	}
	else if (!WIFSTOPPED(wstatus)) {
		res = 1;
		fprintf(stderr, "Error: unable to stop process for inspection: signal delivery failed\n");
		goto cleanup;
	}

	// Iterate on all loaded filters, 0 is the most recently loaded
	for (filter_idx = 0; ; filter_idx += 1) {
		int filter_len;
		struct sock_filter *filter;
		char out_file[255];
		int out_fd;
		ssize_t bytes_written;

		filter_len = ptrace(PTRACE_SECCOMP_GET_FILTER, tid, (void*)filter_idx, NULL);
		if (filter_len < 0 && errno == ENOENT) {
			break; // end of list, expected
		}
		else if (filter_len < 0 && errno == EINVAL) {
			printf("Thread %d has no seccomp filter attached\n", tid);
			goto cleanup;
		}
		else if (filter_len < 0 && errno == ESRCH) {
			res = 1;
			fprintf(stderr, "Error: Process resumed spuriously, or died during inspection\n");
			goto cleanup;
		}
		else if (filter_len < 0) {
			res = errno;
			perror("ptrace(PTRACE_SECCOMP_GET_FILTER)");
			goto cleanup;
		}

		if (out_dir >= 0) {
			snprintf(out_file, sizeof(out_file), "%d.%zu", tid, filter_idx);
			out_fd = openat(out_dir, out_file, OPEN_MODE, FILE_MODE);
		}
		else {
			snprintf(out_file, sizeof(out_file), "%s.%zu", argv[2], filter_idx);
			out_fd = open(out_file, OPEN_MODE, FILE_MODE);
		}
		if (out_fd < 0) {
			res = errno;
			fprintf(stderr, "Error: could not create file %s : %s\n", out_file, strerror(errno));
			goto cleanup;
		}

		filter = calloc(filter_len, sizeof(struct sock_filter));
		if (filter == NULL) {
			fprintf(stderr, "Error: requested %zu bytes, out of memory\n", filter_len * sizeof(struct sock_filter));
			_exit(ENOMEM);
		}
		filter_len = ptrace(PTRACE_SECCOMP_GET_FILTER, tid, (void*)filter_idx, filter);
		if (filter_len < 0 && errno == ESRCH) {
			res = 1;
			fprintf(stderr, "Error: Process resumed spuriously, or died during inspection\n");
			free(filter);
			goto cleanup;
		}
		else if (filter_len < 0) {
			res = errno;
			perror("ptrace(PTRACE_SECCOMP_GET_FILTER)");
			free(filter);
			goto cleanup;
		}
		printf("Filter %zu : %u instructions\n", filter_idx, filter_len);
		bytes_written = write(out_fd, filter, filter_len * sizeof(struct sock_filter));
		if (bytes_written != (ssize_t)(filter_len * sizeof(struct sock_filter))) {
			res = errno;
			fprintf(stderr, "Error: could not write to file %s (code %u)\n", out_file, errno);
			free(filter);
			close(out_fd);
			goto cleanup;
		}
		free(filter);
		close(out_fd);
	}
	printf("Successfully dumped %zu filter%s\n",
		filter_idx, filter_idx > 1 ? "s" : "");

cleanup:
	if (out_dir >= 0)
		close(out_dir);
	return res;
}
