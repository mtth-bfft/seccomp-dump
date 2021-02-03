#include <stdio.h>
#include <linux/filter.h>

void bpf_hexdump(FILE *fout, const struct sock_filter *filter, size_t count)
{
    fprintf(fout, "#\tCLASS\tCODE\tJT\tJF\tK\n");
    for (size_t i = 0; i < count; i++)
    {
        fprintf(fout, "%zu\t0x%02X\t0x%04X\t0x%02X\t0x%02X\t0x%08X\n",
            i, BPF_CLASS(filter[i].code), filter[i].code, filter[i].jt, filter[i].jf, filter[i].k);
    }
}


