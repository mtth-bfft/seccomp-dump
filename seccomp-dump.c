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

#define GET_OR_CREATE_LABEL(pos) (labels[pos] == 0 ? (labels[pos] = ++last_label) : labels[pos])

typedef enum {
    MODE_BRIEF,
    MODE_HEXDUMP,
    MODE_DISASSEMBLY,
    MODE_PROLOG,
} output_mode_t;

// Prolog fact names mapped to each known instruction
const char* BPF_PROLOG_ATOMS[][2] = {
	{ "bpf_ld_w_abs",   (const char*)(BPF_LD + BPF_W + BPF_ABS) },
	{ "bpf_ld_h_abs",   (const char*)(BPF_LD + BPF_H + BPF_ABS) },
	{ "bpf_ld_b_abs",   (const char*)(BPF_LD + BPF_B + BPF_ABS) },
	{ "bpf_ld_w_ind",   (const char*)(BPF_LD + BPF_W + BPF_IND) },
	{ "bpf_ld_h_ind",   (const char*)(BPF_LD + BPF_H + BPF_IND) },
	{ "bpf_ld_b_ind",   (const char*)(BPF_LD + BPF_B + BPF_IND) },
	{ "bpf_ld_w_len",   (const char*)(BPF_LD + BPF_W + BPF_LEN) },
	{ "bpf_ld_w_imm",   (const char*)(BPF_LD + BPF_W + BPF_IMM) },
	{ "bpf_ld_w_mem",   (const char*)(BPF_LD + BPF_W + BPF_MEM) },
	{ "bpf_ldx_w_imm",  (const char*)(BPF_LDX + BPF_W + BPF_IMM) },
	{ "bpf_ldx_w_mem",  (const char*)(BPF_LDX + BPF_W + BPF_MEM) },
	{ "bpf_ldx_w_len",  (const char*)(BPF_LDX + BPF_W + BPF_LEN) },
	{ "bpf_ldx_b_msh",  (const char*)(BPF_LDX + BPF_B + BPF_MSH) },
	{ "bpf_st",         (const char*)(BPF_ST) },
	{ "bpf_stx",        (const char*)(BPF_STX) },
	{ "bpf_alu_add_k",  (const char*)(BPF_ALU + BPF_ADD + BPF_K) },
	{ "bpf_alu_sub_k",  (const char*)(BPF_ALU + BPF_SUB + BPF_K) },
	{ "bpf_alu_mul_k",  (const char*)(BPF_ALU + BPF_MUL + BPF_K) },
	{ "bpf_alu_div_k",  (const char*)(BPF_ALU + BPF_DIV + BPF_K) },
	{ "bpf_alu_mod_k",  (const char*)(BPF_ALU + BPF_MOD + BPF_K) },
	{ "bpf_alu_and_k",  (const char*)(BPF_ALU + BPF_AND + BPF_K) },
	{ "bpf_alu_or_k",   (const char*)(BPF_ALU + BPF_OR + BPF_K) },
	{ "bpf_alu_xor_k",  (const char*)(BPF_ALU + BPF_XOR + BPF_K) },
	{ "bpf_alu_lsh_k",  (const char*)(BPF_ALU + BPF_LSH + BPF_K) },
	{ "bpf_alu_rsh_k",  (const char*)(BPF_ALU + BPF_RSH + BPF_K) },
	{ "bpf_alu_add_x",  (const char*)(BPF_ALU + BPF_ADD + BPF_X) },
	{ "bpf_alu_sub_x",  (const char*)(BPF_ALU + BPF_SUB + BPF_X) },
	{ "bpf_alu_mul_x",  (const char*)(BPF_ALU + BPF_MUL + BPF_X) },
	{ "bpf_alu_div_x",  (const char*)(BPF_ALU + BPF_DIV + BPF_X) },
	{ "bpf_alu_mod_x",  (const char*)(BPF_ALU + BPF_MOD + BPF_X) },
	{ "bpf_alu_and_x",  (const char*)(BPF_ALU + BPF_AND + BPF_X) },
	{ "bpf_alu_or_x",   (const char*)(BPF_ALU + BPF_OR + BPF_X) },
	{ "bpf_alu_xor_x",  (const char*)(BPF_ALU + BPF_XOR + BPF_X) },
	{ "bpf_alu_lsh_x",  (const char*)(BPF_ALU + BPF_LSH + BPF_X) },
	{ "bpf_alu_rsh_x",  (const char*)(BPF_ALU + BPF_RSH + BPF_X) },
	{ "bpf_alu_neg",    (const char*)(BPF_ALU + BPF_NEG) },
	{ "bpf_jmp_ja",     (const char*)(BPF_JMP + BPF_JA) },
	{ "bpf_jmp_jgt_k",  (const char*)(BPF_JMP + BPF_JGT + BPF_K) },
	{ "bpf_jmp_jge_k",  (const char*)(BPF_JMP + BPF_JGE + BPF_K) },
	{ "bpf_jmp_jeq_k",  (const char*)(BPF_JMP + BPF_JEQ + BPF_K) },
	{ "bpf_jmp_jset_k", (const char*)(BPF_JMP + BPF_JSET + BPF_K) },
	{ "bpf_jmp_jgt_x",  (const char*)(BPF_JMP + BPF_JGT + BPF_X) },
	{ "bpf_jmp_jge_x",  (const char*)(BPF_JMP + BPF_JGE + BPF_X) },
	{ "bpf_jmp_jeq_x",  (const char*)(BPF_JMP + BPF_JEQ + BPF_X) },
	{ "bpf_jmp_jset_x", (const char*)(BPF_JMP + BPF_JSET + BPF_X) },
	{ "bpf_ret_a",      (const char*)(BPF_RET + BPF_A) },
	{ "bpf_ret_k",      (const char*)(BPF_RET + BPF_K) },
	{ "bpf_misc_tax",   (const char*)(BPF_MISC + BPF_TAX) },
	{ "bpf_misc_txa",   (const char*)(BPF_MISC + BPF_TXA) },
	{ NULL, NULL },
};

static void* safe_alloc(size_t bytes)
{
    void *res = calloc(bytes, 1);
    if (res == NULL)
    {
        fprintf(stderr, "Error: out of memory\n");
	_exit(ENOMEM);
    }
    return res;
}

void bpf_hexdump(FILE *fout, const struct sock_filter *filter, size_t count)
{
    fprintf(fout, "#\tCLASS\tCODE\tJT\tJF\tK\n");
    for (size_t i = 0; i < count; i++)
    {
        fprintf(fout, "%zu\t0x%02X\t0x%04X\t0x%02X\t0x%02X\t0x%08X\n",
            i, BPF_CLASS(filter[i].code), filter[i].code, filter[i].jt, filter[i].jf, filter[i].k);
    }
}

void bpf_prolog(FILE *fout, const struct sock_filter *filter, size_t count)
{
    for (size_t pos = 0; pos < count; pos++, filter++)
    {
	int found = 0;
	for (size_t atom = 0; BPF_PROLOG_ATOMS[atom][0] != NULL; atom++)
	{
            if ((uint64_t)BPF_PROLOG_ATOMS[atom][1] == filter->code)
	    {
                fprintf(fout, "bpf_op(%zu, %s, 0x%x, 0x%x, 0x%x).\n", pos,
		    BPF_PROLOG_ATOMS[atom][0],
		    filter->jt, filter->jf, filter->k);
		found = 1;
		break;
	    }
	}
	if (found == 0)
	{
            fprintf(stderr, " [!] Unable to decode intruction %zu\n", pos);
	}
    }
}

void bpf_disassemble(FILE *fout, struct sock_filter *filter, size_t count)
{
    // Each instruction can be associated with a label number, or 0 if none
    size_t *labels = safe_alloc(sizeof(size_t) * count);
    size_t last_label = 0;

    for (size_t pos = 0; pos < count; pos++, filter++)
    {
        int c = filter->code;

	if (labels[pos] != 0)
            fprintf(fout, "L%zu:\t", labels[pos]);
	else
            fprintf(fout, "     \t");

        // ld [k]
        if (BPF_CLASS(c) == BPF_LD && BPF_SIZE(c) == BPF_W && BPF_MODE(c) == BPF_ABS)
	{
	    if (filter->k >= sizeof(struct seccomp_data))
		fprintf(stderr, " [!] Out-of-bounds absolute LD (offset %u) at insn %zu", filter->k, pos);
            if ((filter->k & 3) != 0)
	        fprintf(stderr, " [!] Unaligned absolute LDW (offset %u) at insn %zu", filter->k, pos);
	    fprintf(fout, "ld [%u]", filter->k);
	}
        // ld [x + k]
        else if (BPF_CLASS(c) == BPF_LD && BPF_SIZE(c) == BPF_W && BPF_MODE(c) == BPF_IND)
        {
	    fprintf(fout, "ld [x+%u]", filter->k);
        }
        // ld M[k]
        else if (BPF_CLASS(c) == BPF_LD && BPF_SIZE(c) == BPF_W && BPF_MODE(c) == BPF_MEM)
        {
	    fprintf(fout, "ld M[%u]", filter->k);
        }
        // ld #k || ldi #k
        else if (BPF_CLASS(c) == BPF_LD && BPF_SIZE(c) == BPF_W && BPF_MODE(c) == BPF_IMM)
        {
	    fprintf(fout, "ld #%u", filter->k);
        }
	else if (BPF_CLASS(c) == BPF_LD && BPF_SIZE(c) == BPF_W && BPF_MODE(c) == BPF_LEN)
        {
	    fprintf(fout, "ld #%zu", sizeof(struct seccomp_data));
        }
        // ldh [k]
        else if (BPF_CLASS(c) == BPF_LD && BPF_SIZE(c) == BPF_H && BPF_MODE(c) == BPF_ABS)
	{
	    if (filter->k >= sizeof(struct seccomp_data))
		fprintf(stderr, " [!] Out-of-bounds absolute LD (offset %u) at insn %zu", filter->k, pos);
            if ((filter->k & 2) != 0)
	        fprintf(stderr, " [!] Unaligned absolute LDH (offset %u) at insn %zu", filter->k, pos);
	    fprintf(fout, "ldh [%u]", filter->k);
	}
        // ldh [x + k]
        else if (BPF_CLASS(c) == BPF_LD && BPF_SIZE(c) == BPF_H && BPF_MODE(c) == BPF_IND)
        {
	    fprintf(fout, "ldh [x+%u]", filter->k);
        }
        // ldb [k]
        else if (BPF_CLASS(c) == BPF_LD && BPF_SIZE(c) == BPF_B && BPF_MODE(c) == BPF_ABS)
	{
	    if (filter->k >= sizeof(struct seccomp_data))
		fprintf(stderr, " [!] Out-of-bounds absolute LD (offset %u) at insn %zu", filter->k, pos);
	    fprintf(fout, "ldb [%u]", filter->k);
	}
        // ldb [x + k]
        else if (BPF_CLASS(c) == BPF_LD && BPF_SIZE(c) == BPF_B && BPF_MODE(c) == BPF_IND)
        {
	    fprintf(fout, "ldb [x+%u]", filter->k);
        }
        // ldx M[k]
        else if (BPF_CLASS(c) == BPF_LDX && BPF_SIZE(c) == BPF_W && BPF_MODE(c) == BPF_MEM)
        {
	    fprintf(fout, "ldx M[%u]", filter->k);
        }
        // ldx #k || ldxi #k
        else if (BPF_CLASS(c) == BPF_LDX && BPF_SIZE(c) == BPF_W && BPF_MODE(c) == BPF_IMM)
        {
	    fprintf(fout, "ldx #%u", filter->k);
        }
	else if (BPF_CLASS(c) == BPF_LDX && BPF_SIZE(c) == BPF_W && BPF_MODE(c) == BPF_LEN)
        {
	    fprintf(fout, "ldx #%zu", sizeof(struct seccomp_data));
        }
        // ldx 4*([k]&0xf)
        else if (BPF_CLASS(c) == BPF_LDX && BPF_SIZE(c) == BPF_W && BPF_MODE(c) == BPF_MSH)
        {
	    fprintf(fout, "ldx 4*([%d]&0xf)", filter->k);
        }
        // ldxb 4*([k]&0xf)
        else if (BPF_CLASS(c) == BPF_LDX && BPF_SIZE(c) == BPF_B && BPF_MODE(c) == BPF_MSH)
        {
	    fprintf(fout, "ldxb 4*([%d]&0xf)", filter->k);
        }
        // st M[k]
        else if (BPF_CLASS(c) == BPF_ST)
        {
	    fprintf(fout, "st M[%d]", filter->k);
        }
        // stx M[k]
        else if (BPF_CLASS(c) == BPF_STX)
        {
	    fprintf(fout, "stx M[%d]", filter->k);
        }
        // jmp Label || ja Label
        else if (BPF_CLASS(c) == BPF_JMP && BPF_SRC(c) == BPF_K && BPF_OP(c) == BPF_JA)
        {
            if (pos + 1 + filter->k > count)
	    {
		fprintf(stderr, " [!] Out of bounds JA (offset %u) at insn %zu\n", filter->k, pos);
	        fprintf(fout, "jmp <INVALID>");
            }
            else
            {
	        fprintf(fout, "jmp L%zu", GET_OR_CREATE_LABEL(pos + 1 + filter->k));
            }
	}
        // jeq #k,Lt,Lf
        // jeq #k,Lt
        // jneq #k,Lt
	else if (BPF_CLASS(c) == BPF_JMP && BPF_SRC(c) == BPF_K && BPF_OP(c) == BPF_JEQ)
	{
            if (pos + 1 + filter->jt > count || pos + 1 + filter->jf > count)
	    {
		fprintf(stderr, " [!] Out of bounds JEQ at insn %zu\n", pos);
                fprintf(fout, "jmp <INVALID>");
            }
	    else if (filter->jf == 0)
	    {
	        fprintf(fout, "jeq #%u, L%zu", filter->k, GET_OR_CREATE_LABEL(pos + 1 + filter->jt));
	    }
	    else if (filter->jt == 0)
	    {
	        fprintf(fout, "jneq #%u, L%zu", filter->k, GET_OR_CREATE_LABEL(pos + 1 + filter->jf));
	    }
	    else
	    {
                size_t label_t = GET_OR_CREATE_LABEL(pos + 1 + filter->jt);
                size_t label_f = GET_OR_CREATE_LABEL(pos + 1 + filter->jf);
	        fprintf(fout, "jeq #%u, L%zu, L%zu", filter->k, label_t, label_f);
	    }
	}
        // jeq %x,Lt,Lf
        // jeq %x,Lt
        // jneq %x,Lt
	else if (BPF_CLASS(c) == BPF_JMP && BPF_SRC(c) == BPF_X && BPF_OP(c) == BPF_JEQ)
	{
            if (pos + 1 + filter->jt > count || pos + 1 + filter->jf > count)
	    {
		fprintf(stderr, " [!] Out of bounds JEQ at insn %zu\n", pos);
                fprintf(fout, "jeq %%x,<INVALID>");
            }
	    else if (filter->jf == filter->jt)
	    {
	        fprintf(fout, "jmp L%zu", GET_OR_CREATE_LABEL(pos + 1 + filter->jt));
	    }
	    else if (filter->jf == 0)
	    {
	        fprintf(fout, "jeq %%x, L%zu", GET_OR_CREATE_LABEL(pos + 1 + filter->jt));
	    }
	    else if (filter->jt == 0)
	    {
	        fprintf(fout, "jneq %%x, L%zu", GET_OR_CREATE_LABEL(pos + 1 + filter->jf));
	    }
	    else
	    {
                size_t label_t = GET_OR_CREATE_LABEL(pos + 1 + filter->jt);
                size_t label_f = GET_OR_CREATE_LABEL(pos + 1 + filter->jf);
	        fprintf(fout, "jeq %%x, L%zu, L%zu", label_t, label_f);
	    }
	}
        // jgt #k,Lt
        // jgt #k,Lt,Lf
        // jle #k,Lt
	else if (BPF_CLASS(c) == BPF_JMP && BPF_SRC(c) == BPF_K && BPF_OP(c) == BPF_JGT)
	{
            if (pos + 1 + filter->jt > count || pos + 1 + filter->jf > count)
	    {
		fprintf(stderr, " [!] Out of bounds JGT at insn %zu: ", pos);
	        fprintf(fout, "jgt #%u, <INVALID>", filter->k);
            }
	    else if (filter->jf == 0)
	    {
	        fprintf(fout, "jgt #%u, L%zu", filter->k, GET_OR_CREATE_LABEL(pos + 1 + filter->jt));
	    }
	    else if (filter->jt == 0)
	    {
	        fprintf(fout, "jle #%u, L%zu", filter->k, GET_OR_CREATE_LABEL(pos + 1 + filter->jf));
	    }
	    else
	    {
                size_t label_t = GET_OR_CREATE_LABEL(pos + 1 + filter->jt);
                size_t label_f = GET_OR_CREATE_LABEL(pos + 1 + filter->jf);
	        fprintf(fout, "jgt #%u, L%zu, L%zu", filter->k, label_t, label_f);
	    }
	}
        // jgt %x,Lt
        // jgt %x,Lt,Lf
        // jle %x,Lt
	else if (BPF_CLASS(c) == BPF_JMP && BPF_SRC(c) == BPF_X && BPF_OP(c) == BPF_JGT)
	{
            if (pos + 1 + filter->jt > count || pos + 1 + filter->jf > count)
	    {
		fprintf(stderr, " [!] Out of bounds JGT at insn %zu\n", pos);
	        fprintf(fout, "jgt %%x, <INVALID>");
            }
	    else if (filter->jf == 0)
	    {
	        fprintf(fout, "jgt %%x, L%zu", GET_OR_CREATE_LABEL(pos + 1 + filter->jt));
	    }
	    else if (filter->jt == 0)
	    {
	        fprintf(fout, "jle %%x, L%zu", GET_OR_CREATE_LABEL(pos + 1 + filter->jf));
	    }
	    else
	    {
                size_t label_t = GET_OR_CREATE_LABEL(pos + 1 + filter->jt);
                size_t label_f = GET_OR_CREATE_LABEL(pos + 1 + filter->jf);
	        fprintf(fout, "jgt %%x, L%zu, L%zu", label_t, label_f);
	    }
	}
        // jge #k,Lt,Lf
        // jge #k,Lt
        // jlt #k,Lt
	else if (BPF_CLASS(c) == BPF_JMP && BPF_SRC(c) == BPF_K && BPF_OP(c) == BPF_JGE)
	{
            if (pos + 1 + filter->jt > count || pos + 1 + filter->jf > count)
	    {
		fprintf(stderr, " [!] Out of bounds JGE at insn %zu\n", pos);
	        fprintf(fout, "jge #%u, <INVALID>", filter->k);
            }
	    else if (filter->jf == 0)
	    {
	        fprintf(fout, "jge #%u, L%zu", filter->k, GET_OR_CREATE_LABEL(pos + 1 + filter->jt));
	    }
	    else if (filter->jt == 0)
	    {
	        fprintf(fout, "jlt #%u, L%zu", filter->k, GET_OR_CREATE_LABEL(pos + 1 + filter->jf));
	    }
	    else
	    {
                size_t label_t = GET_OR_CREATE_LABEL(pos + 1 + filter->jt);
                size_t label_f = GET_OR_CREATE_LABEL(pos + 1 + filter->jf);
	        fprintf(fout, "jge #%u, L%zu, L%zu", filter->k, label_t, label_f);
	    }
	}
        // jge %x,Lt,Lf
        // jge %x,Lt
        // jlt %x,Lt
	else if (BPF_CLASS(c) == BPF_JMP && BPF_SRC(c) == BPF_X && BPF_OP(c) == BPF_JGE)
	{
            if (pos + 1 + filter->jt > count || pos + 1 + filter->jf > count)
	    {
		fprintf(stderr, " [!] Out of bounds JGE at insn %zu\n", pos);
	        fprintf(fout, "jge %%x, <INVALID>");
            }
	    else if (filter->jf == 0)
	    {
	        fprintf(fout, "jge %%x, L%zu", GET_OR_CREATE_LABEL(pos + 1 + filter->jt));
	    }
	    else if (filter->jt == 0)
	    {
	        fprintf(fout, "jlt %%x, L%zu", GET_OR_CREATE_LABEL(pos + 1 + filter->jf));
	    }
	    else
	    {
                size_t label_t = GET_OR_CREATE_LABEL(pos + 1 + filter->jt);
                size_t label_f = GET_OR_CREATE_LABEL(pos + 1 + filter->jf);
	        fprintf(fout, "jge %%x, L%zu, L%zu", label_t, label_f);
	    }
	}
        // jset #k,Lt,Lf
        // jgset #k,Lt
	else if (BPF_CLASS(c) == BPF_JMP && BPF_SRC(c) == BPF_K && BPF_OP(c) == BPF_JSET)
	{
            if (pos + 1 + filter->jt > count || pos + 1 + filter->jf > count)
	    {
		fprintf(stderr, " [!] Out of bounds JSET at insn %zu\n", pos);
	        fprintf(fout, "jset #%u, <INVALID>", filter->k);
            }
	    else if (filter->jf == 0)
	    {
	        fprintf(fout, "jset #%u, L%zu", filter->k, GET_OR_CREATE_LABEL(pos + 1 + filter->jt));
	    }
	    else if (filter->jt == 0)
	    {
	        fprintf(fout, "jnset #%u, L%zu", filter->k, GET_OR_CREATE_LABEL(pos + 1 + filter->jf));
	    }
	    else
	    {
                size_t label_t = GET_OR_CREATE_LABEL(pos + 1 + filter->jt);
                size_t label_f = GET_OR_CREATE_LABEL(pos + 1 + filter->jf);
	        fprintf(fout, "jset #%u, L%zu, L%zu", filter->k, label_t, label_f);
	    }
	}
        // jset %x,Lt,Lf
        // jgset %x,Lt
	else if (BPF_CLASS(c) == BPF_JMP && BPF_SRC(c) == BPF_X && BPF_OP(c) == BPF_JSET)
	{
            if (pos + 1 + filter->jt > count || pos + 1 + filter->jf > count)
	    {
		fprintf(stderr, " [!] Out of bounds JSET at insn %zu\n", pos);
	        fprintf(fout, "jset %%x, <INVALID>");
            }
	    else if (filter->jf == 0)
	    {
	        fprintf(fout, "jset %%x, L%zu", GET_OR_CREATE_LABEL(pos + 1 + filter->jt));
	    }
            else if (filter->jt == 0)
            {
	        fprintf(fout, "jnset %%x, L%zu", GET_OR_CREATE_LABEL(pos + 1 + filter->jf));
            }
	    else
	    {
                size_t label_t = GET_OR_CREATE_LABEL(pos + 1 + filter->jt);
                size_t label_f = GET_OR_CREATE_LABEL(pos + 1 + filter->jf);
	        fprintf(fout, "jset %%x, L%zu, L%zu", label_t, label_f);
	    }
	}
        // add %x
	else if (BPF_CLASS(c) == BPF_ALU && BPF_SRC(c) == BPF_X && BPF_OP(c) == BPF_ADD)
        {
	    fprintf(fout, "add %%x");
        }
        // add #k
	else if (BPF_CLASS(c) == BPF_ALU && BPF_SRC(c) == BPF_K && BPF_OP(c) == BPF_ADD)
        {
	    fprintf(fout, "add #%u", filter->k);
        }
        // sub %x
	else if (BPF_CLASS(c) == BPF_ALU && BPF_SRC(c) == BPF_X && BPF_OP(c) == BPF_SUB)
        {
	    fprintf(fout, "sub %%x");
        }
        // sub #k
	else if (BPF_CLASS(c) == BPF_ALU && BPF_SRC(c) == BPF_K && BPF_OP(c) == BPF_SUB)
        {
	    fprintf(fout, "sub #%u", filter->k);
        }
        // mul %x
	else if (BPF_CLASS(c) == BPF_ALU && BPF_SRC(c) == BPF_X && BPF_OP(c) == BPF_MUL)
        {
	    fprintf(fout, "mul %%x");
        }
        // mul #k
	else if (BPF_CLASS(c) == BPF_ALU && BPF_SRC(c) == BPF_K && BPF_OP(c) == BPF_MUL)
        {
	    fprintf(fout, "mul #%u", filter->k);
        }
        // div %x
	else if (BPF_CLASS(c) == BPF_ALU && BPF_SRC(c) == BPF_X && BPF_OP(c) == BPF_DIV)
        {
	    fprintf(fout, "div %%x");
        }
        // div #k
	else if (BPF_CLASS(c) == BPF_ALU && BPF_SRC(c) == BPF_K && BPF_OP(c) == BPF_DIV)
        {
	    fprintf(fout, "div #%u", filter->k);
        }
        // mod %x
	else if (BPF_CLASS(c) == BPF_ALU && BPF_SRC(c) == BPF_X && BPF_OP(c) == BPF_MOD)
        {
	    fprintf(fout, "mod x");
        }
        // mod #k
	else if (BPF_CLASS(c) == BPF_ALU && BPF_SRC(c) == BPF_K && BPF_OP(c) == BPF_MOD)
        {
	    fprintf(fout, "mod #%u", filter->k);
        }
        // neg
	else if (BPF_CLASS(c) == BPF_ALU && BPF_OP(c) == BPF_NEG)
        {
	    fprintf(fout, "neg");
        }
        // and %x
	else if (BPF_CLASS(c) == BPF_ALU && BPF_SRC(c) == BPF_X && BPF_OP(c) == BPF_AND)
        {
	    fprintf(fout, "and x");
        }
        // and #k
	else if (BPF_CLASS(c) == BPF_ALU && BPF_SRC(c) == BPF_K && BPF_OP(c) == BPF_AND)
        {
	    fprintf(fout, "and #%u", filter->k);
        }
        // or %x
	else if (BPF_CLASS(c) == BPF_ALU && BPF_SRC(c) == BPF_X && BPF_OP(c) == BPF_OR)
        {
	    fprintf(fout, "or %%x");
        }
        // or #k
	else if (BPF_CLASS(c) == BPF_ALU && BPF_SRC(c) == BPF_K && BPF_OP(c) == BPF_OR)
        {
	    fprintf(fout, "or #%u", filter->k);
        }
        // xor %x
	else if (BPF_CLASS(c) == BPF_ALU && BPF_SRC(c) == BPF_X && BPF_OP(c) == BPF_XOR)
        {
	    fprintf(fout, "xor %%x");
        }
        // xor #k
	else if (BPF_CLASS(c) == BPF_ALU && BPF_SRC(c) == BPF_K && BPF_OP(c) == BPF_XOR)
        {
	    fprintf(fout, "xor #%u", filter->k);
        }
        // lsh %x
	else if (BPF_CLASS(c) == BPF_ALU && BPF_SRC(c) == BPF_X && BPF_OP(c) == BPF_LSH)
        {
	    fprintf(fout, "lsh %%x");
        }
        // lsh #k
	else if (BPF_CLASS(c) == BPF_ALU && BPF_SRC(c) == BPF_K && BPF_OP(c) == BPF_LSH)
        {
	    fprintf(fout, "lsh #%u", filter->k);
        }
        // rsh %x
	else if (BPF_CLASS(c) == BPF_ALU && BPF_SRC(c) == BPF_X && BPF_OP(c) == BPF_RSH)
        {
	    fprintf(fout, "rsh %%x");
        }
        // rsh #k
	else if (BPF_CLASS(c) == BPF_ALU && BPF_SRC(c) == BPF_K && BPF_OP(c) == BPF_RSH)
        {
	    fprintf(fout, "rsh #%u", filter->k);
        }
        // tax
        else if (BPF_CLASS(c) == BPF_MISC && BPF_MISCOP(c) == BPF_TAX)
        {
            fprintf(fout, "tax");
        }
        // txa
        else if (BPF_CLASS(c) == BPF_MISC && BPF_MISCOP(c) == BPF_TXA)
        {
            fprintf(fout, "txa");
        }
        // ret #k
	else if (BPF_CLASS(c) == BPF_RET && BPF_RVAL(c) == BPF_K)
        {
            fprintf(fout, "ret #0x%08X", filter->k);
        }
        // ret %a
	else if (BPF_CLASS(c) == BPF_RET && BPF_RVAL(c) == BPF_A)
        {
            fprintf(fout, "ret %%a");
        }
	else
	{
            fprintf(stderr, " [!] Unable to decode instruction %zu", pos);
            fprintf(fout, "<INVALID INSTRUCTION>");
	}
	fprintf(fout, "\n");
    }

    if (labels != NULL)
	free(labels);
}

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

    progs = safe_alloc(total_size);
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
