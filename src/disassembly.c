#include <stdio.h>
#include <stdlib.h>
#include <linux/seccomp.h>
#include <linux/filter.h>

#define GET_OR_CREATE_LABEL(pos) (labels[pos] == 0 ? (labels[pos] = ++last_label) : labels[pos])

void bpf_disassemble(FILE *fout, struct sock_filter *filter, size_t count)
{
    // Each instruction can be associated with a label number, or 0 if none
    size_t *labels;
    size_t last_label = 0;

    labels = calloc(sizeof(size_t) * count, 1);
    if (labels == NULL)
    {
        fprintf(stderr, "Error: out of memory\n");
	exit(1);
    }
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

