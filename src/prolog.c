#include <stdio.h>
#include <stdint.h>
#include <linux/filter.h>

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

void bpf_prolog(FILE *fout, const struct sock_filter *filter, size_t count)
{
    for (size_t pos = 0; pos < count; pos++, filter++)
    {
	int found = 0;
	for (size_t atom = 0; BPF_PROLOG_ATOMS[atom][0] != NULL; atom++)
	{
            if ((uint16_t)(uint64_t)BPF_PROLOG_ATOMS[atom][1] == filter->code)
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

