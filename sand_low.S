#include <linux/linkage.h>
#include <asm/unwind_hints.h>

.global _sand_cpu_vmxon
.global _sand_cpu_vmxoff
.global _sand_cpu_invept
.global _sand_cpu_vmcs_clear
.global _sand_cpu_vmcs_load
.global sand_cpu_vmcs_write_64
.global sand_cpu_vmcs_read_64
.global sand_cpu_get_cs
.global sand_cpu_get_ds
.global sand_cpu_get_es
.global sand_cpu_get_ss
.global sand_cpu_get_fs
.global sand_cpu_get_gs
.global sand_cpu_get_tr
.global sand_vm_exit
.global sand_vm_launch
.global sand_cpu_sgdt
.global sand_cpu_sidt

.set sgc_rax, 0
.set sgc_rbx, 8
.set sgc_rcx, 16
.set sgc_rdx, 24
.set sgc_rsi, 32
.set sgc_rdi, 40
.set sgc_r8,  48
.set sgc_r9,  56
.set sgc_r10, 64
.set sgc_r11, 72
.set sgc_r12, 80
.set sgc_r13, 88
.set sgc_r14, 96
.set sgc_r15, 104
.set sgc_cr2, 112
.set sgc_rbp, 120

.set shc_host_stack,     0
.set shc_temp_rdi,       8
.set shc_guest_regs_ctx, 16
.set shc_err,            24

SYM_FUNC_START(_sand_cpu_vmxon)
	xor %rax, %rax
	vmxon (%rdi)
	setna %al
	ret
SYM_FUNC_END(_sand_cpu_vmxon)

SYM_FUNC_START(_sand_cpu_vmxoff)
	vmxoff
	ret
SYM_FUNC_END(_sand_cpu_vmxoff)

SYM_FUNC_START(_sand_cpu_invept)
	xor %rax, %rax
	invept (%rsi), %rdi
	setna %al
	ret
SYM_FUNC_END(_sand_cpu_invept)

SYM_FUNC_START(_sand_cpu_vmcs_clear)
	xor %rax, %rax
	vmclear (%rdi)
	setna %al
	ret
SYM_FUNC_END(_sand_cpu_vmcs_clear)

SYM_FUNC_START(_sand_cpu_vmcs_load)
	xor %rax, %rax
	vmptrld (%rdi)
	setna %al
	ret
SYM_FUNC_END(_sand_cpu_vmcs_load)

SYM_FUNC_START(sand_cpu_vmcs_write_64)
	xor %rax, %rax
	vmwrite %rsi, %rdi
	setna %al
	ret
SYM_FUNC_END(sand_cpu_vmcs_write_64)

SYM_FUNC_START(sand_cpu_vmcs_read_64)
	vmread %rdi, %rax
	ret
SYM_FUNC_END(sand_cpu_vmcs_read_64)

SYM_FUNC_START(sand_cpu_sgdt)
	sgdt (%rdi)
	ret
SYM_FUNC_END(sand_cpu_sgdt)

SYM_FUNC_START(sand_cpu_sidt)
	sidt (%rdi)
	ret
SYM_FUNC_END(sand_cpu_sidt)

.macro gen_get_seg sreg
SYM_FUNC_START(sand_cpu_get_\sreg)
	mov %\sreg, %rax
	ret
SYM_FUNC_END(sand_cpu_get_\sreg)
.endm

gen_get_seg cs
gen_get_seg ds
gen_get_seg es
gen_get_seg ss
gen_get_seg fs
gen_get_seg gs

SYM_FUNC_START(sand_cpu_get_tr)
	str %rax
	ret
SYM_FUNC_END(sand_cpu_get_tr)

.macro gen_sgc_restore reg base
	mov sgc_\reg(%\base), %\reg
.endm

.macro gen_sgc_save reg base
	mov %\reg, sgc_\reg(%\base)
.endm

# TODO: add proper annotations for objtool.
SYM_FUNC_START(sand_vm_launch)
	# rdi - guest ctx
	# rsi - host ctx
	# rdx - first?
	push %rbp
	push %rsi
	push %rdi
	push %rax
	push %rbx
	push %rcx
	push %rdx
	push %r8
	push %r9
	push %r10
	push %r11
	push %r12
	push %r13
	push %r14
	push %r15
	pushf

	sub $6, %rsp
	fstcw (%rsp)
	stmxcsr 2(%rsp)

	cli
	cmpq $1, %rdx

	mov %rsp, shc_host_stack(%rsi)
	mov %rdi, shc_guest_regs_ctx(%rsi)

	gen_sgc_restore rax rdi
	gen_sgc_restore rbx rdi
	gen_sgc_restore rcx rdi
	gen_sgc_restore rdx rdi
	gen_sgc_restore rbp rdi
	gen_sgc_restore r8  rdi
	gen_sgc_restore r9  rdi
	gen_sgc_restore r10 rdi
	gen_sgc_restore r11 rdi
	gen_sgc_restore r12 rdi
	gen_sgc_restore r13 rdi
	gen_sgc_restore r14 rdi
	gen_sgc_restore r15 rdi

	mov %rsi, %rsp

	mov sgc_cr2(%rdi), %rsi
	mov %rsi, %cr2

	gen_sgc_restore rsi rdi
	gen_sgc_restore rdi rdi

	jz 1f
	vmresume
	movl $2, shc_err(%rsp)
	jmp 2f
1:
	vmlaunch

	movl $3, shc_err(%rsp)
2:
	mov shc_host_stack(%rsp), %rsp

	jmp 3f

	sand_vm_exit:

	mov %rdi, shc_temp_rdi(%rsp)
	mov shc_guest_regs_ctx(%rsp), %rdi

	gen_sgc_save rsi rdi

	mov %cr2, %rsi
	mov %rsi, sgc_cr2(%rdi)
	mov shc_temp_rdi(%rsp), %rsi
	mov %rsi, sgc_rdi(%rdi)

	setbe shc_err(%rsp)

	gen_sgc_save rax rdi
	gen_sgc_save rbx rdi
	gen_sgc_save rcx rdi
	gen_sgc_save rdx rdi
	gen_sgc_save rbp rdi
	gen_sgc_save r8  rdi
	gen_sgc_save r9  rdi
	gen_sgc_save r10 rdi
	gen_sgc_save r11 rdi
	gen_sgc_save r12 rdi
	gen_sgc_save r13 rdi
	gen_sgc_save r14 rdi
	gen_sgc_save r15 rdi

	mov shc_host_stack(%rsp), %rsp

3:

	fldcw (%rsp)
	ldmxcsr 2(%rsp)
	add $6, %rsp

	popf
	pop %r15
	pop %r14
	pop %r13
	pop %r12
	pop %r11
	pop %r10
	pop %r9
	pop %r8
	pop %rdx
	pop %rcx
	pop %rbx
	pop %rax
	pop %rdi
	pop %rsi
	pop %rbp

	ret
SYM_FUNC_END(sand_vm_launch)
