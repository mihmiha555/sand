/* This code example is for task 5.
 *
 * There is an arithmetic expression:
 * (a + b) * (c + d) / e = (3.8 + 10.3) * (5.6 - 2.4) / 4.7 = 9.6,
 * where a, b, c, d - double-precision floating-point numbers.
 *
 * Calculate the expression with x87 FPU and then compute the same
 * using SSE instructions.
 *
 * In such way, we test FPU execution environment in guest mode.
 */

.text
.code32

.global _start
_start:
	subl    $16, %esp   /* we store results on stack */

	finit
	fldcw   x87_ctw     /* load guest x87 CTW - #Z is not masked */

/* Compute the result with x87 FPU */
	fldl    a
	fldl    b
	faddp   %st(0), %st(1)      /* a + b */
	fldl    c
	fldl    d
	faddp   %st(0), %st(1)      /* c + d */
	fmulp   %st(0), %st(1)      /* (a + b) * (c + d) */
	fldl    e
	fdivrp  %st(0), %st(1)      /* (a + b) * (c + d) / e */
	fstps   (%esp)              /* store x87 result on stack */

	fstcw   4(%esp)             /* store guest x87 CTW value on stack */

	ldmxcsr sse_mxcsr   /* load guest MXCSR - #Z is not masked */

/* Now calculate the same expression using power of SIMD! */
	movapd  a, %xmm0            /* (a, c) --> %xmm0 */
	movapd  b, %xmm1            /* (b, d) --> %xmm1 */
	addpd   %xmm1, %xmm0        /* (a + b), (c + d) */
	movhlps %xmm0, %xmm1        /* (c + d) --> %xmm1 */
	mulsd   %xmm1, %xmm0        /* (a + b) * (c + d) */
	movsd   e, %xmm2
	divsd   %xmm2, %xmm0        /* (a + b) * (c + d) / e */
	cvtsd2ss %xmm0, %xmm0       /* convert result to single-precision value */
	movss   %xmm0, 8(%esp)      /* store SSE result on stack */

	stmxcsr 12(%esp)    /* store guest MXCSR value on stack */

/* Pop the results from stack */
	popl    %eax        /* calculation result (x87) */
	popl    %ebx        /* guest x87 CTW value */
	popl    %ecx        /* calculation result (SSE) */
	popl    %edx        /* guest MXCSR value */

	hlt     /* vmexit */

/* Expected results:
 *
 * %eax = 0x4119999a   (x87 result);
 * %ebx = 0x37b        (guest x87 CTW);
 * %ecx = 0x4119999a   (SSE result);
 * %edx = 0x1da0       (guest MXCSR: pending #P means we've lost some accuracy).
 */

/* We store numbers for calculations in double-precision format.
 * They are aligned and packed for SSE access.
 */
.section .rodata
.balign 16

a:  .double 0d+3.8
c:  .double 0d+5.6
b:  .double 0d+10.3
d:  .double 0d-2.4
e:  .double 0d+4.7

x87_ctw:    .word 0x37b     /* guest x87 control word */
sse_mxcsr:  .long 0x1d80    /* guest MXCSR */
