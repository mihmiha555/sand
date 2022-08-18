/* This code example is for task 2.
 *
 * Set the registers with magic values and then loop
 * waiting for the VMX-preemption timer to expire.
 */

.text
.code32

.global _start
_start:
	movl    $0xa, %eax
	movl    $0xb, %ebx
	movl    $0xc, %ecx
	movl    $0xd, %edx

	jmp     .
