/* This code example is for task 3.
 *
 * Load the array of 4-byte integers from .rodata to data segment
 * and then sort it using the "bubble sort" algorithm.
 *
 * In such way, we test multiple reads/writes to data region.
 */

.set data_start, 0x2000

.text
.code32

.global _start
_start:
/* Move the array to the begining of data region */
	movl    $array_size, %ecx
	movl    $array, %esi
	movl    $data_start, %edi

	cld

	rep
	movsl

/* Sort the array using modified bubble sort.
 *
 * Comments below reveal steps of the algorithm
 * as if it were written in C.
 */
	movl    $data_start, %ebx       /* array base */
	movl    $array_size, %edi       /* i = array_size, main loop index */

	cmpl    $1, %edi    /* if array_size <= 1 then */
	jle     4f          /* exit, nothing to sort */
	decl    %edi        /* we need only (array_size - 1) iterations */

0:                      /* Main loop: while (sf != 0) */
	xorl    %ecx, %ecx  /* sf = 0, "swaps" flag (sf > 0 if there were swaps) */
	xorl    %esi, %esi  /* j = 0, nested loop index */

1:
	cmpl    %esi, %edi  /* Nested loop: while (j < i) */
	jle     3f

	movl    (%ebx, %esi, 4), %eax   /* %eax = array[j] */
	movl    4(%ebx,%esi ,4), %edx   /* %edx = array[j + 1] */
	cmpl    %eax, %edx              /* if (array[j] > array[j + 1]) then */
	jge     2f
	movl    %eax, 4(%ebx, %esi, 4)  /* swap (array[j], array[j + 1]) */
	movl    %edx, (%ebx, %esi, 4)
	incl    %ecx        /* sf++ */
2:
	incl    %esi        /* j++ */
	jmp     1b

3:
	decl    %edi        /* i-- */
	testl   %ecx, %ecx  /* if there were swaps (sf != 0) then */
	jnz     0b          /* go to next iteration of the main loop */

4:
	movl    (%ebx), %eax            /* array[0], least element */
	movl    $array_size, %ecx
	movl    -4(%ebx, %ecx, 4), %edx /* array[array_size-1], greatest element */
	hlt     /* vmexit */

/* Expected results:
 *
 * %eax = 0x3       (least element);
 * %ebx = 0x2000    (data region start address);
 * %ecx = 0xa       (size of array);
 * %edx = 0x34      (greatest element).
 */

/* We transfer the array to the guest along with code
 * so we put it to .rodata section.
 */
.section .rodata
.balign 4

array:  .long 7, 23, 11, 8, 42, 52, 16, 3, 34, 5

.set array_size, (. - array) / 4
