/* This code example is for task 4.
 *
 * Set the array with pseudo-random values got from the hypervisor
 * and then sort it using the "bubble sort" algorithm.
 */

/* Sand provided hypercalls */
.set SAND_HC_GET_PRANDOM_VALUE, 1
/* Sand hypercall error codes */
.set SAND_UNKNOWN_HYPERCALL, 1000   /* check negative */

.set data_start, 0x2000

.set array_size, 10

.text
.code32

.global _start
_start:
/* Fill the array with values got from the hypervisor */
	movl    $array_size, %ecx
	movl    $data_start, %edi   /* array start address */
	cld
5:
	movl    $SAND_HC_GET_PRANDOM_VALUE, %eax    /* hypercall number */
	vmcall
	stosl
	loop    5b

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
 * %eax = <pseudo-random>   (least element);
 * %ebx = 0x2000            (data region start address);
 * %ecx = 0xa               (size of array);
 * %edx = <pseudo-random>   (greatest element).
 */
