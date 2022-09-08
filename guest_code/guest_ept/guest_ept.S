/* This code example is for task 6.
 *
 * Guest starts in unpaged protected mode.
 *
 * Set identity mapping in guest paging structures,
 * load CR3, and enable paging in CR0.
 *
 * Then test read/write access to each page to make sure
 * that paging mechanism works correctly.
 */

/* CR0 register bits */
.set CR0_PG, 0x80000000
.set CR0_WP, 0x10000

/* Guest physical memory layout */
.set page_directory, 0x4000
.set page_table, 0x3000
.set data_start, 0x2000
.set code_start, 0x1000
.set stack_start, 0x0000

.text
.code32

.global _start
_start:
/* We are in unpaged protected mode now (CR0.PE = 1, CR0.PG = 0) */

/* Initialize guest paging structures */
	call    init_mm
/* Set CR3 with guest physical address of page directory */
	movl    $page_directory, %eax
	movl    %eax, %cr3
/* Enable paging in CR0, set write-protect */
	movl    %cr0, %eax
	orl     $(CR0_PG | CR0_WP), %eax
	movl    %eax, %cr0
/* Flush the prefetch queue */
	jmp     goto_paging

goto_paging:
/* We use paging now! */

/* Test read/write access to stack page */
	pushl   $0xabcd
	popl    %eax

/* We have no need to test read access to code page -
 * it's OK if we can execute these instructions.
 * Write access crashes due to page fault (#PF).
 */
#   movl    $0x1234, code_start

/* Test read/write access to data page */
	movl    $0x55aa, data_start
	movl    data_start, %ebx

/* Try to read first entries of guest paging structures */
	movl    page_directory, %ecx
	movl    page_table, %edx

	hlt     /* vmexit */

/* Expected results:
 *
 * %eax = 0xabcd    (magic value written to stack page);
 * %ebx = 0x55aa    (magic value written to data page);
 * %ecx = 0x3023    (first PDE: accessed);
 * %edx = 0x0063    (first PTE: accessed, dirty).
 */

/* Set 1:1 mapping in guest paging structures */
init_mm:
	pushl   %eax
	pushl   %ebx

	movl    $page_directory, %ebx

	movl    $page_table, %eax
	orl     $3, %eax                /* page present, read/write access */
	movl    %eax, (%ebx)

	movl    $page_table, %ebx

	movl    $stack_start, %eax
	orl     $3, %eax                /* page present, read/write access */
	movl    %eax, (%ebx)

	movl    $code_start, %eax
	orl     $1, %eax                /* page present, read only access */
	movl    %eax, 4(%ebx)

	movl    $data_start, %eax
	orl     $3, %eax                /* page present, read/write access */
	movl    %eax, 8(%ebx)

	movl    $page_table, %eax
	orl     $3, %eax                /* page present, read/write access */
	movl    %eax, 12(%ebx)

	movl    $page_directory, %eax
	orl     $3, %eax                /* page present, read/write access */
	movl    %eax, 16(%ebx)

	popl    %ebx
	popl    %eax
	ret
