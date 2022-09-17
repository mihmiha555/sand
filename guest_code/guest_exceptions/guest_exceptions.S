/* This code example is for task 7.
 *
 * Create exception handling environment in guest mode.
 *
 * Provide exception-handler procedures
 * for all x86 architecture-defined exceptions
 * and initialize the interrupt descriptor table (IDT).
 *
 * Then test exception handling by generating several exceptions.
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

/* Code and data segment selectors */
.set SEG_CODE, 0x8      /* index = 1, TI = 0(GDT), RPL = 0 */
.set SEG_DATA, 0x10     /* index = 2, TI = 0(GDT), RPL = 0 */

/* GDT related symbols */
.set GDT_ENTRIES, 3
.set gdt_table, data_start
.set gdt_descr, gdt_table + 8 * GDT_ENTRIES

/* IDT related symbols */
.set IDT_ENTRIES, 32
.set idt_table, data_start + 32
.set idt_descr, idt_table + 8 * IDT_ENTRIES

/* Sand provided hypercalls */
.set SAND_HC_GET_PRANDOM_VALUE, 1
.set SAND_HC_NOTIFY_EXCEPTION, 2

/* Sand hypercall error codes (check negative) */
.set SAND_UNKNOWN_HYPERCALL, 1000
.set SAND_UNKNOWN_EXCEPTION, 1001

.text
.code32

.global _start
_start:
/* We are in unpaged protected mode now (CR0.PE = 1, CR0.PG = 0). */

/* Now segmentation is provided using "descriptor cache" loaded directly
 * from VMCS. To initialize the IDT correctly, we need to create valid
 * segment descriptors in GDT and then reload segment registers with
 * appropriate selectors.
 */
	call setup_gdt

	movl    $gdt_descr, %ebx
	movw    $(8 * GDT_ENTRIES - 1), (%ebx)  /* set GDT limit */
	movl    $gdt_table, 2(%ebx)             /* set GDT base */

	lgdt    (%ebx)
/* Switch to a new code segment */
	ljmp    $SEG_CODE, $reload_cs

reload_cs:
/* Reload other segment registers as well */
	movw    $SEG_DATA, %ax
	movw    %ax, %ds
	movw    %ax, %es
	movw    %ax, %ss
	movw    %ax, %fs
	movw    %ax, %gs
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

/* Initialize IDT */
	call setup_idt

	movl    $idt_descr, %ebx
	movw    $(8 * IDT_ENTRIES - 1), (%ebx)   /* set IDT limit */
	movl    $idt_table, 2(%ebx)              /* set IDT base */

	lidt    (%ebx)

/* Here we try to generate several exceptions
 * (Uncomment the instructions to invoke selected).
 */
	int3                    # Breakpoint exception (#BP)
/*
	xorl    %ebx, %ebx
	divl    %ebx            # Divide error exception (#DE)
*/
/*
	movb    $0x7f, %al
	addb    $1, %al
	into                    # Overflow exception (#OF)
*/
/*
	ud2                     # Invalid opcode exception (#UD)
*/
/*
	movw    $0x18, %ax      # We have no GDT descriptor for this selector
	movw    %ax, %gs        # General protection exception (#GP)
*/
/*
	movl    $0x1234, code_start     # Page-fault exception (#PF)
*/

	hlt     /* vmexit */


/* Initialize GDT with code and data segment descriptors */
setup_gdt:
	pushl   %ebx
	movl    $gdt_table, %ebx

/* Null descriptor */
	movl    $0, (%ebx)
	movl    $0, 4(%ebx)

	addl    $8, %ebx

/* Code segment descriptor */
	movw    $0xffff, (%ebx)         /* limit 15:00 */
	movw    $0x0000, 2(%ebx)        /* base 15:00 */
	movb    $0x00, 4(%ebx)          /* base 23:16 */
	movb    $0b10011010, 5(%ebx)    /* present, DPL=0, not system, exec/read */
	movb    $0b11001111, 6(%ebx)    /* G="page", 32-bit segment, limit 19:16 */
	movb    $0x00, 7(%ebx)          /* base 31:24 */

	addl    $8, %ebx

/* Data segment descriptor */
	movw    $0xffff, (%ebx)         /* limit 15:00 */
	movw    $0x0000, 2(%ebx)        /* base 15:00 */
	movb    $0x00, 4(%ebx)          /* base 23:16 */
	movb    $0b10010010, 5(%ebx)    /* present, DPL=0, not system, read/write */
	movb    $0b11001111, 6(%ebx)    /* G="page", 32-bit segment, limit 19:16 */
	movb    $0x00, 7(%ebx)          /* base 31:24 */

	popl    %ebx
	ret

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

/* Provide IDT descriptors for all x86 architecture-defined exceptions */
setup_idt:
	pushl   %ebx
	pushl   %ecx
	pushl   %esi
	pushl   %edi

	movl    $idt_table, %ebx
	movl    $handler_table, %ecx
	xorl    %edi, %edi

0:
	movl    (%ecx, %edi, 4), %esi   /* handler address */
	call    set_trap_gate
	incl    %edi                    /* vector number */
	cmpl    $IDT_ENTRIES, %edi
	jl      0b

	popl    %edi
	popl    %esi
	popl    %ecx
	popl    %ebx

	ret

/* Set up IDT descriptor for selected vector as a trap gate.
 *
 * Parameters:
 *    %edi - vector number;
 *    %esi - handler address offset;
 *    %ebx - IDT base address.
 */
set_trap_gate:
	pushl   %edi
	pushl   %esi

	leal    (%ebx, %edi, 8), %edi
	movw    %si, (%edi)             /* handler offset 15:00 */
	movw    $SEG_CODE, 2(%edi)      /* handler segment selector */
	movw    $0x8F00, 4(%edi)        /* present, DPL=0, 32-bit trap gate */
	shrl    $16, %esi
	movw    %si, 6(%edi)            /* handler offset 31:16 */

	popl    %esi
	popl    %edi
	ret

/* Macro for generating exception entry points.
 *
 * Note that this macro relies on the macro execution counter \@
 * which is shared by all invocations across this compilation unit.
 */
.macro define_exception_handler
handler_\@:
/* Some exceptions push error code to the stack, others don't */
.if \@ == 8 || (\@ >= 10 && \@ <= 14) || \@ == 17
	pushl   $\@     /* vector number */
	jmp     common_exception_handler
.else
	pushl   $0      /* fill with 0 if no error code */
	pushl   $\@     /* vector number */
	jmp     common_exception_handler
.endif

/* Provide an entry with handler address for handler_table in .rodata */
.pushsection .rodata
.long handler_\@
.popsection

.endm

.pushsection .rodata
.balign 4
/* Build a table of exception entry point addresses */
handler_table:
.popsection

.rept IDT_ENTRIES
	define_exception_handler
.endr

/* Сommon routine where all exception handlers are redirected to.
 *
 * Invokes SAND hypercall which notifies the hypervisor
 * that a guest exception has occurred. Then if the exception
 * is of type "trap", the procedure returns via "iret".
 * Otherwise, it enters the endless loop waiting for
 * the VMX-preemption timer to expire.
 */
common_exception_handler:
	pushl   %ebp
	movl    %esp, %ebp
	pushl   %eax
	pushl   %ebx
	pushl   %ecx

	movl    $SAND_HC_NOTIFY_EXCEPTION, %eax     /* hypercall number */
	movl    4(%ebp), %ebx                       /* exception vector number */
	movl    8(%ebp), %ecx                       /* error code */

	vmcall

	cmpl    $1, %ebx        /* is it #DB? */
	je      0f
	cmpl    $3, %ebx        /* is it #BP? */
	je      0f
	cmpl    $4, %ebx        /* is it #OF? */
	je      0f
	call    unhandled_exception
0:
	popl    %ecx
	popl    %ebx
	popl    %eax
	movl    %ebp, %esp
	popl    %ebp
	addl    $8, %esp        /* drop vector number and error code */
	iret

/* Loop here until the VMX-preemption timer expires */
unhandled_exception:
	jmp     .
