#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/miscdevice.h>
#include <asm/processor.h>
#include <linux/uaccess.h>
#include <linux/module.h>
#include <linux/ioctl.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/random.h>
#include <asm/fpu/api.h>
#include <asm/vmx.h>

#include "sand.h"

#define DEVICE_NAME "sand"
#define CPUID_VMX (1ul << 5)

#define VMX_BASIC_USE_TRUE_CTRLS (1ull << 55)

#define VM_TIMEOUT_MS 5000

enum sand_hypercalls {
	SAND_HC_GET_PRANDOM_VALUE = 1
};

enum sand_hypercall_errors {
	SAND_UNKNOWN_HYPERCALL = 1000
};

struct cpu_state {
	uint64_t cr0;
	uint64_t cr4;

	int saved;
	int enabled;

	void *vmxon_region;
};

struct sand_dev {
	struct miscdevice misc;
};

struct sand_host_ctx {
	uint64_t host_stack;
	uint64_t temp_rdi;
	uint64_t guest_regs_ctx;
	uint64_t err;
} __attribute__((packed));

struct sand_guest_ctx {
	uint64_t rax;
	uint64_t rbx;
	uint64_t rcx;
	uint64_t rdx;
	uint64_t rsi;
	uint64_t rdi;
	uint64_t r8;
	uint64_t r9;
	uint64_t r10;
	uint64_t r11;
	uint64_t r12;
	uint64_t r13;
	uint64_t r14;
	uint64_t r15;
	uint64_t cr2;
	uint64_t rbp;
} __attribute__((packed));

struct sand_ctx {
	void *vmcs;
	void *code;
	void *data;
	void *stack;
	void *page_dir;
	void *page_table;

	struct sand_host_ctx saved_host_ctx;
	struct sand_guest_ctx guest_ctx;
};

DEFINE_PER_CPU(struct cpu_state, cpu);

static int sand_open(struct inode *inode, struct file *file);
static int sand_release(struct inode *inode, struct file *file);
static long sand_ioctl(struct file *file, unsigned int cmd,
		unsigned long arg);

static struct file_operations sand_misc_fops = {
	.owner = THIS_MODULE,
	.open = sand_open,
	.release = sand_release,
	.compat_ioctl = sand_ioctl,
	.unlocked_ioctl = sand_ioctl,
};

static struct sand_dev dev = {
	.misc = {
		.minor = MISC_DYNAMIC_MINOR,
		.name = DEVICE_NAME,
		.fops = &sand_misc_fops
	}
};

extern int _sand_cpu_vmxon(uint64_t *addr);
extern void _sand_cpu_vmxoff(void);
extern int _sand_cpu_vmcs_clear(uint64_t *addr);
extern int _sand_cpu_vmcs_load(uint64_t *addr);

static int sand_cpu_vmxon(uint64_t addr)
{
	return _sand_cpu_vmxon(&addr);
}
static void sand_cpu_vmxoff(void)
{
	_sand_cpu_vmxoff();
}
static int sand_cpu_vmcs_clear(uint64_t addr)
{
	return _sand_cpu_vmcs_clear(&addr);
}
static int sand_cpu_vmcs_load(uint64_t addr)
{
	return _sand_cpu_vmcs_load(&addr);
}

extern int sand_cpu_vmcs_write_64(uint32_t field, uint64_t val);
extern uint64_t sand_cpu_vmcs_read_64(uint32_t field);
extern uint16_t sand_cpu_get_cs(void);
extern uint16_t sand_cpu_get_ds(void);
extern uint16_t sand_cpu_get_es(void);
extern uint16_t sand_cpu_get_ss(void);
extern uint16_t sand_cpu_get_fs(void);
extern uint16_t sand_cpu_get_gs(void);
extern uint16_t sand_cpu_get_tr(void);

static int sand_cpu_vmcs_write_32(uint32_t field, uint32_t val)
{
	return sand_cpu_vmcs_write_64(field, (uint64_t)val);
}

#define sand_cpu_vmcs_write sand_cpu_vmcs_write_64

static uint32_t sand_cpu_vmcs_read_32(uint32_t field)
{
	return (uint32_t)sand_cpu_vmcs_read_64(field);
}

#define sand_cpu_vmcs_read sand_cpu_vmcs_read_64

static uint64_t sand_cpu_get_fs_base(void)
{
	uint64_t base;
	rdmsrl_safe(MSR_FS_BASE, &base);
	return base;
}

static uint64_t sand_cpu_get_gs_base(void)
{
	uint64_t base;
	rdmsrl_safe(MSR_GS_BASE, &base);
	return base;
}

static unsigned long sand_cpu_get_gdtr_base(void)
{
	struct gdtr {
		uint16_t limit;
		uint64_t base;
	} __attribute__((packed));

	extern void sand_cpu_sgdt(struct gdtr *gdtr);

	struct gdtr _gdtr = { 0, 0 };

	sand_cpu_sgdt(&_gdtr);

	return _gdtr.base;
}

static unsigned long sand_cpu_get_idtr_base(void)
{
	struct idtr {
		uint16_t limit;
		uint64_t base;
	} __attribute__((packed));

	extern void sand_cpu_sidt(struct idtr *idtr);

	struct idtr _idtr = { 0, 0 };

	sand_cpu_sidt(&_idtr);

	return _idtr.base;
}

static unsigned long sand_cpu_get_tr_base(void)
{
	uint16_t tr_sel = sand_cpu_get_tr();
	unsigned long gdtr_base = sand_cpu_get_gdtr_base();
	uint16_t tr_idx = tr_sel >> 3;

	/* Extract the corresponding descriptor from GDT. */
	uint64_t desc_lo = ((uint64_t *)gdtr_base)[tr_idx];
	uint64_t desc_hi = ((uint64_t *)gdtr_base)[tr_idx+1];

	return 	0
		| (desc_hi << 32)
		| ((desc_lo & 0xFFFFFF0000ull) >> 16)
		| ((desc_lo >> 32) & 0xFF000000);
}

static unsigned long sand_cpu_get_sysenter_cs(void)
{
	uint64_t val;
	rdmsrl_safe(MSR_IA32_SYSENTER_CS, &val);
	return val;
}

static unsigned long sand_cpu_get_sysenter_esp(void)
{
	uint64_t val;
	rdmsrl_safe(MSR_IA32_SYSENTER_ESP, &val);
	return val;
}

static unsigned long sand_cpu_get_sysenter_eip(void)
{
	uint64_t val;
	rdmsrl_safe(MSR_IA32_SYSENTER_EIP, &val);
	return val;
}

static uint64_t sand_cpu_get_pat(void)
{
	uint64_t val;
	rdmsrl_safe(MSR_IA32_CR_PAT, &val);
	return val;
}

static uint64_t sand_cpu_get_efer(void)
{
	uint64_t val;
	rdmsrl_safe(MSR_EFER, &val);
	return val;
}

static int check_vendor(void)
{
	char vendor_name[16];

	cpuid(0,
		(unsigned int *)(&vendor_name[12]),
		(unsigned int *)(&vendor_name[0]),
		(unsigned int *)(&vendor_name[8]),
		(unsigned int *)(&vendor_name[4]));

	vendor_name[12] = '\0';

	if (0 == strncmp(vendor_name, "GenuineIntel", 12))
		return 0;

	pr_err("Non-supported CPU vendor: %s\n", vendor_name);

	return -EINVAL;
}

static int check_vtx(void)
{
	unsigned int eax, ebx, ecx, edx;

	cpuid(1, &eax, &ebx, &ecx, &edx);

	if (ecx & CPUID_VMX)
		return 0;

	pr_err("VTX isn't supported\n");

	return -EINVAL;
}

static void save_cpu_state_pcpu(void *unused)
{
	struct cpu_state *state =
		&per_cpu(cpu, smp_processor_id());

	state->cr0 = read_cr0();
	state->cr4 = __read_cr4();

	state->saved = 1;
}

static void save_cpu_state(void)
{
	on_each_cpu(save_cpu_state_pcpu, NULL, 1);
}

static void set_vmxe_cr4_pcpu(void *unused)
{
	struct cpu_state *state =
		&per_cpu(cpu, smp_processor_id());

	uint64_t vmx_basic;
	uint64_t vmx_fixed0, vmx_fixed1;
	uint64_t vmx_cr0, vmx_cr4;

	state->vmxon_region = (void *) get_zeroed_page(GFP_KERNEL);
	if (!state->vmxon_region)
		return;

	if (rdmsrl_safe(MSR_IA32_VMX_BASIC, &vmx_basic)) {
		free_page((unsigned long)state->vmxon_region);
		return;
	}

	*((uint32_t *)state->vmxon_region) = (uint32_t)vmx_basic;

	rdmsrl_safe(MSR_IA32_VMX_CR0_FIXED0, &vmx_fixed0);
	rdmsrl_safe(MSR_IA32_VMX_CR0_FIXED1, &vmx_fixed1);

	vmx_cr0 = (state->cr0 | vmx_fixed0) & vmx_fixed1;
	write_cr0(vmx_cr0);

	rdmsrl_safe(MSR_IA32_VMX_CR4_FIXED0, &vmx_fixed0);
	rdmsrl_safe(MSR_IA32_VMX_CR4_FIXED1, &vmx_fixed1);

	vmx_cr4 = (state->cr4 | vmx_fixed0) & vmx_fixed1;
	__write_cr4(vmx_cr4);

	if (sand_cpu_vmxon(virt_to_phys(state->vmxon_region))) {
		pr_err("Failed to call VMXON\n");

		write_cr0(state->cr0);
		__write_cr4(state->cr4);
		free_page((unsigned long)state->vmxon_region);
		return;
	}

	state->enabled = 1;
}

static void enable_vmx(void)
{
	on_each_cpu(set_vmxe_cr4_pcpu, NULL, 1);
}

static void restore_cr0_cr4_pcpu(void *unused)
{
	struct cpu_state *state =
		&per_cpu(cpu, smp_processor_id());

	if (state->saved) {
		write_cr0(state->cr0);
		__write_cr4(state->cr4);

		state->saved = 0;
	}
}

static void restore_cpu_state(void)
{
	on_each_cpu(restore_cr0_cr4_pcpu, NULL, 1);
}

static void exec_vmxoff_pcpu(void *unused)
{
	struct cpu_state *state =
		&per_cpu(cpu, smp_processor_id());

	if(state->enabled) {
		sand_cpu_vmxoff();
		free_page((unsigned long)state->vmxon_region);

		state->enabled = 0;
	}
}

static void disable_vmx(void)
{
	on_each_cpu(exec_vmxoff_pcpu, NULL, 1);
}

static uint32_t millisecs_to_preempt_timer_value(uint32_t millisecs)
{
	const uint64_t tsc_rate = tsc_khz * 1000;
	uint64_t misc = 0;
	uint64_t preemption_timer_rate = 0;
	uint32_t preemption_timer_value = 0;

	rdmsrl_safe(MSR_IA32_VMX_MISC, &misc);
	preemption_timer_rate = tsc_rate >> vmx_misc_preemption_timer_rate(misc);
	preemption_timer_value = preemption_timer_rate * millisecs / 1000;

	return preemption_timer_value;
}

static void init_guest_state(void)
{
	const uint8_t uc = 0, wt = 4, wb = 6, ucm = 7;
	const unsigned long guest_cr0_bits = 0
		| X86_CR0_MP
		| X86_CR0_EM
		| X86_CR0_TS;
	const unsigned long guest_cr4_bits = 0
		| X86_CR4_PVI
		| X86_CR4_DE
		| X86_CR4_PCE
		| X86_CR4_OSFXSR
		| X86_CR4_OSXMMEXCPT
		| X86_CR4_PGE
		| X86_CR4_TSD;
	union {
		uint8_t array[8];
		uint64_t word;
	} pat = {
		.array = {
			wb, wt, ucm, uc, wb, wt, ucm, uc
		}
	};
	const uint32_t timer_value = millisecs_to_preempt_timer_value(VM_TIMEOUT_MS);

	sand_cpu_vmcs_write_32(VMX_PREEMPTION_TIMER_VALUE, timer_value);
	sand_cpu_vmcs_write_32(VIRTUAL_PROCESSOR_ID, 0);
	sand_cpu_vmcs_write_64(VMCS_LINK_POINTER, -1ull);

	sand_cpu_vmcs_write(GUEST_DR7, 0x400);
	sand_cpu_vmcs_write_64(GUEST_IA32_PAT, pat.word);
	sand_cpu_vmcs_write_32(GUEST_ACTIVITY_STATE, 0);

	sand_cpu_vmcs_write(CR0_GUEST_HOST_MASK, ~guest_cr0_bits);
	sand_cpu_vmcs_write(CR4_GUEST_HOST_MASK, ~guest_cr4_bits);
}

static void set_initial_guest_ctx(struct sand_ctx *ctx)
{
	/* We use stack one page in length placed before the code. */
	/* Remember, stack grows down towards 0. */
	/* Here I hope that all the pages have addresses lower than 4GB. */

	BUG_ON((unsigned long)virt_to_phys(ctx->page_dir) >= 0x100000000);
	BUG_ON((unsigned long)virt_to_phys(ctx->page_table) >= 0x100000000);
	BUG_ON((unsigned long)virt_to_phys(ctx->stack) >= 0x100000000);
	BUG_ON((unsigned long)virt_to_phys(ctx->code) >= 0x100000000);
	BUG_ON((unsigned long)virt_to_phys(ctx->data) >= 0x100000000);

	((uint32_t *)ctx->page_dir)[0] = (uint32_t)virt_to_phys(ctx->page_table) | 1;
	/* Present. */
	((uint32_t *)ctx->page_table)[0] = (uint32_t)virt_to_phys(ctx->stack) | 3;
	/* Present, read only. */
	((uint32_t *)ctx->page_table)[1] = (uint32_t)virt_to_phys(ctx->code) | 1;
	/* Present, read/write. */
	((uint32_t *)ctx->page_table)[2] = (uint32_t)virt_to_phys(ctx->data) | 3;

	sand_cpu_vmcs_write(GUEST_RSP, 4096);
	sand_cpu_vmcs_write(GUEST_RIP, 4096);
	sand_cpu_vmcs_write(GUEST_RFLAGS, 0x2);

	sand_cpu_vmcs_write(GUEST_CR0, X86_CR0_PG | X86_CR0_PE | X86_CR0_NE
									| X86_CR0_MP);
	sand_cpu_vmcs_write(CR0_READ_SHADOW, X86_CR0_PG | X86_CR0_PE | X86_CR0_NE);
	sand_cpu_vmcs_write(GUEST_CR4, X86_CR4_PSE | X86_CR4_VMXE | X86_CR4_OSFXSR
									| X86_CR4_OSXMMEXCPT);
	sand_cpu_vmcs_write(CR4_READ_SHADOW, X86_CR4_PSE);
	sand_cpu_vmcs_write(GUEST_CR3, virt_to_phys(ctx->page_dir));

	sand_cpu_vmcs_write_64(GUEST_IA32_EFER, 0);
	sand_cpu_vmcs_write(GUEST_SYSENTER_CS, 0);
	sand_cpu_vmcs_write(GUEST_SYSENTER_ESP, 0);
	sand_cpu_vmcs_write(GUEST_SYSENTER_EIP, 0);

	sand_cpu_vmcs_write_32(GUEST_TR_SELECTOR, 0);
	sand_cpu_vmcs_write(GUEST_TR_BASE, 0);
	sand_cpu_vmcs_write_32(GUEST_TR_LIMIT, 0xFFFF);
	sand_cpu_vmcs_write_32(GUEST_TR_AR_BYTES, (1 << 7) | 0xB); /* Present, TSS. */

	sand_cpu_vmcs_write_32(GUEST_LDTR_SELECTOR, 0);
	sand_cpu_vmcs_write(GUEST_LDTR_BASE, 0);
	sand_cpu_vmcs_write_32(GUEST_LDTR_LIMIT, 0);
	sand_cpu_vmcs_write_32(GUEST_LDTR_AR_BYTES, 1 << 16);      /* Unusable. */

	sand_cpu_vmcs_write_32(GUEST_CS_SELECTOR, 0);
	sand_cpu_vmcs_write(GUEST_CS_BASE, 0);
	sand_cpu_vmcs_write_32(GUEST_CS_LIMIT, 0xFFFFFFFF);
	sand_cpu_vmcs_write_32(GUEST_CS_AR_BYTES, 0
			| (1 << 7)   /* Present. */
			| (1 << 14)  /* Seg 32. */
			| (1 << 15)  /* Granularity. */
			| (1 << 4)   /* Not system. */
			| 0xA        /* Code. */
			| 0x1);      /* Accessed. */

	sand_cpu_vmcs_write_32(GUEST_DS_SELECTOR, 0);
	sand_cpu_vmcs_write(GUEST_DS_BASE, 0);
	sand_cpu_vmcs_write_32(GUEST_DS_LIMIT, 0xFFFFFFFF);
	sand_cpu_vmcs_write_32(GUEST_DS_AR_BYTES, 0
			| (1 << 7)   /* Present. */
			| (1 << 14)  /* Seg 32. */
			| (1 << 15)  /* Granularity. */
			| (1 << 4)   /* Not system. */
			| 0x2        /* Data R/W. */
			| 0x1);      /* Accessed. */

	sand_cpu_vmcs_write_32(GUEST_ES_SELECTOR, 0);
	sand_cpu_vmcs_write(GUEST_ES_BASE, 0);
	sand_cpu_vmcs_write_32(GUEST_ES_LIMIT, 0xFFFFFFFF);
	sand_cpu_vmcs_write_32(GUEST_ES_AR_BYTES, 0
			| (1 << 7)   /* Present. */
			| (1 << 14)  /* Seg 32. */
			| (1 << 15)  /* Granularity. */
			| (1 << 4)   /* Not system. */
			| 0x2        /* Data R/W. */
			| 0x1);      /* Accessed. */

	sand_cpu_vmcs_write_32(GUEST_SS_SELECTOR, 0);
	sand_cpu_vmcs_write(GUEST_SS_BASE, 0);
	sand_cpu_vmcs_write_32(GUEST_SS_LIMIT, 0xFFFFFFFF);
	sand_cpu_vmcs_write_32(GUEST_SS_AR_BYTES, 0
			| (1 << 7)   /* Present. */
			| (1 << 14)  /* Seg 32. */
			| (1 << 15)  /* Granularity. */
			| (1 << 4)   /* Not system. */
			| 0x2        /* Data R/W. */
			| 0x1);      /* Accessed. */

	sand_cpu_vmcs_write_32(GUEST_FS_SELECTOR, 0);
	sand_cpu_vmcs_write(GUEST_FS_BASE, 0);
	sand_cpu_vmcs_write_32(GUEST_FS_LIMIT, 0xFFFFFFFF);
	sand_cpu_vmcs_write_32(GUEST_FS_AR_BYTES, 0
			| (1 << 7)   /* Present. */
			| (1 << 14)  /* Seg 32. */
			| (1 << 15)  /* Granularity. */
			| (1 << 4)   /* Not system. */
			| 0x2        /* Data R/W. */
			| 0x1);      /* Accessed. */

	sand_cpu_vmcs_write_32(GUEST_GS_SELECTOR, 0);
	sand_cpu_vmcs_write(GUEST_GS_BASE, 0);
	sand_cpu_vmcs_write_32(GUEST_GS_LIMIT, 0xFFFFFFFF);
	sand_cpu_vmcs_write_32(GUEST_GS_AR_BYTES, 0
			| (1 << 7)   /* Present. */
			| (1 << 14)  /* Seg 32. */
			| (1 << 15)  /* Granularity. */
			| (1 << 4)   /* Not system. */
			| 0x2        /* Data R/W. */
			| 0x1);      /* Accessed. */
}

static void save_host_state(void)
{
	sand_cpu_vmcs_write_32(HOST_CS_SELECTOR,
			(uint32_t)sand_cpu_get_cs());
	sand_cpu_vmcs_write_32(HOST_DS_SELECTOR,
			(uint32_t)sand_cpu_get_ds());
	sand_cpu_vmcs_write_32(HOST_ES_SELECTOR,
			(uint32_t)sand_cpu_get_es());
	sand_cpu_vmcs_write_32(HOST_SS_SELECTOR,
			(uint32_t)sand_cpu_get_ss());
	sand_cpu_vmcs_write_32(HOST_FS_SELECTOR,
			(uint32_t)sand_cpu_get_fs() & 0xFFFC);
	sand_cpu_vmcs_write_32(HOST_GS_SELECTOR,
			(uint32_t)sand_cpu_get_gs() & 0xFFFC);
	sand_cpu_vmcs_write_32(HOST_TR_SELECTOR,
			(uint32_t)sand_cpu_get_tr());

	sand_cpu_vmcs_write(HOST_FS_BASE, sand_cpu_get_fs_base());
	sand_cpu_vmcs_write(HOST_GS_BASE, sand_cpu_get_gs_base());
	sand_cpu_vmcs_write(HOST_TR_BASE, sand_cpu_get_tr_base());
	sand_cpu_vmcs_write(HOST_GDTR_BASE, sand_cpu_get_gdtr_base());
	sand_cpu_vmcs_write(HOST_IDTR_BASE, sand_cpu_get_idtr_base());
	sand_cpu_vmcs_write(HOST_IA32_SYSENTER_CS, sand_cpu_get_sysenter_cs());
	sand_cpu_vmcs_write(HOST_IA32_SYSENTER_ESP, sand_cpu_get_sysenter_esp());
	sand_cpu_vmcs_write(HOST_IA32_SYSENTER_EIP, sand_cpu_get_sysenter_eip());
}

static int init_sand_ctx(struct sand_ctx *ctx)
{
	uint32_t cpu_based_controls;
	uint32_t pin_based_controls;
	uint32_t vmentry_controls;
	uint32_t vmexit_controls;

	uint64_t vmx_basic = 0, ctrls = 0;

	extern void sand_vm_exit(void);

	cpu_based_controls = 0
		| CPU_BASED_HLT_EXITING
		;

	pin_based_controls = 0
		| PIN_BASED_EXT_INTR_MASK
		| PIN_BASED_NMI_EXITING
		| PIN_BASED_VMX_PREEMPTION_TIMER
		;

	vmentry_controls = 0;

	vmexit_controls = 0
		| VM_EXIT_HOST_ADDR_SPACE_SIZE
		| VM_EXIT_SAVE_VMX_PREEMPTION_TIMER
		;

	rdmsrl_safe(MSR_IA32_VMX_BASIC, &vmx_basic);

	if (vmx_basic & VMX_BASIC_USE_TRUE_CTRLS)
		rdmsrl_safe(MSR_IA32_VMX_TRUE_PINBASED_CTLS, &ctrls);
	else
		rdmsrl_safe(MSR_IA32_VMX_PINBASED_CTLS, &ctrls);

	pin_based_controls |= ctrls & 0xFFFFFFFF;
	pin_based_controls &= (ctrls >> 32);

	if (vmx_basic & VMX_BASIC_USE_TRUE_CTRLS)
		rdmsrl_safe(MSR_IA32_VMX_TRUE_PROCBASED_CTLS, &ctrls);
	else
		rdmsrl_safe(MSR_IA32_VMX_PROCBASED_CTLS, &ctrls);

	cpu_based_controls |= ctrls & 0xFFFFFFFF;
	cpu_based_controls &= (ctrls >> 32);

	if (vmx_basic & VMX_BASIC_USE_TRUE_CTRLS)
		rdmsrl_safe(MSR_IA32_VMX_TRUE_EXIT_CTLS, &ctrls);
	else
		rdmsrl_safe(MSR_IA32_VMX_EXIT_CTLS, &ctrls);

	vmexit_controls |= ctrls & 0xFFFFFFFF;
	vmexit_controls &= (ctrls >> 32);

	if (vmx_basic & VMX_BASIC_USE_TRUE_CTRLS)
		rdmsrl_safe(MSR_IA32_VMX_TRUE_ENTRY_CTLS, &ctrls);
	else
		rdmsrl_safe(MSR_IA32_VMX_ENTRY_CTLS, &ctrls);

	vmentry_controls |= ctrls & 0xFFFFFFFF;
	vmentry_controls &= (ctrls >> 32);

	sand_cpu_vmcs_clear(virt_to_phys(ctx->vmcs));
	*((uint32_t*)ctx->vmcs) = (uint32_t)vmx_basic;

	if (sand_cpu_vmcs_load(virt_to_phys(ctx->vmcs)))
		goto out;

	sand_cpu_vmcs_write_32(PIN_BASED_VM_EXEC_CONTROL, pin_based_controls);
	sand_cpu_vmcs_write_32(CPU_BASED_VM_EXEC_CONTROL, cpu_based_controls);
	sand_cpu_vmcs_write_32(VM_EXIT_CONTROLS, vmexit_controls);
	sand_cpu_vmcs_write_32(VM_ENTRY_CONTROLS, vmentry_controls);

	sand_cpu_vmcs_write_32(PAGE_FAULT_ERROR_CODE_MASK, 0);
	sand_cpu_vmcs_write_32(PAGE_FAULT_ERROR_CODE_MATCH, 0);
	sand_cpu_vmcs_write_32(EXCEPTION_BITMAP, 0);

	save_host_state();

	sand_cpu_vmcs_write_64(HOST_IA32_PAT, sand_cpu_get_pat());
	sand_cpu_vmcs_write_64(HOST_IA32_EFER, sand_cpu_get_efer());
	sand_cpu_vmcs_write_64(HOST_IA32_PERF_GLOBAL_CTRL, 0);

	sand_cpu_vmcs_write(HOST_CR0, read_cr0() & ~X86_CR0_TS);
	sand_cpu_vmcs_write(HOST_CR3, __read_cr3());
	sand_cpu_vmcs_write(HOST_CR4, __read_cr4());

	sand_cpu_vmcs_write_32(CR3_TARGET_COUNT, 0);

	sand_cpu_vmcs_write(HOST_RIP, (unsigned long)(void *)sand_vm_exit);
	sand_cpu_vmcs_write(HOST_RSP, (unsigned long)&ctx->saved_host_ctx);

	init_guest_state();
	set_initial_guest_ctx(ctx);

	pr_info("Pin based exec control: %x\n",
		sand_cpu_vmcs_read_32(PIN_BASED_VM_EXEC_CONTROL));
	pr_info("Cpu based VM exec control: %x\n",
		sand_cpu_vmcs_read_32(CPU_BASED_VM_EXEC_CONTROL));
	pr_info("VM exit controls: %x\n",
		sand_cpu_vmcs_read_32(VM_EXIT_CONTROLS));
	pr_info("VM entry controls: %x\n",
		sand_cpu_vmcs_read_32(VM_ENTRY_CONTROLS));

	if (sand_cpu_vmcs_clear(virt_to_phys(ctx->vmcs)))
		goto out;

	return 0;
out:
	return -EINVAL;
}

static int sand_open(struct inode *inode, struct file *file)
{
	struct sand_ctx *ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);

	file->private_data = NULL;

	if (!ctx) {
		pr_err("Failed to alloc sand context\n");
		goto out;
	}

	ctx->vmcs = (void *)get_zeroed_page(GFP_KERNEL);
	if (!ctx->vmcs) {
		pr_err("Failed to alloc vmcs\n");
		goto out_free_ctx;
	}

	ctx->code = (void *)get_zeroed_page(GFP_DMA32 | GFP_KERNEL);
	if (!ctx->code) {
		pr_err("Failed to alloc code page\n");
		goto out_free_vmcs;
	}

	ctx->data = (void *)get_zeroed_page(GFP_DMA32 | GFP_KERNEL);
	if (!ctx->data) {
		pr_err("Failed to alloc data page\n");
		goto out_free_code;
	}

	ctx->stack = (void *)get_zeroed_page(GFP_DMA32 | GFP_KERNEL);
	if (!ctx->stack) {
		pr_err("Failed to alloc stack page\n");
		goto out_free_data;
	}

	ctx->page_dir = (void *)get_zeroed_page(GFP_DMA32 | GFP_KERNEL);
	if (!ctx->page_dir) {
		pr_err("Failed to alloc page for page directory\n");
		goto out_free_stack;
	}

	ctx->page_table = (void *)get_zeroed_page(GFP_DMA32 | GFP_KERNEL);
	if (!ctx->page_table) {
		pr_err("Failed to alloc page for page table\n");
		goto out_free_page_dir;
	}

	file->private_data = ctx;

	return 0;

out_free_page_dir:
	free_page((unsigned long)ctx->page_dir);
out_free_stack:
	free_page((unsigned long)ctx->stack);
out_free_data:
	free_page((unsigned long)ctx->data);
out_free_code:
	free_page((unsigned long)ctx->code);
out_free_vmcs:
	free_page((unsigned long)ctx->vmcs);
out_free_ctx:
	kfree(ctx);
out:
	return -ENOMEM;
}

static int sand_release(struct inode *inode, struct file *file)
{
	struct sand_ctx *ctx = file->private_data;

	if (ctx) {
		if (ctx->vmcs)
			free_page((unsigned long)ctx->vmcs);
		if (ctx->code)
			free_page((unsigned long)ctx->code);
		if (ctx->data)
			free_page((unsigned long)ctx->data);
		if (ctx->stack)
			free_page((unsigned long)ctx->stack);
		if (ctx->page_dir)
			free_page((unsigned long)ctx->page_dir);
		if (ctx->page_table)
			free_page((unsigned long)ctx->page_table);

		kfree(ctx);
	}

	return 0;
}

static void skip_vmexit_instruction(void)
{
	uint64_t guest_rip = sand_cpu_vmcs_read(GUEST_RIP);
	guest_rip += sand_cpu_vmcs_read_32(VM_EXIT_INSTRUCTION_LEN);
	sand_cpu_vmcs_write(GUEST_RIP, guest_rip);
}

static void handle_hypercall(struct sand_ctx *ctx)
{
	uint64_t nr, ret;
	uint64_t arg[4];

	nr = ctx->guest_ctx.rax;
	arg[0] = ctx->guest_ctx.rbx;
	arg[1] = ctx->guest_ctx.rcx;
	arg[2] = ctx->guest_ctx.rdx;
	arg[3] = ctx->guest_ctx.rsi;

	switch (nr) {
	case SAND_HC_GET_PRANDOM_VALUE:
		ret = prandom_u32() & 0xFFFF;
		break;
	default:
		pr_warning("Unknown hypercall %llu\n", nr);
		ret = -SAND_UNKNOWN_HYPERCALL;
		break;
	}

	ctx->guest_ctx.rax = (uint32_t)ret;

	skip_vmexit_instruction();
}

static int run_ctx(struct sand_ctx *ctx, unsigned long first)
{
	extern void sand_vm_launch(struct sand_guest_ctx *gctx,
			struct sand_host_ctx *hctx, unsigned long first);

	sand_vm_launch(&ctx->guest_ctx, &ctx->saved_host_ctx, first);

	return ctx->saved_host_ctx.err;
}

static long sand_ioctl(struct file *file, unsigned int cmd,
		unsigned long arg)
{
	struct sandbox __user *sandbox_ptr = (struct sandbox __user *)arg;
	struct sand_ctx *ctx = file->private_data;

	unsigned long non_copied;
	struct sandbox sandbox;

	unsigned long first = 1;
	int err, stop = 0;

	if (SAND_IOCTL_EXECUTE_FUNCTION != cmd) {
		pr_err("Incorrect IOCTL command\n");
		goto out;
	}

	non_copied = copy_from_user(&sandbox, sandbox_ptr, sizeof(sandbox));
	if (non_copied) {
		pr_err("Failed to copy sandbox context from user\n");
		goto out;
	}

	if (sandbox.code_size > PAGE_SIZE) {
		pr_err("Code is too long\n");
		goto out;
	}

	non_copied = copy_from_user(ctx->code, sandbox.code, sandbox.code_size);
	if (non_copied) {
		pr_err("Failed to copy code from user\n");
		goto out;
	}

	pr_info("Going to run %zu bytes of code\n", sandbox.code_size);

	kernel_fpu_begin();

	if (init_sand_ctx(ctx)) {
		pr_err("Failed to init sand context\n");
		goto out_preempt_enable;
	}

	if (sand_cpu_vmcs_load(virt_to_phys(ctx->vmcs))) {
		pr_err("Failed to load VMCS\n");
		goto out_preempt_enable;
	}

	ctx->guest_ctx.rax = sandbox.eax;
	ctx->guest_ctx.rbx = sandbox.ebx;
	ctx->guest_ctx.rcx = sandbox.ecx;
	ctx->guest_ctx.rdx = sandbox.edx;

	do {
		err = run_ctx(ctx, first);
		if (err) {
			uint32_t ierr = sand_cpu_vmcs_read_32(VM_INSTRUCTION_ERROR);
			pr_err("VM Instruction Error: %x\n", ierr);

			goto out_preempt_enable;
		} else {
			uint32_t vmexit = sand_cpu_vmcs_read_32(VM_EXIT_REASON);
			unsigned long rip = sand_cpu_vmcs_read(GUEST_RIP);
			pr_info("VM Exit Reason %x\n", vmexit);
			pr_info("ip: %zx\n", rip);

			first = 0;

			switch (vmexit) {
			case EXIT_REASON_VMCALL:
				handle_hypercall(ctx);
				break;
			case EXIT_REASON_HLT:
			case EXIT_REASON_PREEMPTION_TIMER:
			/* We return to user space on HLT VMEXIT
			 * or when VMX-preemption timer expires.
			 */
				stop = 1;
				break;
			}
		}
	} while (!stop);

	sandbox.eax = ctx->guest_ctx.rax;
	sandbox.ebx = ctx->guest_ctx.rbx;
	sandbox.ecx = ctx->guest_ctx.rcx;
	sandbox.edx = ctx->guest_ctx.rdx;

	if (sand_cpu_vmcs_clear(virt_to_phys(ctx->vmcs))) {
		pr_err("Failed to clear VMCS\n");
		goto out_preempt_enable;
	}

	kernel_fpu_end();

	non_copied = copy_to_user(sandbox_ptr, &sandbox, sizeof(sandbox));
	if (non_copied) {
		pr_err("Failed to copy sandbox context back to user\n");
		goto out;
	}

	return 0;

out_preempt_enable:
	kernel_fpu_end();
out:
	return -EINVAL;
}

static int __init sand_init(void)
{
	if (check_vendor())
		goto out;

	pr_info("Detected Intel CPU\n");

	if (check_vtx())
		goto out;

	pr_info("Detected basic VTX support\n");

	save_cpu_state();

	pr_info("Saved original host state (CR0, CR4)\n");

	enable_vmx();

	pr_info("Enabled virtualization extensions\n");

	if (misc_register(&dev.misc)) {
		pr_err("Failed to register misc device\n");
		goto out;
	}

	pr_info("Registered misc device\n");

	return 0;
out:
	return -EINVAL;
}

static void __exit sand_exit(void)
{
	disable_vmx();

	pr_info("Disabled virtualization extensions\n");

	restore_cpu_state();

	pr_info("Restored original host state (CR0, CR4)\n");

	misc_deregister(&dev.misc);

	pr_info("Deregistered misc device\n");
}

module_init(sand_init);
module_exit(sand_exit);

MODULE_LICENSE("Dual BSD/GPL");
