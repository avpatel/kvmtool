#include "kvm/kvm-cpu.h"
#include "kvm/kvm.h"
#include "kvm/virtio.h"
#include "kvm/sbi.h"
#include "kvm/term.h"

#include <asm/ptrace.h>

static int debug_fd;

void kvm_cpu__set_debug_fd(int fd)
{
	debug_fd = fd;
}

int kvm_cpu__get_debug_fd(void)
{
	return debug_fd;
}

static __u64 __kvm_reg_id(__u64 type, __u64 idx)
{
	__u64 id = KVM_REG_RISCV | type | idx;

	if (__riscv_xlen == 64)
		id |= KVM_REG_SIZE_U64;
	else
		id |= KVM_REG_SIZE_U32;

	return id;
}

#define RISCV_CONFIG_REG(name)	__kvm_reg_id(KVM_REG_RISCV_CONFIG, \
					     KVM_REG_RISCV_CONFIG_REG(name))

#define RISCV_CORE_REG(name)	__kvm_reg_id(KVM_REG_RISCV_CORE, \
					     KVM_REG_RISCV_CORE_REG(name))

#define RISCV_CSR_REG(name)	__kvm_reg_id(KVM_REG_RISCV_CSR, \
					     KVM_REG_RISCV_CSR_REG(name))

#define RISCV_TIMER_REG(name)	__kvm_reg_id(KVM_REG_RISCV_TIMER, \
					     KVM_REG_RISCV_TIMER_REG(name))

struct kvm_cpu *kvm_cpu__arch_init(struct kvm *kvm, unsigned long cpu_id)
{
	struct kvm_cpu *vcpu;
	unsigned long timebase = 0, isa = 0;
	int coalesced_offset, mmap_size;
	struct kvm_one_reg reg;

	vcpu = calloc(1, sizeof(struct kvm_cpu));
	if (!vcpu)
		return NULL;

	vcpu->vcpu_fd = ioctl(kvm->vm_fd, KVM_CREATE_VCPU, cpu_id);
	if (vcpu->vcpu_fd < 0)
		die_perror("KVM_CREATE_VCPU ioctl");

	reg.id = RISCV_CONFIG_REG(isa);
	reg.addr = (unsigned long)&isa;
	if (ioctl(vcpu->vcpu_fd, KVM_GET_ONE_REG, &reg) < 0)
		die("KVM_GET_ONE_REG failed (config.isa)");

	reg.id = RISCV_TIMER_REG(frequency);
	reg.addr = (unsigned long)&timebase;
	if (ioctl(vcpu->vcpu_fd, KVM_GET_ONE_REG, &reg) < 0)
		die("KVM_GET_ONE_REG failed (config.timebase)");

	mmap_size = ioctl(kvm->sys_fd, KVM_GET_VCPU_MMAP_SIZE, 0);
	if (mmap_size < 0)
		die_perror("KVM_GET_VCPU_MMAP_SIZE ioctl");

	vcpu->kvm_run = mmap(NULL, mmap_size, PROT_RW, MAP_SHARED,
			     vcpu->vcpu_fd, 0);
	if (vcpu->kvm_run == MAP_FAILED)
		die("unable to mmap vcpu fd");

	coalesced_offset = ioctl(kvm->sys_fd, KVM_CHECK_EXTENSION,
				 KVM_CAP_COALESCED_MMIO);
	if (coalesced_offset)
		vcpu->ring = (void *)vcpu->kvm_run +
			     (coalesced_offset * PAGE_SIZE);

	reg.id = RISCV_CONFIG_REG(isa);
	reg.addr = (unsigned long)&isa;
	if (ioctl(vcpu->vcpu_fd, KVM_SET_ONE_REG, &reg) < 0)
		die("KVM_SET_ONE_REG failed (config.isa)");

	/* Populate the vcpu structure. */
	vcpu->kvm		= kvm;
	vcpu->cpu_id		= cpu_id;
	vcpu->riscv_isa		= isa;
	vcpu->riscv_xlen	= __riscv_xlen;
	vcpu->riscv_timebase	= timebase;
	vcpu->is_running	= true;

	return vcpu;
}

void kvm_cpu__arch_nmi(struct kvm_cpu *cpu)
{
}

void kvm_cpu__delete(struct kvm_cpu *vcpu)
{
	free(vcpu);
}

static bool kvm_cpu_riscv_sbi(struct kvm_cpu *vcpu)
{
	char ch;
	bool ret = true;
	int dfd = kvm_cpu__get_debug_fd();

	switch (vcpu->kvm_run->riscv_sbi.extension_id) {
	case SBI_EXT_0_1_CONSOLE_PUTCHAR:
		ch = vcpu->kvm_run->riscv_sbi.args[0];
		term_putc(&ch, 1, 0);
		vcpu->kvm_run->riscv_sbi.ret[0] = 0;
		break;
	case SBI_EXT_0_1_CONSOLE_GETCHAR:
		if (term_readable(0))
			vcpu->kvm_run->riscv_sbi.ret[0] =
					term_getc(vcpu->kvm, 0);
		else
			vcpu->kvm_run->riscv_sbi.ret[0] = SBI_ERR_FAILURE;
		break;
	default:
		dprintf(dfd, "Unhandled SBI call\n");
		dprintf(dfd, "extension_id=0x%lx function_id=0x%lx\n",
			vcpu->kvm_run->riscv_sbi.extension_id,
			vcpu->kvm_run->riscv_sbi.function_id);
		dprintf(dfd, "args[0]=0x%lx args[1]=0x%lx\n",
			vcpu->kvm_run->riscv_sbi.args[0],
			vcpu->kvm_run->riscv_sbi.args[1]);
		dprintf(dfd, "args[2]=0x%lx args[3]=0x%lx\n",
			vcpu->kvm_run->riscv_sbi.args[2],
			vcpu->kvm_run->riscv_sbi.args[3]);
		dprintf(dfd, "args[4]=0x%lx args[5]=0x%lx\n",
			vcpu->kvm_run->riscv_sbi.args[4],
			vcpu->kvm_run->riscv_sbi.args[5]);
		ret = false;
		break;
	};

	return ret;
}

bool kvm_cpu__handle_exit(struct kvm_cpu *vcpu)
{
	switch (vcpu->kvm_run->exit_reason) {
	case KVM_EXIT_RISCV_SBI:
		return kvm_cpu_riscv_sbi(vcpu);
	default:
		break;
	};

	return false;
}

void kvm_cpu__show_page_tables(struct kvm_cpu *vcpu)
{
}

void kvm_cpu__reset_vcpu(struct kvm_cpu *vcpu)
{
	struct kvm *kvm = vcpu->kvm;
	struct kvm_mp_state mp_state;
	struct kvm_one_reg reg;
	unsigned long data;

	if (ioctl(vcpu->vcpu_fd, KVM_GET_MP_STATE, &mp_state) < 0)
		die_perror("KVM_GET_MP_STATE failed");

	/*
	 * If MP state is stopped then it means Linux KVM RISC-V emulates
	 * SBI v0.2 (or higher) with HART power managment and give VCPU
	 * will power-up at boot-time by boot VCPU. For such VCPU, we
	 * don't update PC, A0 and A1 here.
	 */
	if (mp_state.mp_state == KVM_MP_STATE_STOPPED)
		return;

	reg.addr = (unsigned long)&data;

	data	= kvm->arch.kern_guest_start;
	reg.id	= RISCV_CORE_REG(regs.pc);
	if (ioctl(vcpu->vcpu_fd, KVM_SET_ONE_REG, &reg) < 0)
		die_perror("KVM_SET_ONE_REG failed (pc)");

	data	= vcpu->cpu_id;
	reg.id	= RISCV_CORE_REG(regs.a0);
	if (ioctl(vcpu->vcpu_fd, KVM_SET_ONE_REG, &reg) < 0)
		die_perror("KVM_SET_ONE_REG failed (a0)");

	data	= kvm->arch.dtb_guest_start;
	reg.id	= RISCV_CORE_REG(regs.a1);
	if (ioctl(vcpu->vcpu_fd, KVM_SET_ONE_REG, &reg) < 0)
		die_perror("KVM_SET_ONE_REG failed (a1)");
}

int kvm_cpu__get_endianness(struct kvm_cpu *vcpu)
{
	return VIRTIO_ENDIAN_LE;
}

void kvm_cpu__show_code(struct kvm_cpu *vcpu)
{
	struct kvm_one_reg reg;
	unsigned long data;
	int debug_fd = kvm_cpu__get_debug_fd();

	reg.addr = (unsigned long)&data;

	dprintf(debug_fd, "\n*PC:\n");
	reg.id = RISCV_CORE_REG(regs.pc);
	if (ioctl(vcpu->vcpu_fd, KVM_GET_ONE_REG, &reg) < 0)
		die("KVM_GET_ONE_REG failed (show_code @ PC)");

	kvm__dump_mem(vcpu->kvm, data, 32, debug_fd);

	dprintf(debug_fd, "\n*RA:\n");
	reg.id = RISCV_CORE_REG(regs.ra);
	if (ioctl(vcpu->vcpu_fd, KVM_GET_ONE_REG, &reg) < 0)
		die("KVM_GET_ONE_REG failed (show_code @ RA)");

	kvm__dump_mem(vcpu->kvm, data, 32, debug_fd);
}

void kvm_cpu__show_registers(struct kvm_cpu *vcpu)
{
	struct kvm_one_reg reg;
	unsigned long data;
	int debug_fd = kvm_cpu__get_debug_fd();

	reg.addr = (unsigned long)&data;
	dprintf(debug_fd, "\n Registers:\n");

	reg.id		= RISCV_CORE_REG(mode);
	if (ioctl(vcpu->vcpu_fd, KVM_GET_ONE_REG, &reg) < 0)
		die("KVM_GET_ONE_REG failed (mode)");
	dprintf(debug_fd, " MODE:  0x%lx\n", data);

	reg.id		= RISCV_CORE_REG(regs.pc);
	if (ioctl(vcpu->vcpu_fd, KVM_GET_ONE_REG, &reg) < 0)
		die("KVM_GET_ONE_REG failed (pc)");
	dprintf(debug_fd, " PC:    0x%lx\n", data);

	reg.id		= RISCV_CORE_REG(regs.ra);
	if (ioctl(vcpu->vcpu_fd, KVM_GET_ONE_REG, &reg) < 0)
		die("KVM_GET_ONE_REG failed (ra)");
	dprintf(debug_fd, " RA:    0x%lx\n", data);

	reg.id		= RISCV_CORE_REG(regs.sp);
	if (ioctl(vcpu->vcpu_fd, KVM_GET_ONE_REG, &reg) < 0)
		die("KVM_GET_ONE_REG failed (sp)");
	dprintf(debug_fd, " SP:    0x%lx\n", data);

	reg.id		= RISCV_CORE_REG(regs.gp);
	if (ioctl(vcpu->vcpu_fd, KVM_GET_ONE_REG, &reg) < 0)
		die("KVM_GET_ONE_REG failed (gp)");
	dprintf(debug_fd, " GP:    0x%lx\n", data);

	reg.id		= RISCV_CORE_REG(regs.tp);
	if (ioctl(vcpu->vcpu_fd, KVM_GET_ONE_REG, &reg) < 0)
		die("KVM_GET_ONE_REG failed (tp)");
	dprintf(debug_fd, " TP:    0x%lx\n", data);

	reg.id		= RISCV_CORE_REG(regs.t0);
	if (ioctl(vcpu->vcpu_fd, KVM_GET_ONE_REG, &reg) < 0)
		die("KVM_GET_ONE_REG failed (t0)");
	dprintf(debug_fd, " T0:    0x%lx\n", data);

	reg.id		= RISCV_CORE_REG(regs.t1);
	if (ioctl(vcpu->vcpu_fd, KVM_GET_ONE_REG, &reg) < 0)
		die("KVM_GET_ONE_REG failed (t1)");
	dprintf(debug_fd, " T1:    0x%lx\n", data);

	reg.id		= RISCV_CORE_REG(regs.t2);
	if (ioctl(vcpu->vcpu_fd, KVM_GET_ONE_REG, &reg) < 0)
		die("KVM_GET_ONE_REG failed (t2)");
	dprintf(debug_fd, " T2:    0x%lx\n", data);

	reg.id		= RISCV_CORE_REG(regs.s0);
	if (ioctl(vcpu->vcpu_fd, KVM_GET_ONE_REG, &reg) < 0)
		die("KVM_GET_ONE_REG failed (s0)");
	dprintf(debug_fd, " S0:    0x%lx\n", data);

	reg.id		= RISCV_CORE_REG(regs.s1);
	if (ioctl(vcpu->vcpu_fd, KVM_GET_ONE_REG, &reg) < 0)
		die("KVM_GET_ONE_REG failed (s1)");
	dprintf(debug_fd, " S1:    0x%lx\n", data);

	reg.id		= RISCV_CORE_REG(regs.a0);
	if (ioctl(vcpu->vcpu_fd, KVM_GET_ONE_REG, &reg) < 0)
		die("KVM_GET_ONE_REG failed (a0)");
	dprintf(debug_fd, " A0:    0x%lx\n", data);

	reg.id		= RISCV_CORE_REG(regs.a1);
	if (ioctl(vcpu->vcpu_fd, KVM_GET_ONE_REG, &reg) < 0)
		die("KVM_GET_ONE_REG failed (a1)");
	dprintf(debug_fd, " A1:    0x%lx\n", data);

	reg.id		= RISCV_CORE_REG(regs.a2);
	if (ioctl(vcpu->vcpu_fd, KVM_GET_ONE_REG, &reg) < 0)
		die("KVM_GET_ONE_REG failed (a2)");
	dprintf(debug_fd, " A2:    0x%lx\n", data);

	reg.id		= RISCV_CORE_REG(regs.a3);
	if (ioctl(vcpu->vcpu_fd, KVM_GET_ONE_REG, &reg) < 0)
		die("KVM_GET_ONE_REG failed (a3)");
	dprintf(debug_fd, " A3:    0x%lx\n", data);

	reg.id		= RISCV_CORE_REG(regs.a4);
	if (ioctl(vcpu->vcpu_fd, KVM_GET_ONE_REG, &reg) < 0)
		die("KVM_GET_ONE_REG failed (a4)");
	dprintf(debug_fd, " A4:    0x%lx\n", data);

	reg.id		= RISCV_CORE_REG(regs.a5);
	if (ioctl(vcpu->vcpu_fd, KVM_GET_ONE_REG, &reg) < 0)
		die("KVM_GET_ONE_REG failed (a5)");
	dprintf(debug_fd, " A5:    0x%lx\n", data);

	reg.id		= RISCV_CORE_REG(regs.a6);
	if (ioctl(vcpu->vcpu_fd, KVM_GET_ONE_REG, &reg) < 0)
		die("KVM_GET_ONE_REG failed (a6)");
	dprintf(debug_fd, " A6:    0x%lx\n", data);

	reg.id		= RISCV_CORE_REG(regs.a7);
	if (ioctl(vcpu->vcpu_fd, KVM_GET_ONE_REG, &reg) < 0)
		die("KVM_GET_ONE_REG failed (a7)");
	dprintf(debug_fd, " A7:    0x%lx\n", data);

	reg.id		= RISCV_CORE_REG(regs.s2);
	if (ioctl(vcpu->vcpu_fd, KVM_GET_ONE_REG, &reg) < 0)
		die("KVM_GET_ONE_REG failed (s2)");
	dprintf(debug_fd, " S2:    0x%lx\n", data);

	reg.id		= RISCV_CORE_REG(regs.s3);
	if (ioctl(vcpu->vcpu_fd, KVM_GET_ONE_REG, &reg) < 0)
		die("KVM_GET_ONE_REG failed (s3)");
	dprintf(debug_fd, " S3:    0x%lx\n", data);

	reg.id		= RISCV_CORE_REG(regs.s4);
	if (ioctl(vcpu->vcpu_fd, KVM_GET_ONE_REG, &reg) < 0)
		die("KVM_GET_ONE_REG failed (s4)");
	dprintf(debug_fd, " S4:    0x%lx\n", data);

	reg.id		= RISCV_CORE_REG(regs.s5);
	if (ioctl(vcpu->vcpu_fd, KVM_GET_ONE_REG, &reg) < 0)
		die("KVM_GET_ONE_REG failed (s5)");
	dprintf(debug_fd, " S5:    0x%lx\n", data);

	reg.id		= RISCV_CORE_REG(regs.s6);
	if (ioctl(vcpu->vcpu_fd, KVM_GET_ONE_REG, &reg) < 0)
		die("KVM_GET_ONE_REG failed (s6)");
	dprintf(debug_fd, " S6:    0x%lx\n", data);

	reg.id		= RISCV_CORE_REG(regs.s7);
	if (ioctl(vcpu->vcpu_fd, KVM_GET_ONE_REG, &reg) < 0)
		die("KVM_GET_ONE_REG failed (s7)");
	dprintf(debug_fd, " S7:    0x%lx\n", data);

	reg.id		= RISCV_CORE_REG(regs.s8);
	if (ioctl(vcpu->vcpu_fd, KVM_GET_ONE_REG, &reg) < 0)
		die("KVM_GET_ONE_REG failed (s8)");
	dprintf(debug_fd, " S8:    0x%lx\n", data);

	reg.id		= RISCV_CORE_REG(regs.s9);
	if (ioctl(vcpu->vcpu_fd, KVM_GET_ONE_REG, &reg) < 0)
		die("KVM_GET_ONE_REG failed (s9)");
	dprintf(debug_fd, " S9:    0x%lx\n", data);

	reg.id		= RISCV_CORE_REG(regs.s10);
	if (ioctl(vcpu->vcpu_fd, KVM_GET_ONE_REG, &reg) < 0)
		die("KVM_GET_ONE_REG failed (s10)");
	dprintf(debug_fd, " S10:   0x%lx\n", data);

	reg.id		= RISCV_CORE_REG(regs.s11);
	if (ioctl(vcpu->vcpu_fd, KVM_GET_ONE_REG, &reg) < 0)
		die("KVM_GET_ONE_REG failed (s11)");
	dprintf(debug_fd, " S11:   0x%lx\n", data);

	reg.id		= RISCV_CORE_REG(regs.t3);
	if (ioctl(vcpu->vcpu_fd, KVM_GET_ONE_REG, &reg) < 0)
		die("KVM_GET_ONE_REG failed (t3)");
	dprintf(debug_fd, " T3:    0x%lx\n", data);

	reg.id		= RISCV_CORE_REG(regs.t4);
	if (ioctl(vcpu->vcpu_fd, KVM_GET_ONE_REG, &reg) < 0)
		die("KVM_GET_ONE_REG failed (t4)");
	dprintf(debug_fd, " T4:    0x%lx\n", data);

	reg.id		= RISCV_CORE_REG(regs.t5);
	if (ioctl(vcpu->vcpu_fd, KVM_GET_ONE_REG, &reg) < 0)
		die("KVM_GET_ONE_REG failed (t5)");
	dprintf(debug_fd, " T5:    0x%lx\n", data);

	reg.id		= RISCV_CORE_REG(regs.t6);
	if (ioctl(vcpu->vcpu_fd, KVM_GET_ONE_REG, &reg) < 0)
		die("KVM_GET_ONE_REG failed (t6)");
	dprintf(debug_fd, " T6:    0x%lx\n", data);
}
