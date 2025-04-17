#ifndef ARM_COMMON__KVM_CPU_ARCH_H
#define ARM_COMMON__KVM_CPU_ARCH_H

#include "kvm/kvm.h"

#include <linux/kvm.h>
#include <pthread.h>
#include <stdbool.h>

#define ARM_MPIDR_HWID_BITMASK	0xFF00FFFFFFUL
#define ARM_CPU_ID		3, 0, 0, 0
#define ARM_CPU_ID_MPIDR	5
#define ARM_CPU_CTRL		3, 0, 1, 0
#define ARM_CPU_CTRL_SCTLR_EL1	0

struct kvm_cpu {
	pthread_t	thread;

	unsigned long	cpu_id;
	unsigned long	cpu_type;
	const char	*cpu_compatible;

	struct kvm	*kvm;
	int		vcpu_fd;
	struct kvm_run	*kvm_run;
	struct kvm_cpu_task	*task;

	u8		is_running;
	u8		paused;
	u8		needs_nmi;

	struct kvm_coalesced_mmio_ring	*ring;

	void		(*generate_fdt_nodes)(void *fdt, struct kvm* kvm);
};

struct kvm_arm_target {
	u32		id;
	const char 	*compatible;
	int		(*init)(struct kvm_cpu *vcpu);
};

void kvm_cpu__set_kvm_arm_generic_target(struct kvm_arm_target *target);

int kvm_cpu__register_kvm_arm_target(struct kvm_arm_target *target);

static inline bool kvm_cpu__emulate_io(struct kvm_cpu *vcpu, u16 port, void *data,
				       int direction, int size, u32 count)
{
	return false;
}

static inline bool kvm_cpu__emulate_mmio(struct kvm_cpu *vcpu, u64 phys_addr,
					 u8 *data, u32 len, u8 is_write)
{
	if (arm_addr_in_ioport_region(phys_addr)) {
		int direction = is_write ? KVM_EXIT_IO_OUT : KVM_EXIT_IO_IN;
		u16 port = (phys_addr - KVM_IOPORT_AREA) & USHRT_MAX;

		return kvm__emulate_io(vcpu, port, data, direction, len, 1);
	}

	return kvm__emulate_mmio(vcpu, phys_addr, data, len, is_write);
}

unsigned long kvm_cpu__get_vcpu_mpidr(struct kvm_cpu *vcpu);
int kvm_cpu__setup_pvtime(struct kvm_cpu *vcpu);
int kvm_cpu__teardown_pvtime(struct kvm *kvm);

#endif /* ARM_COMMON__KVM_CPU_ARCH_H */
