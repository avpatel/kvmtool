#ifndef __ARM_SMCCC_H__
#define __ARM_SMCCC_H__

#include "kvm/kvm-cpu.h"

#include <linux/arm-smccc.h>
#include <linux/types.h>

static inline bool smccc_is_64bit(struct kvm_cpu *vcpu)
{
	return ARM_SMCCC_IS_64(vcpu->kvm_run->hypercall.nr);
}

static inline bool smccc_calling_conv_allowed(struct kvm_cpu *vcpu, u32 fn)
{
	return !(vcpu->kvm->cfg.arch.aarch32_guest && ARM_SMCCC_IS_64(fn));
}

static inline u64 smccc_get_arg(struct kvm_cpu *vcpu, u8 arg)
{
	u64 val;
	struct kvm_one_reg reg = {
		.id	= ARM64_CORE_REG(regs.regs[arg]),
		.addr	= (u64)&val,
	};

	if (ioctl(vcpu->vcpu_fd, KVM_GET_ONE_REG, &reg))
		die_perror("KVM_GET_ONE_REG failed");

	if (!smccc_is_64bit(vcpu))
		val = (u32)val;

	return val;
}

static inline void smccc_return_result(struct kvm_cpu *vcpu, struct arm_smccc_res *res)
{
	unsigned long *vals = (unsigned long *)res;
	unsigned long i;

	/*
	 * The author was lazy and chose to abuse the layout of struct
	 * arm_smccc_res to write a loop set the retvals.
	 */
	for (i = 0; i < sizeof(*res) / sizeof(unsigned long); i++) {
		u64 val = vals[i];
		struct kvm_one_reg reg = {
			.id	= ARM64_CORE_REG(regs.regs[i]),
			.addr	= (u64)&val,
		};

		if (!smccc_is_64bit(vcpu))
			val = (u32)val;

		if (ioctl(vcpu->vcpu_fd, KVM_SET_ONE_REG, &reg))
			die_perror("KVM_SET_ONE_REG failed");
	}
}

bool handle_hypercall(struct kvm_cpu *vcpu);
void handle_psci(struct kvm_cpu *vcpu, struct arm_smccc_res *res);

void kvm__setup_smccc(struct kvm *kvm);

#endif /* __ARM_SMCCC_H__ */
