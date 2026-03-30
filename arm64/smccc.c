#include "asm/smccc.h"
#include "kvm/kvm.h"
#include "kvm/kvm-cpu.h"
#include "kvm/util.h"

#include <linux/types.h>

static void handle_std_call(struct kvm_cpu *vcpu, struct arm_smccc_res *res)
{
	u32 fn = vcpu->kvm_run->hypercall.nr;

	switch (ARM_SMCCC_FUNC_NUM(fn)) {
	/* PSCI */
	case 0x00 ... 0x1F:
		handle_psci(vcpu, res);
		break;
	}
}

bool handle_hypercall(struct kvm_cpu *vcpu)
{
	u32 fn = vcpu->kvm_run->hypercall.nr;
	struct arm_smccc_res res = {
		.a0	= SMCCC_RET_NOT_SUPPORTED,
	};

	if (!smccc_calling_conv_allowed(vcpu, fn))
		goto out;

	switch (ARM_SMCCC_OWNER_NUM(fn)) {
	case ARM_SMCCC_OWNER_STANDARD:
		handle_std_call(vcpu, &res);
		break;
	}

out:
	smccc_return_result(vcpu, &res);
	return true;
}

static struct kvm_smccc_filter filter_ranges[] = {
	{
		.base		= KVM_PSCI_FN_BASE,
		.nr_functions	= 4,
		.action		= KVM_SMCCC_FILTER_DENY,
	},
	{
		.base		= PSCI_0_2_FN_BASE,
		.nr_functions	= 0x20,
		.action		= KVM_SMCCC_FILTER_FWD_TO_USER,
	},
	{
		.base		= PSCI_0_2_FN64_BASE,
		.nr_functions	= 0x20,
		.action		= KVM_SMCCC_FILTER_FWD_TO_USER,
	},
};

void kvm__setup_smccc(struct kvm *kvm)
{
	struct kvm_device_attr attr = {
		.group	= KVM_ARM_VM_SMCCC_CTRL,
		.attr	= KVM_ARM_VM_SMCCC_FILTER,
	};
	unsigned int i;

	if (!kvm->cfg.arch.psci)
		return;

	if (ioctl(kvm->vm_fd, KVM_HAS_DEVICE_ATTR, &attr)) {
		pr_debug("KVM SMCCC filter not supported");
		return;
	}

	for (i = 0; i < ARRAY_SIZE(filter_ranges); i++) {
		attr.addr = (u64)&filter_ranges[i];

		if (ioctl(kvm->vm_fd, KVM_SET_DEVICE_ATTR, &attr))
			die_perror("KVM_SET_DEVICE_ATTR failed");
	}
}
