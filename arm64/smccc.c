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

void kvm__setup_smccc(struct kvm *kvm)
{

}
