#include "asm/smccc.h"
#include "kvm/kvm.h"
#include "kvm/kvm-cpu.h"
#include "kvm/util.h"

#include <linux/psci.h>
#include <linux/types.h>

static void psci_features(struct kvm_cpu *vcpu, struct arm_smccc_res *res)
{
	u32 arg = smccc_get_arg(vcpu, 1);

	res->a0 = PSCI_RET_NOT_SUPPORTED;
	if (!smccc_calling_conv_allowed(vcpu, arg))
		return;

	switch (arg) {
	case PSCI_0_2_FN_CPU_SUSPEND:
	case PSCI_0_2_FN64_CPU_SUSPEND:
	case PSCI_0_2_FN_CPU_OFF:
	case ARM_SMCCC_VERSION_FUNC_ID:
		res->a0 = PSCI_RET_SUCCESS;
		break;
	}
}

static void cpu_suspend(struct kvm_cpu *vcpu, struct arm_smccc_res *res)
{
	struct kvm_mp_state mp_state = {
		.mp_state	= KVM_MP_STATE_SUSPENDED,
	};

	/* Rely on in-kernel emulation of a 'suspended' (i.e. WFI) state. */
	if (ioctl(vcpu->vcpu_fd, KVM_SET_MP_STATE, &mp_state))
		die_perror("KVM_SET_MP_STATE failed");

	res->a0 = PSCI_RET_SUCCESS;
}

static void cpu_off(struct kvm_cpu *vcpu, struct arm_smccc_res *res)
{
	struct kvm_mp_state mp_state = {
		.mp_state	= KVM_MP_STATE_STOPPED,
	};

	if (ioctl(vcpu->vcpu_fd, KVM_SET_MP_STATE, &mp_state))
		die_perror("KVM_SET_MP_STATE failed");
}

void handle_psci(struct kvm_cpu *vcpu, struct arm_smccc_res *res)
{
	switch (vcpu->kvm_run->hypercall.nr) {
	case PSCI_0_2_FN_PSCI_VERSION:
		res->a0 = PSCI_VERSION(1, 0);
		break;
	case PSCI_1_0_FN_PSCI_FEATURES:
		psci_features(vcpu, res);
		break;
	case PSCI_0_2_FN_CPU_SUSPEND:
	case PSCI_0_2_FN64_CPU_SUSPEND:
		cpu_suspend(vcpu, res);
		break;
	case PSCI_0_2_FN_CPU_OFF:
		cpu_off(vcpu, res);
		break;
	default:
		res->a0 = PSCI_RET_NOT_SUPPORTED;
	}
}
