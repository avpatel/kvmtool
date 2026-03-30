#include "asm/smccc.h"
#include "kvm/kvm.h"
#include "kvm/kvm-cpu.h"
#include "kvm/util.h"

#include <linux/psci.h>
#include <linux/types.h>

#define AFFINITY_MASK(level)	~((0x1UL << ((level) * ARM_MPIDR_LEVEL_BITS)) - 1)

static unsigned long psci_affinity_mask(unsigned long affinity_level)
{
	if (affinity_level <= 3)
		return ARM_MPIDR_HWID_BITMASK & AFFINITY_MASK(affinity_level);

	return 0;
}

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
	case PSCI_0_2_FN_CPU_ON:
	case PSCI_0_2_FN64_CPU_ON:
	case PSCI_0_2_FN_AFFINITY_INFO:
	case PSCI_0_2_FN64_AFFINITY_INFO:
	case PSCI_0_2_FN_MIGRATE_INFO_TYPE:
	case PSCI_0_2_FN_SYSTEM_OFF:
	case PSCI_0_2_FN_SYSTEM_RESET:
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

static void reset_cpu_with_context(struct kvm_cpu *vcpu, u64 entry_addr, u64 ctx_id)
{
	struct kvm_one_reg reg;

	if (ioctl(vcpu->vcpu_fd, KVM_ARM_VCPU_INIT, &vcpu->init))
		die_perror("KVM_ARM_VCPU_INIT failed");

	reg = (struct kvm_one_reg) {
		.id	= ARM64_CORE_REG(regs.pc),
		.addr	= (u64)&entry_addr,
	};
	if (ioctl(vcpu->vcpu_fd, KVM_SET_ONE_REG, &reg))
		die_perror("KVM_SET_ONE_REG failed");

	reg = (struct kvm_one_reg) {
		.id	= ARM64_CORE_REG(regs.regs[0]),
		.addr	= (u64)&ctx_id,
	};
	if (ioctl(vcpu->vcpu_fd, KVM_SET_ONE_REG, &reg))
		die_perror("KVM_SET_ONE_REG failed");
}

static bool psci_valid_affinity(u64 affinity)
{
	return !(affinity & ~ARM_MPIDR_HWID_BITMASK);
}

static void cpu_on(struct kvm_cpu *vcpu, struct arm_smccc_res *res)
{
	u64 target_mpidr = smccc_get_arg(vcpu, 1);
	u64 entry_addr = smccc_get_arg(vcpu, 2);
	u64 ctx_id = smccc_get_arg(vcpu, 3);
	struct kvm_mp_state mp_state;
	struct kvm_cpu *target;

	if (!psci_valid_affinity(target_mpidr)) {
		res->a0 = PSCI_RET_INVALID_PARAMS;
		return;
	}

	kvm__pause(vcpu->kvm);

	target = kvm__arch_mpidr_to_vcpu(vcpu->kvm, target_mpidr);
	if (!target) {
		res->a0 = PSCI_RET_INVALID_PARAMS;
		goto out_continue;
	}

	if (ioctl(target->vcpu_fd, KVM_GET_MP_STATE, &mp_state))
		die_perror("KVM_GET_MP_STATE failed");

	if (mp_state.mp_state != KVM_MP_STATE_STOPPED) {
		res->a0 = PSCI_RET_ALREADY_ON;
		goto out_continue;
	}

	reset_cpu_with_context(target, entry_addr, ctx_id);
	res->a0 = PSCI_RET_SUCCESS;
out_continue:
	kvm__continue(vcpu->kvm);
}

static void affinity_info(struct kvm_cpu *vcpu, struct arm_smccc_res *res)
{
	u64 target_affinity = smccc_get_arg(vcpu, 1);
	u64 lowest_level = smccc_get_arg(vcpu, 2);
	u64 mpidr_mask = psci_affinity_mask(lowest_level);
	struct kvm *kvm = vcpu->kvm;
	bool matched = false;
	int i;

	if (!psci_valid_affinity(target_affinity) || lowest_level > 3) {
		res->a0 = PSCI_RET_INVALID_PARAMS;
		return;
	}

	kvm__pause(vcpu->kvm);

	for (i = 0; i < kvm->nrcpus; i++) {
		struct kvm_cpu *tmp = kvm->cpus[i];
		u64 mpidr = kvm_cpu__get_vcpu_mpidr(tmp);
		struct kvm_mp_state mp_state;

		if ((mpidr & mpidr_mask) != target_affinity)
			continue;

		if (ioctl(tmp->vcpu_fd, KVM_GET_MP_STATE, &mp_state))
			die_perror("KVM_GET_MP_STATE failed");

		if (mp_state.mp_state != KVM_MP_STATE_STOPPED) {
			res->a0 = PSCI_0_2_AFFINITY_LEVEL_ON;
			goto out_continue;
		}

		matched = true;
	}

	if (matched)
		res->a0 = PSCI_0_2_AFFINITY_LEVEL_OFF;
	else
		res->a0 = PSCI_RET_INVALID_PARAMS;
out_continue:
	kvm__continue(vcpu->kvm);
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
	case PSCI_0_2_FN_CPU_ON:
	case PSCI_0_2_FN64_CPU_ON:
		cpu_on(vcpu, res);
		break;
	case PSCI_0_2_FN_AFFINITY_INFO:
	case PSCI_0_2_FN64_AFFINITY_INFO:
		affinity_info(vcpu, res);
		break;
	case PSCI_0_2_FN_MIGRATE_INFO_TYPE:
		/* Trusted OS not present */
		res->a0 = PSCI_0_2_TOS_MP;
		break;
	case PSCI_0_2_FN_SYSTEM_OFF:
	case PSCI_0_2_FN_SYSTEM_RESET:
		kvm__reboot(vcpu->kvm);
		break;
	default:
		res->a0 = PSCI_RET_NOT_SUPPORTED;
	}
}
