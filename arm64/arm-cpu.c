#include "kvm/fdt.h"
#include "kvm/kvm.h"
#include "kvm/kvm-cpu.h"
#include "kvm/util.h"

#include "arm-common/gic.h"
#include "arm-common/timer.h"

#include "asm/pmu.h"

#include <linux/byteorder.h>
#include <linux/types.h>

static void generate_fdt_nodes(void *fdt, struct kvm *kvm)
{
	int timer_interrupts[4] = {13, 14, 11, 10};

	gic__generate_fdt_nodes(fdt, kvm->cfg.arch.irqchip);
	timer__generate_fdt_nodes(fdt, kvm, timer_interrupts);
	pmu__generate_fdt_nodes(fdt, kvm);
}

static int arm_cpu__vcpu_init(struct kvm_cpu *vcpu)
{
	vcpu->generate_fdt_nodes = generate_fdt_nodes;
	return kvm_cpu__setup_pvtime(vcpu);
}

static struct kvm_arm_target target_generic_v8 = {
	.id		= UINT_MAX,
	.compatible	= "arm,arm-v8",
	.init		= arm_cpu__vcpu_init,
};

static struct kvm_arm_target target_aem_v8 = {
	.id		= KVM_ARM_TARGET_AEM_V8,
	.compatible	= "arm,arm-v8",
	.init		= arm_cpu__vcpu_init,
};

static struct kvm_arm_target target_foundation_v8 = {
	.id		= KVM_ARM_TARGET_FOUNDATION_V8,
	.compatible	= "arm,arm-v8",
	.init		= arm_cpu__vcpu_init,
};

static struct kvm_arm_target target_cortex_a57 = {
	.id		= KVM_ARM_TARGET_CORTEX_A57,
	.compatible	= "arm,cortex-a57",
	.init		= arm_cpu__vcpu_init,
};

/*
 * We really don't need to register a target for every
 * new CPU. The target for Potenza CPU is only registered
 * to enable compatibility with older host kernels.
 */
static struct kvm_arm_target target_potenza = {
	.id		= KVM_ARM_TARGET_XGENE_POTENZA,
	.compatible	= "arm,arm-v8",
	.init		= arm_cpu__vcpu_init,
};

static int arm_cpu__core_init(struct kvm *kvm)
{
	kvm_cpu__set_kvm_arm_generic_target(&target_generic_v8);

	return (kvm_cpu__register_kvm_arm_target(&target_aem_v8) ||
		kvm_cpu__register_kvm_arm_target(&target_foundation_v8) ||
		kvm_cpu__register_kvm_arm_target(&target_cortex_a57) ||
		kvm_cpu__register_kvm_arm_target(&target_potenza));
}
core_init(arm_cpu__core_init);
