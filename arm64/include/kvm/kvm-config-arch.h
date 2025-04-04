#ifndef ARM_COMMON__KVM_CONFIG_ARCH_H
#define ARM_COMMON__KVM_CONFIG_ARCH_H

#include "kvm/parse-options.h"

struct kvm_config_arch {
	const char	*dump_dtb_filename;
	const char	*vcpu_affinity;
	unsigned int	force_cntfrq;
	bool		aarch32_guest;
	bool		has_pmuv3;
	bool		mte_disabled;
	u64		kaslr_seed;
	enum irqchip_type irqchip;
	u64		fw_addr;
	unsigned int	sve_max_vq;
	bool		no_pvtime;
};

int irqchip_parser(const struct option *opt, const char *arg, int unset);
int vcpu_affinity_parser(const struct option *opt, const char *arg, int unset);
int sve_vl_parser(const struct option *opt, const char *arg, int unset);

#define OPT_ARCH_RUN(pfx, cfg)							\
	pfx,									\
	OPT_BOOLEAN('\0', "aarch32", &(cfg)->aarch32_guest,			\
			"Run AArch32 guest"),					\
	OPT_BOOLEAN('\0', "pmu", &(cfg)->has_pmuv3,				\
			"Create PMUv3 device. The emulated PMU will be" 	\
			" set to the PMU associated with the"			\
			" main thread, unless --vcpu-affinity is set"),		\
	OPT_BOOLEAN('\0', "disable-mte", &(cfg)->mte_disabled,			\
			"Disable Memory Tagging Extension"),			\
	OPT_CALLBACK('\0', "vcpu-affinity", kvm, "cpulist",  			\
			"Specify the CPU affinity that will apply to "		\
			"all VCPUs", vcpu_affinity_parser, kvm),		\
	OPT_U64('\0', "kaslr-seed", &(cfg)->kaslr_seed,				\
			"Specify random seed for Kernel Address Space "		\
			"Layout Randomization (KASLR)"),			\
	OPT_BOOLEAN('\0', "no-pvtime", &(cfg)->no_pvtime, "Disable"		\
			" stolen time"),					\
	OPT_CALLBACK('\0', "sve-max-vl", NULL, "vector length",			\
		     "Specify the max SVE vector length (in bits) for "		\
		     "all vCPUs", sve_vl_parser, kvm),				\
	OPT_STRING('\0', "dump-dtb", &(cfg)->dump_dtb_filename,			\
		   ".dtb file", "Dump generated .dtb to specified file"),	\
	OPT_UINTEGER('\0', "override-bad-firmware-cntfrq", &(cfg)->force_cntfrq,\
		     "Specify Generic Timer frequency in guest DT to "		\
		     "work around buggy secure firmware *Firmware should be "	\
		     "updated to program CNTFRQ correctly*"),			\
	OPT_CALLBACK_NOOPT('\0', "force-pci", NULL, "",				\
			   "Force virtio devices to use PCI as their default "	\
			   "transport (Deprecated: Use --virtio-transport "	\
			   "option instead)", virtio_transport_parser, kvm),	\
        OPT_CALLBACK('\0', "irqchip", &(cfg)->irqchip,				\
		     "[gicv2|gicv2m|gicv3|gicv3-its]",				\
		     "Type of interrupt controller to emulate in the guest",	\
		     irqchip_parser, NULL),					\
	OPT_U64('\0', "firmware-address", &(cfg)->fw_addr,			\
		"Address where firmware should be loaded"),

#endif /* ARM_COMMON__KVM_CONFIG_ARCH_H */
