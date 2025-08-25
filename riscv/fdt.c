#include "kvm/devices.h"
#include "kvm/fdt.h"
#include "kvm/kvm.h"
#include "kvm/kvm-cpu.h"

#include <stdbool.h>

#include <linux/byteorder.h>
#include <linux/cpumask.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/sizes.h>

struct isa_ext_info {
	const char *name;
	unsigned long ext_id;
	bool single_letter;
	bool min_enabled;
};

struct isa_ext_info isa_info_arr[] = {
	/* single-letter ordered canonically as "IEMAFDQCLBJTPVNSUHKORWXYZG" */
	{"i",		KVM_RISCV_ISA_EXT_I,	.single_letter = true, .min_enabled = true},
	{"m",		KVM_RISCV_ISA_EXT_M,	.single_letter = true, .min_enabled = true},
	{"a",		KVM_RISCV_ISA_EXT_A,	.single_letter = true, .min_enabled = true},
	{"f",		KVM_RISCV_ISA_EXT_F,	.single_letter = true, .min_enabled = true},
	{"d",		KVM_RISCV_ISA_EXT_D,	.single_letter = true, .min_enabled = true},
	{"c",		KVM_RISCV_ISA_EXT_C,	.single_letter = true, .min_enabled = true},
	{"v",		KVM_RISCV_ISA_EXT_V,	.single_letter = true},
	{"h",		KVM_RISCV_ISA_EXT_H,	.single_letter = true},
	/* multi-letter sorted alphabetically */
	{"smnpm",	KVM_RISCV_ISA_EXT_SMNPM},
	{"smstateen",	KVM_RISCV_ISA_EXT_SMSTATEEN},
	{"ssaia",	KVM_RISCV_ISA_EXT_SSAIA},
	{"sscofpmf",	KVM_RISCV_ISA_EXT_SSCOFPMF},
	{"ssnpm",	KVM_RISCV_ISA_EXT_SSNPM},
	{"sstc",	KVM_RISCV_ISA_EXT_SSTC},
	{"svade",	KVM_RISCV_ISA_EXT_SVADE},
	{"svadu",	KVM_RISCV_ISA_EXT_SVADU},
	{"svinval",	KVM_RISCV_ISA_EXT_SVINVAL},
	{"svnapot",	KVM_RISCV_ISA_EXT_SVNAPOT},
	{"svpbmt",	KVM_RISCV_ISA_EXT_SVPBMT},
	{"svvptc",	KVM_RISCV_ISA_EXT_SVVPTC},
	{"zabha",	KVM_RISCV_ISA_EXT_ZABHA},
	{"zacas",	KVM_RISCV_ISA_EXT_ZACAS},
	{"zawrs",	KVM_RISCV_ISA_EXT_ZAWRS},
	{"zba",		KVM_RISCV_ISA_EXT_ZBA},
	{"zbb",		KVM_RISCV_ISA_EXT_ZBB},
	{"zbc",		KVM_RISCV_ISA_EXT_ZBC},
	{"zbkb",	KVM_RISCV_ISA_EXT_ZBKB},
	{"zbkc",	KVM_RISCV_ISA_EXT_ZBKC},
	{"zbkx",	KVM_RISCV_ISA_EXT_ZBKX},
	{"zbs",		KVM_RISCV_ISA_EXT_ZBS},
	{"zca",		KVM_RISCV_ISA_EXT_ZCA},
	{"zcb",		KVM_RISCV_ISA_EXT_ZCB},
	{"zcd",		KVM_RISCV_ISA_EXT_ZCD},
	{"zcf",		KVM_RISCV_ISA_EXT_ZCF},
	{"zcmop",	KVM_RISCV_ISA_EXT_ZCMOP},
	{"zfa",		KVM_RISCV_ISA_EXT_ZFA},
	{"zfh",		KVM_RISCV_ISA_EXT_ZFH},
	{"zfhmin",	KVM_RISCV_ISA_EXT_ZFHMIN},
	{"zicbom",	KVM_RISCV_ISA_EXT_ZICBOM},
	{"zicboz",	KVM_RISCV_ISA_EXT_ZICBOZ},
	{"ziccrse",	KVM_RISCV_ISA_EXT_ZICCRSE},
	{"zicntr",	KVM_RISCV_ISA_EXT_ZICNTR},
	{"zicond",	KVM_RISCV_ISA_EXT_ZICOND},
	{"zicsr",	KVM_RISCV_ISA_EXT_ZICSR},
	{"zifencei",	KVM_RISCV_ISA_EXT_ZIFENCEI},
	{"zihintntl",	KVM_RISCV_ISA_EXT_ZIHINTNTL},
	{"zihintpause",	KVM_RISCV_ISA_EXT_ZIHINTPAUSE},
	{"zihpm",	KVM_RISCV_ISA_EXT_ZIHPM},
	{"zimop",	KVM_RISCV_ISA_EXT_ZIMOP},
	{"zknd",	KVM_RISCV_ISA_EXT_ZKND},
	{"zkne",	KVM_RISCV_ISA_EXT_ZKNE},
	{"zknh",	KVM_RISCV_ISA_EXT_ZKNH},
	{"zkr",		KVM_RISCV_ISA_EXT_ZKR},
	{"zksed",	KVM_RISCV_ISA_EXT_ZKSED},
	{"zksh",	KVM_RISCV_ISA_EXT_ZKSH},
	{"zkt",		KVM_RISCV_ISA_EXT_ZKT},
	{"ztso",	KVM_RISCV_ISA_EXT_ZTSO},
	{"zvbb",	KVM_RISCV_ISA_EXT_ZVBB},
	{"zvbc",	KVM_RISCV_ISA_EXT_ZVBC},
	{"zvfh",	KVM_RISCV_ISA_EXT_ZVFH},
	{"zvfhmin",	KVM_RISCV_ISA_EXT_ZVFHMIN},
	{"zvkb",	KVM_RISCV_ISA_EXT_ZVKB},
	{"zvkg",	KVM_RISCV_ISA_EXT_ZVKG},
	{"zvkned",	KVM_RISCV_ISA_EXT_ZVKNED},
	{"zvknha",	KVM_RISCV_ISA_EXT_ZVKNHA},
	{"zvknhb",	KVM_RISCV_ISA_EXT_ZVKNHB},
	{"zvksed",	KVM_RISCV_ISA_EXT_ZVKSED},
	{"zvksh",	KVM_RISCV_ISA_EXT_ZVKSH},
	{"zvkt",	KVM_RISCV_ISA_EXT_ZVKT},
};

static bool __isa_ext_disabled(struct kvm *kvm, struct isa_ext_info *info)
{
	if (kvm->cfg.arch.cpu_type == RISCV__CPU_TYPE_MIN &&
	    !info->min_enabled)
		return true;

	return kvm->cfg.arch.ext_disabled[info->ext_id];
}

static bool __isa_ext_warn_disable_failure(struct kvm *kvm, struct isa_ext_info *info)
{
	if (kvm->cfg.arch.cpu_type == RISCV__CPU_TYPE_MIN &&
	    !info->min_enabled)
		return false;

	return true;
}

static void __min_enable(const char *ext, size_t ext_len)
{
	struct isa_ext_info *info;
	unsigned long i;

	for (i = 0; i < ARRAY_SIZE(isa_info_arr); i++) {
		info = &isa_info_arr[i];
		if (strlen(info->name) != ext_len)
			continue;
		if (!strncmp(ext, info->name, ext_len))
			info->min_enabled = true;
	}
}

bool riscv__isa_extension_disabled(struct kvm *kvm, unsigned long isa_ext_id)
{
	struct isa_ext_info *info = NULL;
	unsigned long i;

	for (i = 0; i < ARRAY_SIZE(isa_info_arr); i++) {
		if (isa_info_arr[i].ext_id == isa_ext_id) {
			info = &isa_info_arr[i];
			break;
		}
	}
	if (!info)
		return true;

	return __isa_ext_disabled(kvm, info);
}

int riscv__cpu_type_parser(const struct option *opt, const char *arg, int unset)
{
	struct kvm *kvm = opt->ptr;
	const char *str, *nstr;
	int len;

	if (strncmp(arg, "min", 3) && (strncmp(arg, "max", 3) || strlen(arg) != 3))
		die("Invalid CPU type %s\n", arg);

	if (!strcmp(arg, "max")) {
		kvm->cfg.arch.cpu_type = RISCV__CPU_TYPE_MAX;
	} else {
		kvm->cfg.arch.cpu_type = RISCV__CPU_TYPE_MIN;

		str = arg;
		str += 3;
		while (*str) {
			if (*str == ',') {
				str++;
				continue;
			}

			nstr = strchr(str, ',');
			if (!nstr)
				nstr = str + strlen(str);

			len = nstr - str;
			if (len) {
				__min_enable(str, len);
				str += len;
			}
		}
	}

	return 0;
}

struct riscv_vcpu_affinity {
	struct list_head head;
	unsigned long vcpu_id;
	cpumask_t *vcpu_cpumask;
	cpu_set_t *vcpu_cpuset;
};

int riscv__vcpu_affinity_parser(const struct option *opt, const char *arg, int unset)
{
	struct riscv_vcpu_affinity *entry;
	struct kvm *kvm = opt->ptr;
	unsigned long vcpu_id;
	char *cpulist;
	int cpu, ret;

	if (!kvm->arch.affinity_list) {
		kvm->arch.affinity_list = calloc(1, sizeof(*kvm->arch.affinity_list));
		if (!kvm->arch.affinity_list)
			die("No memory for affinity_list");
		INIT_LIST_HEAD(kvm->arch.affinity_list);
	}

	vcpu_id = strtoul(arg, &cpulist, 10);
	if (vcpu_id == ULONG_MAX)
		die("Failed to parse vcpu_id in parameter %s", arg);
	if (*cpulist != '@')
		die("No '@' found in parameter %s", arg);
	cpulist++;
	if (!strlen(cpulist))
		die("Empty cpuset in parameter %s", arg);

	entry = calloc(1, sizeof(*entry));
	if (!entry)
		die("No memory for affinity_entry");
	INIT_LIST_HEAD(&entry->head);
	entry->vcpu_id = vcpu_id;

	entry->vcpu_cpumask = calloc(1, cpumask_size());
	if (!entry->vcpu_cpumask) {
		free(entry);
		die("No memory for vcpu_cpumask");
	}

	ret = cpulist_parse(cpulist, entry->vcpu_cpumask);
	if (ret) {
		free(entry->vcpu_cpumask);
		free(entry);
		die("Failed to parse cpuset from parameter %s", arg);
	}

	entry->vcpu_cpuset = CPU_ALLOC(NR_CPUS);
	if (!entry->vcpu_cpuset) {
		free(entry->vcpu_cpumask);
		free(entry);
		die("No memory for vcpu_cpuset");
	}
	CPU_ZERO_S(CPU_ALLOC_SIZE(NR_CPUS), entry->vcpu_cpuset);

	for_each_cpu(cpu, entry->vcpu_cpumask)
		CPU_SET(cpu, entry->vcpu_cpuset);

	list_add_tail(&entry->head, kvm->arch.affinity_list);
	return 0;
}

const cpu_set_t *riscv__get_vcpu_affinity(struct kvm *kvm, unsigned long vcpu_id)
{
	struct riscv_vcpu_affinity *entry;

	if (!kvm->arch.affinity_list)
		return NULL;

	list_for_each_entry(entry, kvm->arch.affinity_list, head) {
		if (entry->vcpu_id == vcpu_id)
			return entry->vcpu_cpuset;
	}

	return NULL;
}

static void dump_fdt(const char *dtb_file, void *fdt)
{
	int count, fd;

	fd = open(dtb_file, O_CREAT | O_TRUNC | O_RDWR, 0666);
	if (fd < 0)
		die("Failed to write dtb to %s", dtb_file);

	count = write(fd, fdt, FDT_MAX_SIZE);
	if (count < 0)
		die_perror("Failed to dump dtb");

	pr_debug("Wrote %d bytes to dtb %s", count, dtb_file);
	close(fd);
}

#define CPU_NAME_MAX_LEN 15
static void generate_cpu_nodes(void *fdt, struct kvm *kvm)
{
	unsigned long cbom_blksz = 0, cboz_blksz = 0, satp_mode = 0;
	int i, cpu, pos, arr_sz = ARRAY_SIZE(isa_info_arr);

	_FDT(fdt_begin_node(fdt, "cpus"));
	_FDT(fdt_property_cell(fdt, "#address-cells", 0x1));
	_FDT(fdt_property_cell(fdt, "#size-cells", 0x0));
	_FDT(fdt_property_cell(fdt, "timebase-frequency",
				kvm->cpus[0]->riscv_timebase));

	for (cpu = 0; cpu < kvm->nrcpus; ++cpu) {
		char cpu_name[CPU_NAME_MAX_LEN];
#define CPU_ISA_MAX_LEN (ARRAY_SIZE(isa_info_arr) * 16)
		char cpu_isa[CPU_ISA_MAX_LEN];
		struct kvm_cpu *vcpu = kvm->cpus[cpu];
		struct kvm_one_reg reg;
		unsigned long isa_ext_out = 0;

		snprintf(cpu_name, CPU_NAME_MAX_LEN, "cpu@%x", cpu);

		snprintf(cpu_isa, CPU_ISA_MAX_LEN, "rv%ld", vcpu->riscv_xlen);
		pos = strlen(cpu_isa);

		for (i = 0; i < arr_sz; i++) {
			reg.id = RISCV_ISA_EXT_REG(isa_info_arr[i].ext_id);
			reg.addr = (unsigned long)&isa_ext_out;
			if (ioctl(vcpu->vcpu_fd, KVM_GET_ONE_REG, &reg) < 0)
				continue;
			if (!isa_ext_out)
				/* This extension is not available in hardware */
				continue;

			if (__isa_ext_disabled(kvm, &isa_info_arr[i])) {
				isa_ext_out = 0;
				if (ioctl(vcpu->vcpu_fd, KVM_SET_ONE_REG, &reg) < 0 &&
				    __isa_ext_warn_disable_failure(kvm, &isa_info_arr[i]))
					pr_warning("Failed to disable %s ISA exension\n",
						   isa_info_arr[i].name);
				continue;
			}

			if (isa_info_arr[i].ext_id == KVM_RISCV_ISA_EXT_ZICBOM && !cbom_blksz) {
				reg.id = RISCV_CONFIG_REG(zicbom_block_size);
				reg.addr = (unsigned long)&cbom_blksz;
				if (ioctl(vcpu->vcpu_fd, KVM_GET_ONE_REG, &reg) < 0)
					die("KVM_GET_ONE_REG failed (config.zicbom_block_size)");
			}

			if (isa_info_arr[i].ext_id == KVM_RISCV_ISA_EXT_ZICBOZ && !cboz_blksz) {
				reg.id = RISCV_CONFIG_REG(zicboz_block_size);
				reg.addr = (unsigned long)&cboz_blksz;
				if (ioctl(vcpu->vcpu_fd, KVM_GET_ONE_REG, &reg) < 0)
					die("KVM_GET_ONE_REG failed (config.zicboz_block_size)");
			}

			if ((strlen(isa_info_arr[i].name) + pos + 1) >= CPU_ISA_MAX_LEN) {
				pr_warning("Insufficient space to append ISA exension %s\n",
					   isa_info_arr[i].name);
				break;
			}

			pos += snprintf(cpu_isa + pos, CPU_ISA_MAX_LEN - pos, "%s%s",
					isa_info_arr[i].single_letter ? "" : "_",
					isa_info_arr[i].name);
		}
		cpu_isa[pos] = '\0';

		reg.id = RISCV_CONFIG_REG(satp_mode);
		reg.addr = (unsigned long)&satp_mode;
		if (ioctl(vcpu->vcpu_fd, KVM_GET_ONE_REG, &reg) < 0)
			satp_mode = (vcpu->riscv_xlen == 64) ? 8 : 1;

		_FDT(fdt_begin_node(fdt, cpu_name));
		_FDT(fdt_property_string(fdt, "device_type", "cpu"));
		_FDT(fdt_property_string(fdt, "compatible", "riscv"));
		if (vcpu->riscv_xlen == 64) {
			switch (satp_mode) {
			case 10:
				_FDT(fdt_property_string(fdt, "mmu-type",
							 "riscv,sv57"));
				break;
			case 9:
				_FDT(fdt_property_string(fdt, "mmu-type",
							 "riscv,sv48"));
				break;
			case 8:
				_FDT(fdt_property_string(fdt, "mmu-type",
							 "riscv,sv39"));
				break;
			default:
				_FDT(fdt_property_string(fdt, "mmu-type",
							 "riscv,none"));
				break;
			}
		} else {
			switch (satp_mode) {
			case 1:
				_FDT(fdt_property_string(fdt, "mmu-type",
							 "riscv,sv32"));
				break;
			default:
				_FDT(fdt_property_string(fdt, "mmu-type",
							 "riscv,none"));
				break;
			}
		}
		_FDT(fdt_property_string(fdt, "riscv,isa", cpu_isa));
		if (cbom_blksz)
			_FDT(fdt_property_cell(fdt, "riscv,cbom-block-size", cbom_blksz));
		if (cboz_blksz)
			_FDT(fdt_property_cell(fdt, "riscv,cboz-block-size", cboz_blksz));
		_FDT(fdt_property_cell(fdt, "reg", cpu));
		_FDT(fdt_property_string(fdt, "status", "okay"));

		_FDT(fdt_begin_node(fdt, "interrupt-controller"));
		_FDT(fdt_property_string(fdt, "compatible", "riscv,cpu-intc"));
		_FDT(fdt_property_cell(fdt, "#interrupt-cells", 1));
		_FDT(fdt_property(fdt, "interrupt-controller", NULL, 0));
		_FDT(fdt_property_cell(fdt, "phandle",
					PHANDLE_CPU_INTC_BASE + cpu));
		_FDT(fdt_end_node(fdt));

		_FDT(fdt_end_node(fdt));
	}

	_FDT(fdt_end_node(fdt));
}

static int setup_fdt(struct kvm *kvm)
{
	struct device_header *dev_hdr;
	u8 staging_fdt[FDT_MAX_SIZE];
	u64 mem_reg_prop[]	= {
		cpu_to_fdt64(kvm->arch.memory_guest_start),
		cpu_to_fdt64(kvm->ram_size),
	};
	char *str;
	void *fdt		= staging_fdt;
	void *fdt_dest		= guest_flat_to_host(kvm,
						     kvm->arch.dtb_guest_start);
	void (*generate_mmio_fdt_nodes)(void *, struct device_header *,
					void (*)(void *, u8, enum irq_type));

	/* Create new tree without a reserve map */
	_FDT(fdt_create(fdt, FDT_MAX_SIZE));
	_FDT(fdt_finish_reservemap(fdt));

	/* Header */
	_FDT(fdt_begin_node(fdt, ""));
	_FDT(fdt_property_string(fdt, "compatible", "linux,dummy-virt"));
	_FDT(fdt_property_cell(fdt, "#address-cells", 0x2));
	_FDT(fdt_property_cell(fdt, "#size-cells", 0x2));

	/* /chosen */
	_FDT(fdt_begin_node(fdt, "chosen"));

	/* Pass on our amended command line to a Linux kernel only. */
	if (kvm->cfg.firmware_filename) {
		if (kvm->cfg.kernel_cmdline)
			_FDT(fdt_property_string(fdt, "bootargs",
						 kvm->cfg.kernel_cmdline));
	} else if (kvm->cfg.real_cmdline) {
		_FDT(fdt_property_string(fdt, "bootargs",
					 kvm->cfg.real_cmdline));
	}

	_FDT(fdt_property_string(fdt, "stdout-path", "serial0"));

	/* Initrd */
	if (kvm->arch.initrd_size != 0) {
		u64 ird_st_prop = cpu_to_fdt64(kvm->arch.initrd_guest_start);
		u64 ird_end_prop = cpu_to_fdt64(kvm->arch.initrd_guest_start +
					       kvm->arch.initrd_size);

		_FDT(fdt_property(fdt, "linux,initrd-start",
				   &ird_st_prop, sizeof(ird_st_prop)));
		_FDT(fdt_property(fdt, "linux,initrd-end",
				   &ird_end_prop, sizeof(ird_end_prop)));
	}

	_FDT(fdt_end_node(fdt));

	/* Memory */
	_FDT(fdt_begin_node(fdt, "memory"));
	_FDT(fdt_property_string(fdt, "device_type", "memory"));
	_FDT(fdt_property(fdt, "reg", mem_reg_prop, sizeof(mem_reg_prop)));
	_FDT(fdt_end_node(fdt));

	/* CPUs */
	generate_cpu_nodes(fdt, kvm);

	/* IRQCHIP */
	if (!riscv_irqchip_generate_fdt_node)
		die("No way to generate IRQCHIP FDT node\n");
	riscv_irqchip_generate_fdt_node(fdt, kvm);

	/* Simple Bus */
	_FDT(fdt_begin_node(fdt, "smb"));
	_FDT(fdt_property_string(fdt, "compatible", "simple-bus"));
	_FDT(fdt_property_cell(fdt, "#address-cells", 0x2));
	_FDT(fdt_property_cell(fdt, "#size-cells", 0x2));
	_FDT(fdt_property_cell(fdt, "interrupt-parent",
			       riscv_irqchip_phandle));
	_FDT(fdt_property(fdt, "ranges", NULL, 0));

	/* Virtio MMIO devices */
	dev_hdr = device__first_dev(DEVICE_BUS_MMIO);
	while (dev_hdr) {
		generate_mmio_fdt_nodes = dev_hdr->data;
		generate_mmio_fdt_nodes(fdt, dev_hdr,
					riscv__generate_irq_prop);
		dev_hdr = device__next_dev(dev_hdr);
	}

	/* IOPORT devices */
	dev_hdr = device__first_dev(DEVICE_BUS_IOPORT);
	while (dev_hdr) {
		generate_mmio_fdt_nodes = dev_hdr->data;
		generate_mmio_fdt_nodes(fdt, dev_hdr,
					riscv__generate_irq_prop);
		dev_hdr = device__next_dev(dev_hdr);
	}

	/* PCI host controller */
	pci__generate_fdt_nodes(fdt);

	_FDT(fdt_end_node(fdt));

	if (fdt_stdout_path) {
		str = malloc(strlen(fdt_stdout_path) + strlen("/smb") + 1);
		sprintf(str, "/smb%s", fdt_stdout_path);
		free(fdt_stdout_path);
		fdt_stdout_path = NULL;

		_FDT(fdt_begin_node(fdt, "aliases"));
		_FDT(fdt_property_string(fdt, "serial0", str));
		_FDT(fdt_end_node(fdt));
		free(str);
	}

	/* Finalise. */
	_FDT(fdt_end_node(fdt));
	_FDT(fdt_finish(fdt));

	_FDT(fdt_open_into(fdt, fdt_dest, FDT_MAX_SIZE));
	_FDT(fdt_pack(fdt_dest));

	if (kvm->cfg.arch.dump_dtb_filename)
		dump_fdt(kvm->cfg.arch.dump_dtb_filename, fdt_dest);
	return 0;
}
late_init(setup_fdt);
