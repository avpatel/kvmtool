#include "kvm/devices.h"
#include "kvm/fdt.h"
#include "kvm/kvm.h"
#include "kvm/kvm-cpu.h"

#include <stdbool.h>

#include <linux/byteorder.h>
#include <linux/kernel.h>
#include <linux/sizes.h>

struct isa_ext_info {
	const char *name;
	unsigned long ext_id;
	bool multi_letter;
	bool min_cpu_included;
};

struct isa_ext_info isa_info_arr[] = {
	/* single-letter ordered canonically as "IEMAFDQCLBJTPVNSUHKORWXYZG" */
	{"i",		KVM_RISCV_ISA_EXT_I,		false, true},
	{"m",		KVM_RISCV_ISA_EXT_M,		false, true},
	{"a",		KVM_RISCV_ISA_EXT_A,		false, true},
	{"f",		KVM_RISCV_ISA_EXT_F,		false, true},
	{"d",		KVM_RISCV_ISA_EXT_D,		false, true},
	{"c",		KVM_RISCV_ISA_EXT_C,		false, true},
	{"v",		KVM_RISCV_ISA_EXT_V,		false, false},
	{"h",		KVM_RISCV_ISA_EXT_H,		false, false},
	/* multi-letter sorted alphabetically */
	{"smnpm",	KVM_RISCV_ISA_EXT_SMNPM,	true, false},
	{"smstateen",	KVM_RISCV_ISA_EXT_SMSTATEEN,	true, false},
	{"ssaia",	KVM_RISCV_ISA_EXT_SSAIA,	true, false},
	{"sscofpmf",	KVM_RISCV_ISA_EXT_SSCOFPMF,	true, false},
	{"ssnpm",	KVM_RISCV_ISA_EXT_SSNPM,	true, false},
	{"sstc",	KVM_RISCV_ISA_EXT_SSTC,		true, false},
	{"svade",	KVM_RISCV_ISA_EXT_SVADE,	true, false},
	{"svadu",	KVM_RISCV_ISA_EXT_SVADU,	true, false},
	{"svinval",	KVM_RISCV_ISA_EXT_SVINVAL,	true, false},
	{"svnapot",	KVM_RISCV_ISA_EXT_SVNAPOT,	true, false},
	{"svpbmt",	KVM_RISCV_ISA_EXT_SVPBMT,	true, false},
	{"svvptc",	KVM_RISCV_ISA_EXT_SVVPTC,	true, false},
	{"zabha",	KVM_RISCV_ISA_EXT_ZABHA,	true, false},
	{"zacas",	KVM_RISCV_ISA_EXT_ZACAS,	true, false},
	{"zawrs",	KVM_RISCV_ISA_EXT_ZAWRS,	true, false},
	{"zba",		KVM_RISCV_ISA_EXT_ZBA,		true, false},
	{"zbb",		KVM_RISCV_ISA_EXT_ZBB,		true, false},
	{"zbc",		KVM_RISCV_ISA_EXT_ZBC,		true, false},
	{"zbkb",	KVM_RISCV_ISA_EXT_ZBKB,		true, false},
	{"zbkc",	KVM_RISCV_ISA_EXT_ZBKC,		true, false},
	{"zbkx",	KVM_RISCV_ISA_EXT_ZBKX,		true, false},
	{"zbs",		KVM_RISCV_ISA_EXT_ZBS,		true, false},
	{"zca",		KVM_RISCV_ISA_EXT_ZCA,		true, false},
	{"zcb",		KVM_RISCV_ISA_EXT_ZCB,		true, false},
	{"zcd",		KVM_RISCV_ISA_EXT_ZCD,		true, false},
	{"zcf",		KVM_RISCV_ISA_EXT_ZCF,		true, false},
	{"zcmop",	KVM_RISCV_ISA_EXT_ZCMOP,	true, false},
	{"zfa",		KVM_RISCV_ISA_EXT_ZFA,		true, false},
	{"zfh",		KVM_RISCV_ISA_EXT_ZFH,		true, false},
	{"zfhmin",	KVM_RISCV_ISA_EXT_ZFHMIN,	true, false},
	{"zicbom",	KVM_RISCV_ISA_EXT_ZICBOM,	true, false},
	{"zicboz",	KVM_RISCV_ISA_EXT_ZICBOZ,	true, false},
	{"ziccrse",	KVM_RISCV_ISA_EXT_ZICCRSE,	true, false},
	{"zicntr",	KVM_RISCV_ISA_EXT_ZICNTR,	true, false},
	{"zicond",	KVM_RISCV_ISA_EXT_ZICOND,	true, false},
	{"zicsr",	KVM_RISCV_ISA_EXT_ZICSR,	true, false},
	{"zifencei",	KVM_RISCV_ISA_EXT_ZIFENCEI,	true, false},
	{"zihintntl",	KVM_RISCV_ISA_EXT_ZIHINTNTL,	true, false},
	{"zihintpause",	KVM_RISCV_ISA_EXT_ZIHINTPAUSE,	true, false},
	{"zihpm",	KVM_RISCV_ISA_EXT_ZIHPM,	true, false},
	{"zimop",	KVM_RISCV_ISA_EXT_ZIMOP,	true, false},
	{"zknd",	KVM_RISCV_ISA_EXT_ZKND,		true, false},
	{"zkne",	KVM_RISCV_ISA_EXT_ZKNE,		true, false},
	{"zknh",	KVM_RISCV_ISA_EXT_ZKNH,		true, false},
	{"zkr",		KVM_RISCV_ISA_EXT_ZKR,		true, false},
	{"zksed",	KVM_RISCV_ISA_EXT_ZKSED,	true, false},
	{"zksh",	KVM_RISCV_ISA_EXT_ZKSH,		true, false},
	{"zkt",		KVM_RISCV_ISA_EXT_ZKT,		true, false},
	{"ztso",	KVM_RISCV_ISA_EXT_ZTSO,		true, false},
	{"zvbb",	KVM_RISCV_ISA_EXT_ZVBB,		true, false},
	{"zvbc",	KVM_RISCV_ISA_EXT_ZVBC,		true, false},
	{"zvfh",	KVM_RISCV_ISA_EXT_ZVFH,		true, false},
	{"zvfhmin",	KVM_RISCV_ISA_EXT_ZVFHMIN,	true, false},
	{"zvkb",	KVM_RISCV_ISA_EXT_ZVKB,		true, false},
	{"zvkg",	KVM_RISCV_ISA_EXT_ZVKG,		true, false},
	{"zvkned",	KVM_RISCV_ISA_EXT_ZVKNED,	true, false},
	{"zvknha",	KVM_RISCV_ISA_EXT_ZVKNHA,	true, false},
	{"zvknhb",	KVM_RISCV_ISA_EXT_ZVKNHB,	true, false},
	{"zvksed",	KVM_RISCV_ISA_EXT_ZVKSED,	true, false},
	{"zvksh",	KVM_RISCV_ISA_EXT_ZVKSH,	true, false},
	{"zvkt",	KVM_RISCV_ISA_EXT_ZVKT,		true, false},
};

static bool __isa_ext_disabled(struct kvm *kvm, struct isa_ext_info *info)
{
	if (!strncmp(kvm->cfg.arch.cpu_type, "min", 3) &&
	    !info->min_cpu_included)
		return true;

	return kvm->cfg.arch.ext_disabled[info->ext_id];
}

static bool __isa_ext_warn_disable_failure(struct kvm *kvm, struct isa_ext_info *info)
{
	if (!strncmp(kvm->cfg.arch.cpu_type, "min", 3) &&
	    !info->min_cpu_included)
		return false;

	return true;
}

static void __min_cpu_include(const char *ext, size_t ext_len)
{
	struct isa_ext_info *info;
	unsigned long i;

	for (i = 0; i < ARRAY_SIZE(isa_info_arr); i++) {
		info = &isa_info_arr[i];
		if (strlen(info->name) != ext_len)
			continue;
		if (!strncmp(ext, info->name, ext_len))
			info->min_cpu_included = true;
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

	if ((strncmp(arg, "min", 3) || strlen(arg) < 3) &&
	    (strncmp(arg, "max", 3) || strlen(arg) != 3))
		die("Invalid CPU type %s\n", arg);

	if (!strncmp(arg, "max", 3))
		kvm->cfg.arch.cpu_type = "max";

	if (!strncmp(arg, "min", 3)) {
		kvm->cfg.arch.cpu_type = "min";

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
				__min_cpu_include(str, len);
				str += len;
			}
		}
	}

	return 0;
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
				if ((ioctl(vcpu->vcpu_fd, KVM_SET_ONE_REG, &reg) < 0) &&
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

			if (isa_info_arr[i].multi_letter)
				pos += snprintf(cpu_isa + pos, CPU_ISA_MAX_LEN - pos, "_%s",
						isa_info_arr[i].name);
			else
				pos += snprintf(cpu_isa + pos, CPU_ISA_MAX_LEN - pos, "%s",
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
