#include "kvm/kvm.h"
#include "kvm/term.h"
#include "kvm/util.h"
#include "kvm/8250-serial.h"
#include "kvm/virtio-console.h"
#include "kvm/fdt.h"
#include "kvm/gic.h"

#include <linux/byteorder.h>
#include <linux/cpumask.h>
#include <linux/kernel.h>
#include <linux/kvm.h>
#include <linux/sizes.h>

#include <asm/image.h>

static struct arm64_image_header *kernel_header;

struct kvm_ext kvm_req_ext[] = {
	{ DEFINE_KVM_EXT(KVM_CAP_IRQCHIP) },
	{ DEFINE_KVM_EXT(KVM_CAP_ONE_REG) },
	{ DEFINE_KVM_EXT(KVM_CAP_ARM_PSCI) },
	{ 0, 0 },
};

bool kvm__arch_cpu_supports_vm(void)
{
	/* The KVM capability check is enough. */
	return true;
}

void kvm__init_ram(struct kvm *kvm)
{
	u64 phys_start, phys_size;
	void *host_mem;
	int err;

	/*
	 * Allocate guest memory. We must align our buffer to 64K to
	 * correlate with the maximum guest page size for virtio-mmio.
	 * If using THP, then our minimal alignment becomes 2M.
	 * 2M trumps 64K, so let's go with that.
	 */
	kvm->ram_size = kvm->cfg.ram_size;
	kvm->arch.ram_alloc_size = kvm->ram_size;
	if (!kvm->cfg.hugetlbfs_path)
		kvm->arch.ram_alloc_size += SZ_2M;
	kvm->arch.ram_alloc_start = mmap_anon_or_hugetlbfs(kvm,
						kvm->cfg.hugetlbfs_path,
						kvm->arch.ram_alloc_size);

	if (kvm->arch.ram_alloc_start == MAP_FAILED)
		die("Failed to map %lld bytes for guest memory (%d)",
		    kvm->arch.ram_alloc_size, errno);

	kvm->ram_start = (void *)ALIGN((unsigned long)kvm->arch.ram_alloc_start,
					SZ_2M);

	madvise(kvm->arch.ram_alloc_start, kvm->arch.ram_alloc_size,
		MADV_MERGEABLE);

	madvise(kvm->arch.ram_alloc_start, kvm->arch.ram_alloc_size,
		MADV_HUGEPAGE);

	phys_start	= kvm->cfg.ram_addr;
	phys_size	= kvm->ram_size;
	host_mem	= kvm->ram_start;

	err = kvm__register_ram(kvm, phys_start, phys_size, host_mem);
	if (err)
		die("Failed to register %lld bytes of memory at physical "
		    "address 0x%llx [err %d]", phys_size, phys_start, err);

	kvm->arch.memory_guest_start = phys_start;

	pr_debug("RAM created at 0x%llx - 0x%llx",
		 phys_start, phys_start + phys_size - 1);
}

void kvm__arch_delete_ram(struct kvm *kvm)
{
	munmap(kvm->arch.ram_alloc_start, kvm->arch.ram_alloc_size);
}

void kvm__arch_read_term(struct kvm *kvm)
{
	serial8250__update_consoles(kvm);
	virtio_console__inject_interrupt(kvm);
}

void kvm__arch_set_cmdline(char *cmdline, bool video)
{
}

static void kvm__arch_enable_mte(struct kvm *kvm)
{
	struct kvm_enable_cap cap = {
		.cap = KVM_CAP_ARM_MTE,
	};

	if (kvm->cfg.arch.aarch32_guest) {
		pr_debug("MTE is incompatible with AArch32");
		return;
	}

	if (kvm->cfg.arch.mte_disabled) {
		pr_debug("MTE disabled by user");
		return;
	}

	if (!kvm__supports_extension(kvm, KVM_CAP_ARM_MTE)) {
		pr_debug("MTE capability not available");
		return;
	}

	if (ioctl(kvm->vm_fd, KVM_ENABLE_CAP, &cap))
		die_perror("KVM_ENABLE_CAP(KVM_CAP_ARM_MTE)");

	pr_debug("MTE capability enabled");
}

void kvm__arch_init(struct kvm *kvm)
{
	/* Create the virtual GIC. */
	if (gic__create(kvm, kvm->cfg.arch.irqchip))
		die("Failed to create virtual GIC");

	kvm__arch_enable_mte(kvm);
}

static u64 kvm__arch_get_payload_region_size(struct kvm *kvm)
{
	if (kvm->cfg.arch.aarch32_guest)
		return SZ_256M;

	return SZ_512M;
}

/*
 * Return the TEXT_OFFSET value that the guest kernel expects. Note
 * that pre-3.17 kernels expose this value using the native endianness
 * instead of Little-Endian. BE kernels of this vintage may fail to
 * boot. See Documentation/arm64/booting.rst in your local kernel tree.
 */
static u64 kvm__arch_get_kern_offset(struct kvm *kvm)
{
	const char *debug_str;

	/* the 32bit kernel offset is a well known value */
	if (kvm->cfg.arch.aarch32_guest)
		return 0x8000;

	if (!kernel_header) {
		debug_str = "Kernel header is missing";
		goto default_offset;
	}

	if (!le64_to_cpu(kernel_header->image_size)) {
		debug_str = "Image size is 0";
		goto default_offset;
	}

	return le64_to_cpu(kernel_header->text_offset);

default_offset:
	pr_debug("%s, assuming TEXT_OFFSET to be 0x80000", debug_str);
	return 0x80000;
}

static void kvm__arch_read_kernel_header(struct kvm *kvm, int fd)
{
	const char *debug_str;
	off_t cur_offset;
	ssize_t size;

	if (kvm->cfg.arch.aarch32_guest)
		return;

	kernel_header = malloc(sizeof(*kernel_header));
	if (!kernel_header)
		return;

	cur_offset = lseek(fd, 0, SEEK_CUR);
	if (cur_offset == (off_t)-1 || lseek(fd, 0, SEEK_SET) == (off_t)-1) {
		debug_str = "Failed to seek in kernel image file";
		goto fail;
	}

	size = xread(fd, kernel_header, sizeof(*kernel_header));
	if (size < 0 || (size_t)size < sizeof(*kernel_header))
		die("Failed to read kernel image header");

	lseek(fd, cur_offset, SEEK_SET);

	if (memcmp(&kernel_header->magic, ARM64_IMAGE_MAGIC, sizeof(kernel_header->magic))) {
		debug_str = "Kernel image magic not matching";
		kernel_header = NULL;
		goto fail;
	}

	return;

fail:
	pr_debug("%s, using defaults", debug_str);
}

static u64 kvm__arch_get_kernel_size(struct kvm *kvm)
{
	if (kvm->cfg.arch.aarch32_guest || !kernel_header)
		return 0;

	return le64_to_cpu(kernel_header->image_size);
}

#define FDT_ALIGN	SZ_2M
#define INITRD_ALIGN	4
bool kvm__arch_load_kernel_image(struct kvm *kvm, int fd_kernel, int fd_initrd,
				 const char *kernel_cmdline)
{
	void *pos, *kernel_end, *limit;
	unsigned long guest_addr;
	u64 payload_region_size;
	ssize_t file_size;
	u64 kernel_size;

	payload_region_size = kvm__arch_get_payload_region_size(kvm);
	/*
	 * Linux for arm requires the initrd and dtb to be mapped inside lowmem,
	 * so we can't just place them at the top of memory.
	 */
	limit = kvm->ram_start + min(kvm->ram_size, payload_region_size);

	kvm__arch_read_kernel_header(kvm, fd_kernel);

	pos = kvm->ram_start + kvm__arch_get_kern_offset(kvm);
	kvm->arch.kern_guest_start = host_to_guest_flat(kvm, pos);
	if (!kvm->arch.kern_guest_start)
		die("guest memory too small to contain the kernel");
	file_size = read_file(fd_kernel, pos, limit - pos);
	if (file_size < 0) {
		if (errno == ENOMEM)
			die("kernel image too big to contain in guest memory.");

		die_perror("kernel read");
	}

	kernel_size = kvm__arch_get_kernel_size(kvm);
	if (!kernel_size || kernel_size < (u64)file_size)
		kernel_size = file_size;
	kernel_end = pos + kernel_size;
	pr_debug("Loaded kernel to 0x%llx (%llu bytes)",
		 kvm->arch.kern_guest_start, kernel_size);

	/*
	 * Now load backwards from the end of memory so the kernel
	 * decompressor has plenty of space to work with. First up is
	 * the device tree blob...
	 */
	pos = limit;
	pos -= (FDT_MAX_SIZE + FDT_ALIGN);
	guest_addr = host_to_guest_flat(kvm, pos);
	if (!guest_addr)
		die("fdt too big to contain in guest memory");
	guest_addr = ALIGN(guest_addr, FDT_ALIGN);
	pos = guest_flat_to_host(kvm, guest_addr);
	if (pos < kernel_end)
		die("fdt overlaps with kernel image.");

	kvm->arch.dtb_guest_start = guest_addr;
	pr_debug("Placing fdt at 0x%llx - 0x%llx",
		 kvm->arch.dtb_guest_start,
		 host_to_guest_flat(kvm, limit - 1));
	limit = pos;

	/* ... and finally the initrd, if we have one. */
	if (fd_initrd != -1) {
		struct stat sb;
		unsigned long initrd_start;

		if (fstat(fd_initrd, &sb))
			die_perror("fstat");

		pos -= (sb.st_size + INITRD_ALIGN);
		guest_addr = host_to_guest_flat(kvm, pos);
		if (!guest_addr)
			die("initrd too big to fit in the payload memory region");
		guest_addr = ALIGN(guest_addr, INITRD_ALIGN);
		pos = guest_flat_to_host(kvm, guest_addr);
		if (pos < kernel_end)
			die("initrd overlaps with kernel image.");

		initrd_start = guest_addr;
		file_size = read_file(fd_initrd, pos, limit - pos);
		if (file_size == -1) {
			if (errno == ENOMEM)
				die("initrd too big to contain in guest memory.");

			die_perror("initrd read");
		}

		kvm->arch.initrd_guest_start = initrd_start;
		kvm->arch.initrd_size = file_size;
		pr_debug("Loaded initrd to 0x%llx (%llu bytes)",
			 kvm->arch.initrd_guest_start,
			 kvm->arch.initrd_size);
	} else {
		kvm->arch.initrd_size = 0;
	}

	return true;
}

static bool validate_fw_addr(struct kvm *kvm, u64 fw_addr)
{
	u64 ram_phys;

	ram_phys = host_to_guest_flat(kvm, kvm->ram_start);

	if (fw_addr < ram_phys || fw_addr >= ram_phys + kvm->ram_size) {
		pr_err("Provide --firmware-address an address in RAM: "
		       "0x%016llx - 0x%016llx",
		       ram_phys, ram_phys + kvm->ram_size);

		return false;
	}

	return true;
}

bool kvm__load_firmware(struct kvm *kvm, const char *firmware_filename)
{
	u64 fw_addr = kvm->cfg.arch.fw_addr;
	void *host_pos;
	void *limit;
	ssize_t fw_sz;
	int fd;

	limit = kvm->ram_start + kvm->ram_size;

	/* For default firmware address, lets load it at the begining of RAM */
	if (fw_addr == 0)
		fw_addr = kvm->arch.memory_guest_start;

	if (!validate_fw_addr(kvm, fw_addr))
		die("Bad firmware destination: 0x%016llx", fw_addr);

	fd = open(firmware_filename, O_RDONLY);
	if (fd < 0)
		return false;

	host_pos = guest_flat_to_host(kvm, fw_addr);
	if (!host_pos || host_pos < kvm->ram_start)
		return false;

	fw_sz = read_file(fd, host_pos, limit - host_pos);
	if (fw_sz < 0)
		die("failed to load firmware");
	close(fd);

	/* Kernel isn't loaded by kvm, point start address to firmware */
	kvm->arch.kern_guest_start = fw_addr;
	pr_debug("Loaded firmware to 0x%llx (%zd bytes)",
		 kvm->arch.kern_guest_start, fw_sz);

	/* Load dtb just after the firmware image*/
	host_pos += fw_sz;
	if (host_pos + FDT_MAX_SIZE > limit)
		die("not enough space to load fdt");

	kvm->arch.dtb_guest_start = ALIGN(host_to_guest_flat(kvm, host_pos),
					  FDT_ALIGN);
	pr_debug("Placing fdt at 0x%llx - 0x%llx",
		 kvm->arch.dtb_guest_start,
		 kvm->arch.dtb_guest_start + FDT_MAX_SIZE);

	return true;
}

int kvm__arch_setup_firmware(struct kvm *kvm)
{
	return 0;
}

int vcpu_affinity_parser(const struct option *opt, const char *arg, int unset)
{
	struct kvm *kvm = opt->ptr;
	const char *cpulist = arg;
	cpumask_t *cpumask;
	int cpu, ret;

	kvm->cfg.arch.vcpu_affinity = cpulist;

	cpumask = calloc(1, cpumask_size());
	if (!cpumask)
		die_perror("calloc");

	ret = cpulist_parse(cpulist, cpumask);
	if (ret) {
		free(cpumask);
		return ret;
	}

	kvm->arch.vcpu_affinity_cpuset = CPU_ALLOC(NR_CPUS);
	if (!kvm->arch.vcpu_affinity_cpuset)
		die_perror("CPU_ALLOC");
	CPU_ZERO_S(CPU_ALLOC_SIZE(NR_CPUS), kvm->arch.vcpu_affinity_cpuset);

	for_each_cpu(cpu, cpumask)
		CPU_SET(cpu, kvm->arch.vcpu_affinity_cpuset);

	return 0;
}

void kvm__arch_validate_cfg(struct kvm *kvm)
{

	if (kvm->cfg.ram_addr < ARM_MEMORY_AREA) {
		die("RAM address is below the I/O region ending at %luGB",
		    ARM_MEMORY_AREA >> 30);
	}

	if (kvm->cfg.arch.aarch32_guest &&
	    kvm->cfg.ram_addr + kvm->cfg.ram_size > SZ_4G) {
		die("RAM extends above 4GB");
	}
}

u64 kvm__arch_default_ram_address(void)
{
	return ARM_MEMORY_AREA;
}

static int kvm__arch_get_ipa_limit(struct kvm *kvm)
{
	int ret;

	ret = ioctl(kvm->sys_fd, KVM_CHECK_EXTENSION, KVM_CAP_ARM_VM_IPA_SIZE);
	if (ret <= 0)
		ret = 0;

	return ret;
}

int kvm__get_vm_type(struct kvm *kvm)
{
	unsigned int ipa_bits, max_ipa_bits;
	unsigned long max_ipa;

	/* If we're running on an old kernel, use 0 as the VM type */
	max_ipa_bits = kvm__arch_get_ipa_limit(kvm);
	if (!max_ipa_bits)
		return 0;

	/* Otherwise, compute the minimal required IPA size */
	max_ipa = kvm->cfg.ram_addr + kvm->cfg.ram_size - 1;
	ipa_bits = max(32, fls_long(max_ipa));
	pr_debug("max_ipa %lx ipa_bits %d max_ipa_bits %d",
		 max_ipa, ipa_bits, max_ipa_bits);

	if (ipa_bits > max_ipa_bits)
		die("Memory too large for this system (needs %d bits, %d available)", ipa_bits, max_ipa_bits);

	return KVM_VM_TYPE_ARM_IPA_SIZE(ipa_bits);
}

static int kvm__arch_free_kernel_header(struct kvm *kvm)
{
	free(kernel_header);

	return 0;
}
late_exit(kvm__arch_free_kernel_header);
