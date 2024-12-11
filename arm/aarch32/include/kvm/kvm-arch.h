#ifndef KVM__KVM_ARCH_H
#define KVM__KVM_ARCH_H

#include <linux/sizes.h>

#define kvm__arch_get_kern_offset(...)	0x8000
#define kvm__arch_get_kernel_size(...)	0

struct kvm;
static inline void kvm__arch_read_kernel_header(struct kvm *kvm, int fd) {}
static inline void kvm__arch_enable_mte(struct kvm *kvm) {}

#define MAX_PAGE_SIZE	SZ_4K

#include "arm-common/kvm-arch.h"

#endif /* KVM__KVM_ARCH_H */
