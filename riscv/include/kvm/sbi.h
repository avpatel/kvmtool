/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Common SBI related defines and macros to be used by RISC-V kernel,
 * RISC-V KVM and userspace.
 *
 * Copyright (c) 2019 Western Digital Corporation or its affiliates.
 */

#ifndef __RISCV_SBI_H__
#define __RISCV_SBI_H__

enum sbi_ext_id {
	SBI_EXT_0_1_SET_TIMER = 0x0,
	SBI_EXT_0_1_CONSOLE_PUTCHAR = 0x1,
	SBI_EXT_0_1_CONSOLE_GETCHAR = 0x2,
	SBI_EXT_0_1_CLEAR_IPI = 0x3,
	SBI_EXT_0_1_SEND_IPI = 0x4,
	SBI_EXT_0_1_REMOTE_FENCE_I = 0x5,
	SBI_EXT_0_1_REMOTE_SFENCE_VMA = 0x6,
	SBI_EXT_0_1_REMOTE_SFENCE_VMA_ASID = 0x7,
	SBI_EXT_0_1_SHUTDOWN = 0x8,
	SBI_EXT_BASE = 0x10,
	SBI_EXT_DBCN = 0x4442434E,
	SBI_EXT_SUSP = 0x53555350,
};

enum sbi_ext_base_fid {
	SBI_BASE_GET_SPEC_VERSION = 0,
	SBI_BASE_GET_IMP_ID,
	SBI_BASE_GET_IMP_VERSION,
	SBI_BASE_PROBE_EXT,
	SBI_BASE_GET_MVENDORID,
	SBI_BASE_GET_MARCHID,
	SBI_BASE_GET_MIMPID,
};

enum sbi_ext_dbcn_fid {
	SBI_EXT_DBCN_CONSOLE_WRITE = 0,
	SBI_EXT_DBCN_CONSOLE_READ = 1,
	SBI_EXT_DBCN_CONSOLE_WRITE_BYTE = 2,
};

enum sbi_ext_susp_fid {
	SBI_EXT_SUSP_SYSTEM_SUSPEND = 0,
};

enum sbi_ext_susp_sleep_type {
	SBI_SUSP_SLEEP_TYPE_SUSPEND_TO_RAM = 0,
};

#define SBI_SPEC_VERSION_DEFAULT	0x1
#define SBI_SPEC_VERSION_MAJOR_OFFSET	24
#define SBI_SPEC_VERSION_MAJOR_MASK	0x7f
#define SBI_SPEC_VERSION_MINOR_MASK	0xffffff

/* SBI return error codes */
#define SBI_SUCCESS		0
#define SBI_ERR_FAILURE		-1
#define SBI_ERR_NOT_SUPPORTED	-2
#define SBI_ERR_INVALID_PARAM	-3
#define SBI_ERR_DENIED		-4
#define SBI_ERR_INVALID_ADDRESS	-5
#define SBI_ERR_ALREADY_AVAILABLE -6
#define SBI_ERR_ALREADY_STARTED -7
#define SBI_ERR_ALREADY_STOPPED -8

#endif
