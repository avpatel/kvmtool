#!/bin/sh

########################################################################
# Updates the kvmtool tree with up-to-date public header files from
# a Linux source tree.
# If no directory is given on the command line, it will try to find one
# using the lib/modules/`uname -r`/source link.
########################################################################

set -ue

VIRTIO_LIST="virtio_9p.h virtio_balloon.h virtio_blk.h virtio_config.h \
	     virtio_console.h virtio_ids.h virtio_mmio.h virtio_net.h \
	     virtio_pci.h virtio_ring.h virtio_rng.h virtio_scsi.h \
	     virtio_vsock.h"

if [ "$#" -ge 1 ]
then
	LINUX_ROOT="$1"
else
	LINUX_ROOT="/lib/modules/$(uname -r)/source"
fi

if [ ! -d "$LINUX_ROOT/include/uapi/linux" ]
then
	echo "$LINUX_ROOT does not seem to be valid Linux source tree."
	echo "usage: $0 [path-to-Linux-source-tree]"
	exit 1
fi

copy_uapi_linux_header () {
	cp -- "$LINUX_ROOT/include/uapi/linux/$1" include/linux
}

for header in kvm.h $VIRTIO_LIST
do
	copy_uapi_linux_header $header
done

unset KVMTOOL_PATH

copy_uapi_asm_header () {
	local file="arch/$arch/include/uapi/asm/$1"
	local src="$LINUX_ROOT/$file"

	if [ -r "$src" ]
	then
		cp -- "$src" "$KVMTOOL_PATH/include/asm/"
	else
		echo "Warning: Unable to find $file, skipping..."
	fi
}

for arch in arm64 mips powerpc riscv x86
do
	KVMTOOL_PATH=$arch

	case $arch in
		arm64)
			copy_uapi_asm_header sve_context.h
			copy_uapi_linux_header psci.h
			;;
	esac
	copy_uapi_asm_header kvm.h
done
