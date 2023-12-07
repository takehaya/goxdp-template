#!/bin/bash

LINUX_VERSION=5.15.15

wget https://cdn.kernel.org/pub/linux/kernel/v5.x/linux-${LINUX_VERSION}.tar.xz
tar xf linux-${LINUX_VERSION}.tar.xz
pushd linux-${LINUX_VERSION}/

make defconfig
./scripts/bpf_doc.py --header --filename ./tools/include/uapi/linux/bpf.h > ../include/bpf_helper_defs.h
cp ./tools/lib/bpf/bpf_helpers.h ../include/bpf_helpers.h
cp ./tools/lib/bpf/bpf_core_read.h ../include/bpf_core_read.h
cp ./tools/lib/bpf/bpf_endian.h ../include/bpf_endian.h

popd
rm linux-${LINUX_VERSION}.tar.xz
rm -rf linux-${LINUX_VERSION}/