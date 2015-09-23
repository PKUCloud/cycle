#!/bin/sh
echo "WARNING: If it is the first time to build the kernel, you should execute the full process to make it instead of executing this script!"

export LANG=C
NR_CORES=$(cat /proc/cpuinfo | grep "processor" | wc -l)
TARGET_DIR=/lib/modules/$(uname -r)/kernel/arch/x86/kvm

set -x

cd ./linux
make -j $((NR_CORES + 1)) || exit 1
cp -f arch/x86/kvm/kvm*.ko $TARGET_DIR || exit 1
modprobe -r kvm-intel
modprobe kvm-intel
