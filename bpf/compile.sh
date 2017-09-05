#!/bin/bash
clang \
	-D__KERNEL__ -D__ASM_SYSREG_H -Wno-unused-value -Wno-pointer-sign \
	-Wno-compare-distinct-pointer-types \
	-Wno-gnu-variable-sized-type-not-at-end \
	-Wno-tautological-compare \
	-O2 -emit-llvm -g -c $1 -o -| llc -march=bpf -filetype=obj -o $1.o
