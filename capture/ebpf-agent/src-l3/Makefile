# L3 parity smoke build (run inside the ebpf-agent container: /agent/src-l3)
CLANG ?= clang
BPFTOOL ?= bpftool
CC ?= cc
VMLINUX ?= /sys/kernel/btf/vmlinux
ARCH := $(shell uname -m | sed 's/x86_64/x86/;s/aarch64/arm64/')
MARCH_INC := $(shell echo /usr/include/$$(uname -m)-linux-gnu)

capture.bpf.o: capture.bpf.c vmlinux.h
	$(CLANG) -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH) \
		-I. -I$(MARCH_INC) -c capture.bpf.c -o $@

capture.skel.h: capture.bpf.o
	$(BPFTOOL) gen skeleton capture.bpf.o > $@

smoke: smoke.c capture.skel.h
	$(CC) -O2 -g -Wno-unused-result -o $@ smoke.c -lbpf -lelf -lz

clean:
	rm -f capture.bpf.o capture.skel.h smoke

veryclean: clean
	rm -f vmlinux.h