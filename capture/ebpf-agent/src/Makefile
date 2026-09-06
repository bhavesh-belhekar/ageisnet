# CO-RE capture build. Run inside the ebpf-agent container: make -C /agent/src
# Generates vmlinux.h from the host's BTF at build time.
CLANG ?= clang
BPFTOOL ?= bpftool
CC ?= cc
VMLINUX ?= /sys/kernel/btf/vmlinux
ARCH := $(shell uname -m | sed 's/x86_64/x86/;s/aarch64/arm64/')
MARCH_INC := $(shell echo /usr/include/$$(uname -m)-linux-gnu)

.PHONY: all capture smoke clean veryclean

all: capture

capture: capture.c capture.skel.h
	$(CC) -O2 -g -Wno-unused-result -o $@ capture.c -lbpf -lelf -lz

smoke: capture.c capture.skel.h
	$(CC) -O2 -g -Wno-unused-result -o $@ capture.c -lbpf -lelf -lz

capture.skel.h: capture.bpf.o
	$(BPFTOOL) gen skeleton capture.bpf.o > $@

capture.bpf.o: capture.bpf.c vmlinux.h
	$(CLANG) -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH) \
		-I. -I$(MARCH_INC) -c capture.bpf.c -o $@

vmlinux.h:
	$(BPFTOOL) btf dump file $(VMLINUX) format c > $@

clean:
	rm -f capture smoke capture.bpf.o capture.skel.h

veryclean: clean
	rm -f vmlinux.h