.PHONY: all clean

all: tc_hook.o xdp_hook.o

tc_hook.o: src/tc_hook.c src/common.h
	clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -c src/tc_hook.c -o tc_hook.o

xdp_hook.o: src/xdp_hook.c src/common.h
	clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -c src/xdp_hook.c -o xdp_hook.o

clean:
	rm -f *.o