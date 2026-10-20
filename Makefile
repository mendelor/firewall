BPF_CLANG=clang
BPF_CFLAGS=-O2 -g -target bpf -D__TARGET_ARCH_x86

all: bpf user

bpf:
    $(BPF_CLANG) $(BPF_CFLAGS) -c bpf/socket_minimal.bpf.c -o bpf/socket_minimal.bpf.o

user:
    gcc src/socket_minimal_user.c -o socket_minimal_user -lbpf
