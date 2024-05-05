package sampler

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type alloc -target amd64 -cc clang -cflags "-O2 -Wall -Werror -fpie -Wno-unused-variable -Wno-unused-function" sampler ../ebpf/sampler.c -- -I../ebpf/bpf/libbpf -I../ebpf/bpf/vmlinux/
