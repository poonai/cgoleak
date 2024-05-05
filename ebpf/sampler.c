// go:build ignore
#include <linux/bpf.h>
#include "libbpf/bpf_helpers.h"
#include "libbpf/bpf_tracing.h"
#include "asm/ptrace.h"

#include "malloc.h"

#define PERF_MAX_STACK_DEPTH 127
#define PROFILE_MAPS_SIZE 16384

char __license[] SEC("license") = "GPL";

struct
{
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, 127 * sizeof(__u64));
    __uint(max_entries, PROFILE_MAPS_SIZE);
} stacks SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, PROFILE_MAPS_SIZE);
} alloc_sizes SEC(".maps");



struct 
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, PROFILE_MAPS_SIZE);
} total_allocs SEC(".maps");

struct alloc {
    __u64 size;
    long stack_id;
};

struct 
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, struct alloc);
    __uint(max_entries, PROFILE_MAPS_SIZE);
} allocs SEC(".maps");



const struct alloc *unused __attribute__((unused));

SEC("uprobe/libc.so.6:malloc")
int malloc_enter(struct pt_regs *ctx)
{

    __u64 stack[7];
    bpf_get_stack(ctx, stack, sizeof(stack), BPF_F_USER_STACK);
    for (int i = 0; i < 7; i++) {
        bpf_printk("stack %d\n", stack[i]);
    }
    size_t size = (size_t)PT_REGS_PARM1(ctx);

    __u32 tid = 0;
    tid = bpf_get_current_pid_tgid();

    __u64 size64 = size;
    bpf_map_update_elem(&alloc_sizes, &tid, &size64, BPF_ANY);

    return 0;
}

SEC("uretprobe/libc.so.6:malloc")
int malloc_exit(struct pt_regs *ctx)
{

    __u32 tid = 0;
    tid = bpf_get_current_pid_tgid();
    __u64 *size = bpf_map_lookup_elem(&alloc_sizes, &tid);
    if (size == NULL)
    {
        bpf_printk("failed to read size value\n");
        return 0;
    }

    __u64 size_c = *size;

    bpf_map_delete_elem(&alloc_sizes, &tid);


    void* addr = (void*)PT_REGS_RC(ctx);

    if (addr == NULL)
    {
        bpf_printk("address is null\n");
        return 0;
    }

    __u64 address = (__u64)addr;

    if (address == 0)
    {
        bpf_printk("address is null\n");
        return 0;
    }
    bpf_printk("allocating address %d\n", address);

    long stack_id;
    stack_id = bpf_get_stackid(ctx,&stacks, BPF_F_USER_STACK);

    // store the currect address allocation and there respective stack id. 
    // so it can be used to get the size of the allocation in the free probe.
    struct alloc alloc;
    alloc.size = size_c;
    alloc.stack_id = stack_id;
    bpf_map_update_elem(&allocs, &address, &alloc, BPF_ANY);
    
    __u64 *total_alloc = bpf_map_lookup_elem(&total_allocs, &stack_id);
    if (total_alloc == NULL)
    {
        bpf_map_update_elem(&total_allocs, &stack_id, &size_c, BPF_ANY);
        return 0;
    }
    bpf_printk("stack id %d total alloc %d size %d\n", stack_id, *total_alloc, size_c);
    __sync_fetch_and_add(total_alloc, size_c);
    return 0;
}

SEC("uprobe/libc.so.6:free")
int free_enter(struct pt_regs *ctx)
{
    void *addr = (void *)PT_REGS_PARM1(ctx);
    __u64 address = (__u64)addr;
    if (address == 0)
    {
        bpf_printk("address is null in free\n");
        return 0;
    }
    bpf_printk("freeing address %d\n", address);

    struct alloc *alloc = bpf_map_lookup_elem(&allocs, &address);
    if (alloc == NULL)
    {
        bpf_printk("failed to read alloc value\n");
        return 0;
    }

    __u64 size = alloc->size;
    long stack_id = alloc->stack_id;
    bpf_map_delete_elem(&allocs, &address);

    __u64 *total_alloc = bpf_map_lookup_elem(&total_allocs, &stack_id);
    if (total_alloc == NULL)
    {
        bpf_printk("failed to read total_alloc value\n");
        return 0;
    }
    __sync_fetch_and_sub(total_alloc, size);
    return 0;
}
