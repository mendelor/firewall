// socket_minimal.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

struct conn_event {
    __u64 ts_ns;
    __u32 pid;
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8  type;   // 0=CONNECT, 1=ACCEPT, 2=CLOSE
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events_rb SEC(".maps");

// Helper to submit event
static __always_inline void submit_event(struct sock *sk, __u8 type)
{
    struct conn_event *ev;

    ev = bpf_ringbuf_reserve(&events_rb, sizeof(*ev), 0);
    if (!ev)
        return;

    ev->ts_ns = bpf_ktime_get_ns();
    ev->pid   = bpf_get_current_pid_tgid() >> 32;

    // Read addresses and ports
    ev->saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    ev->daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    ev->sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    ev->dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
    ev->type  = type;

    bpf_ringbuf_submit(ev, 0);
}

// CONNECT: tcp_v4_connect
SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(handle_connect, struct sock *sk)
{
    submit_event(sk, 0);
    return 0;
}

// ACCEPT: inet_csk_accept
SEC("kprobe/inet_csk_accept")
int BPF_KPROBE(handle_accept, struct sock *sk)
{
    submit_event(sk, 1);
    return 0;
}

// CLOSE: tcp_close
SEC("kprobe/tcp_close")
int BPF_KPROBE(handle_close, struct sock *sk)
{
    submit_event(sk, 2);
    return 0;
}
