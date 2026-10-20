// socket_minimal_user.c
#include <stdio.h>
#include <unistd.h>
#include <bpf/libbpf.h>

struct conn_event {
    __u64 ts_ns;
    __u32 pid;
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8  type;
};

static int handle_event(void *ctx, void *data, size_t len) {
    struct conn_event *ev = data;

    printf("PID %u | %s | %u -> %u\n",
        ev->pid,
        ev->type == 0 ? "CONNECT" :
        ev->type == 1 ? "ACCEPT" : "CLOSE",
        ev->sport, ev->dport);

    return 0;
}

int main() {
    struct bpf_object *obj;
    int rb_fd;

    obj = bpf_object__open_file("socket_minimal.bpf.o", NULL);
    bpf_object__load(obj);

    rb_fd = bpf_object__find_map_fd_by_name(obj, "events_rb");
    
    struct ring_buffer *rb = ring_buffer__new(rb_fd, handle_event, NULL, NULL);

    while (1) ring_buffer__poll(rb, 100);

    return 0;
}
