#include <stdio.h>
#include <unistd.h>
#include <errno.h>
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
    struct ring_buffer *rb;

    /* Correct path: your .o file lives in bpf/ */
    obj = bpf_object__open_file("bpf/socket_minimal.bpf.o", NULL);
    if (!obj) {
        fprintf(stderr, "Failed to open BPF object file\n");
        return 1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "Failed to load BPF object\n");
        return 1;
    }

    rb_fd = bpf_object__find_map_fd_by_name(obj, "events_rb");
    if (rb_fd < 0) {
        fprintf(stderr, "Failed to find events_rb map\n");
        return 1;
    }

    rb = ring_buffer__new(rb_fd, handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        return 1;
    }

    while (1) {
        int err = ring_buffer__poll(rb, 100);
        if (err < 0) {
            fprintf(stderr, "ring_buffer__poll error: %d\n", err);
            break;
        }
    }

    return 0;
}
