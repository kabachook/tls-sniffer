#include <uapi/linux/ptrace.h>
#include <linux/string.h>

BPF_PERF_OUTPUT(crypto_tls_conn_write_events);

#define DATA_SIZE 128

struct crypto_tls_conn_write_event_t {
    u32 pid;
    char data[DATA_SIZE];
    long len;
} __attribute__((packed));

// https://pkg.go.dev/reflect#SliceHeader
struct SliceHeader {
    void* Data;
    long Len;
    long Cap;
};


int crypto_tls_conn_write(struct pt_regs *ctx) {
    struct crypto_tls_conn_write_event_t event = {};
    event.pid = bpf_get_current_pid_tgid();

    void* stackAddr = (void*)ctx->sp;
    bpf_trace_printk("stack addr: %x", stackAddr);

    struct SliceHeader b = {};
    
    bpf_probe_read(&b.Data, 8, (void *)stackAddr+16);

    bpf_probe_read(&b.Len, 8, (void *)stackAddr+24);
    bpf_trace_printk("%p\tLen: %ld bytes", b.Len, b.Len);
    event.len = b.Len;

    bpf_probe_read(&b.Cap, 8, (void *)stackAddr+32);
    bpf_trace_printk("%p\tCap %ld bytes", b.Cap, b.Cap);

    bpf_probe_read(&event.data, DATA_SIZE, b.Data);
    bpf_trace_printk("%s", event.data);

    crypto_tls_conn_write_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

