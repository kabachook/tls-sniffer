#include <uapi/linux/ptrace.h>
#include <linux/string.h>

BPF_PERF_OUTPUT(crypto_tls_conn_write_events);

// https://pkg.go.dev/reflect#SliceHeader
struct SliceHeader {
    void* Data;
    long Len;
    long Cap;
};

#define BUF_SIZE 256

int crypto_tls_conn_write(struct pt_regs *ctx) {
    char buf[BUF_SIZE] = {0};

    void* stackAddr = (void*)ctx->sp;
    bpf_trace_printk("stack addr: %x", stackAddr);

    struct SliceHeader b = {};
    
    bpf_probe_read(&b.Data, 8, (void *)stackAddr+16);

    bpf_probe_read(&b.Len, 8, (void *)stackAddr+24);
    bpf_trace_printk("%p\tLen: %ld bytes", b.Len, b.Len);

    bpf_probe_read(&b.Cap, 8, (void *)stackAddr+32);
    bpf_trace_printk("%p\tCap %ld bytes", b.Cap, b.Cap);


    int to_read = b.Len < BUF_SIZE ? b.Len : BUF_SIZE;
    int read = bpf_probe_read(&buf, BUF_SIZE, b.Data);
    bpf_trace_printk("%s", buf);

    
    crypto_tls_conn_write_events.perf_submit(ctx, &buf, BUF_SIZE);
    return 0;
}

