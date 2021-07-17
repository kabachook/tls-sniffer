import argparse
from bcc import BPF
from bcc.utils import printb
import ctypes as ct

bpf_text = open("probe.c", "r").read()

parser = argparse.ArgumentParser(
    description="Sniff TLS",
    formatter_class=argparse.RawDescriptionHelpFormatter,
)
parser.add_argument("-b", "--binary", type=str, help="path to binary")
parser.add_argument("-p", "--pid", type=int, help="sniff this PID only")
args = parser.parse_args()


b = BPF(text=bpf_text)

b.attach_uprobe(args.binary, fn_name="crypto_tls_conn_write",
                sym="crypto/tls.(*Conn).Write", pid=args.pid or -1)



def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(ct.c_char * 256)).contents[:]
    if not any([x in event for x in [b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", b"HTTP/1.1"]]):
        print("Probably failed")
    else:
        print(event)


b["crypto_tls_conn_write_events"].open_perf_buffer(print_event)

print("Probes started")
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
