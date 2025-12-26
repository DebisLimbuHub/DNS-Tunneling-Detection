#DNS traffic patterns to test Suricata timing/frequency rules.

import argparse, random, socket, struct, string, time, sys

# ---------- low-level DNS helpers ----------
def encode_name(name: str) -> bytes:
    out = b""
    for part in name.split("."):
        if not part: continue
        if len(part) > 63:
            raise ValueError("A DNS label exceeds 63 characters.")
        out += bytes([len(part)]) + part.encode("ascii")
    return out + b"\x00"

QTYPE = {"A": 1, "TXT": 16}

def build_query(qname: str, qtype: str = "A") -> bytes:
    txid = random.getrandbits(16)
    flags = 0x0100  # recursion desired
    header = struct.pack("!HHHHHH", txid, flags, 1, 0, 0, 0)
    question = encode_name(qname) + struct.pack("!HH", QTYPE[qtype], 1) 
    return header + question

# ---------- traffic generators ----------
ALPH = string.ascii_lowercase + string.digits

def random_label(n=12):
    return "".join(random.choice(ALPH) for _ in range(n))

def send_series(resolver, qtype, suffix, count, interval, label_len=12, recv=False):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); sock.settimeout(1.5)
    for i in range(1, count + 1):
        name = f"{random_label(label_len)}.{suffix}".strip(".")
        pkt = build_query(name, qtype=qtype)
        print(f"[{i}/{count}] {qtype} {name} -> {resolver}:53")
        try:
            sock.sendto(pkt, (resolver, 53))
            if recv: sock.recvfrom(512)   
        except socket.timeout:
            pass
        time.sleep(interval)
    sock.close()

def main():
    ap = argparse.ArgumentParser(description="Trigger Suricata DNS timing/frequency rules.")
    ap.add_argument("mode", choices=["rate", "txtburst", "beacon"], help="Traffic pattern")
    ap.add_argument("--resolver", default="8.8.8.8", help="DNS server IP")
    ap.add_argument("--suffix", default="example.com", help="Base domain suffix")
    ap.add_argument("--count", type=int, help="Override number of queries")
    ap.add_argument("--interval", type=float, help="Override seconds between queries")
    ap.add_argument("--label-len", type=int, default=12, help="Random label length (<=63)")
    args = ap.parse_args()

    if args.label_len < 1 or args.label_len > 63:
        print("--label-len must be 1..63", file=sys.stderr); sys.exit(2)

    
    if args.mode == "rate":
        count = args.count or 120          # >100 in 60s
        interval = args.interval or 0.4    # ~48s total
        send_series(args.resolver, "A", args.suffix, count, interval, args.label_len)

    elif args.mode == "txtburst":
        count = args.count or 25           # >=20 in 60s
        interval = args.interval or 1.5    # ~37.5s total
        send_series(args.resolver, "TXT", args.suffix, count, interval, args.label_len)

    elif args.mode == "beacon":
        count = args.count or 30
        interval = args.interval or 2.0    # steady periodic pattern
        send_series(args.resolver, "A", args.suffix, count, interval, args.label_len)

if __name__ == "__main__":
    main()
