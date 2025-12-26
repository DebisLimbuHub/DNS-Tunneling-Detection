# Script to test DNS high entropy


import argparse, random, socket, struct, string, time, sys

def encode_name(name: str) -> bytes:
    """Encode a DNS name like 'foo.bar' into label format."""
    out = b""
    for part in name.split("."):
        if not part:
            continue
        if len(part) > 63:
            raise ValueError(f"Label '{part[:20]}...' exceeds 63 chars (RFC limit).")
        out += struct.pack("B", len(part)) + part.encode("ascii")
    return out + b"\x00"

def build_query(qname: str, qtype: int = 1) -> bytes:
    """Build a minimal DNS query packet for qname (A=1, TXT=16, etc.)."""
    txid = random.getrandbits(16)
    flags = 0x0100  # recursion desired
    qdcount, ancount, nscount, arcount = 1, 0, 0, 0
    header = struct.pack("!HHHHHH", txid, flags, qdcount, ancount, nscount, arcount)
    question = encode_name(qname) + struct.pack("!HH", qtype, 1)  # QCLASS IN(1)
    return header + question

def rand_label(mode: str, length: int) -> str:
    if mode == "longlabel":
        alphabet = string.ascii_lowercase + string.digits
    elif mode == "base32":
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    elif mode == "hex":
        alphabet = "0123456789abcdef"
    else:
        raise ValueError("Unknown mode")
    return "".join(random.choice(alphabet) for _ in range(length))

def main():
    p = argparse.ArgumentParser(description="Trigger Suricata DNS tunnelling rules by sending crafted queries.")
    p.add_argument("mode", choices=["longlabel", "base32", "hex"], help="Label style to generate")
    p.add_argument("--resolver", default="8.8.8.8", help="DNS server IP (default: 8.8.8.8)")
    p.add_argument("--suffix", default="example.com", help="Base domain to append (default: example.com)")
    p.add_argument("--length", type=int, default=60, help="Label length (50–63 recommended)")
    p.add_argument("--count", type=int, default=5, help="How many queries to send")
    p.add_argument("--interval", type=float, default=0.2, help="Seconds between queries")
    p.add_argument("--qtype", default="A", choices=["A", "TXT"], help="Query type to send")
    p.add_argument("--timeout", type=float, default=2.0, help="Response timeout seconds")
    args = p.parse_args()

    if args.length < 1 or args.length > 63:
        print("Length must be between 1 and 63 (DNS label limit).", file=sys.stderr)
        sys.exit(2)

    qtype_val = 1 if args.qtype == "A" else 16

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(args.timeout)

    try:
        for i in range(args.count):
            label = rand_label(args.mode, args.length)
            qname = f"{label}.{args.suffix}".strip(".")
            pkt = build_query(qname, qtype=qtype_val)
            print(f"[{i+1}/{args.count}] Querying {qname} ({args.qtype}) -> {args.resolver}:53")
            try:
                sock.sendto(pkt, (args.resolver, 53))
                
                sock.recvfrom(512)
            except socket.timeout:
                pass
            time.sleep(args.interval)
    finally:
        sock.close()

if __name__ == "__main__":
    main()


