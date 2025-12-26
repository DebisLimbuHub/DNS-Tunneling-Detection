#DNS randomisation script to test randomised subdomain labels.

import argparse, random, socket, struct, string, time, sys

# ---------- DNS helpers ----------
def encode_name(name: str) -> bytes:
    out = b""
    for part in name.split("."):
        if not part: continue
        if len(part) > 63:
            raise ValueError("A DNS label exceeds 63 characters.")
        out += bytes([len(part)]) + part.encode("ascii")
    return out + b"\x00"

def build_query(qname: str, qtype: int = 1) -> bytes:
    
    txid = random.getrandbits(16)
    flags = 0x0100
    header = struct.pack("!HHHHHH", txid, flags, 1, 0, 0, 0)
    return header + encode_name(qname) + struct.pack("!HH", qtype, 1)

# ---------- label generators for each branch ----------
def gen_longlabel(n=60):
    chars = string.ascii_lowercase + string.digits + "-"  # [A-Za-z0-9-]
    return "".join(random.choice(chars) for _ in range(n))

def gen_base32(n=48):
    chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567-"          # [A-Z2-7-]
    return "".join(random.choice(chars) for _ in range(n))

def gen_hex(n=50):
    chars = "0123456789ABCDEF-"                         # [0-9A-F-]
    return "".join(random.choice(chars) for _ in range(n))

def gen_digitheavy(n=30, min_digits=10):
   
    if n < 24: n = 24
    digits = [random.choice(string.digits) for _ in range(min_digits)]
    letters = [random.choice(string.ascii_lowercase) for _ in range(n - min_digits)]
    mix = digits + letters
    random.shuffle(mix)
    return "".join(mix)

GENS = {
    "longlabel": gen_longlabel,
    "base32": gen_base32,
    "hex": gen_hex,
    "digitheavy": gen_digitheavy,
}

def send_queries(mode, resolver, suffix, count, interval, length, digits, qtype_name="A", recv=False):
    qtype_val = 1 if qtype_name == "A" else 16
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1.5)

    for i in range(1, count + 1):
        if mode == "digitheavy":
            label = GENS[mode](n=length, min_digits=digits)
        else:
            label = GENS[mode](n=length)
        qname = f"{label}.{suffix}".strip(".")
        pkt = build_query(qname, qtype=qtype_val)
        print(f"[{i}/{count}] {qtype_name} {qname} -> {resolver}:53")
        try:
            sock.sendto(pkt, (resolver, 53))
            if recv:
                sock.recvfrom(512)
        except socket.timeout:
            pass
        time.sleep(interval)
    sock.close()

def main():
    ap = argparse.ArgumentParser(description="Trigger Suricata 'randomised subdomain label' rule.")
    ap.add_argument("mode", choices=["longlabel", "base32", "hex", "digitheavy"], help="Which branch to trigger")
    ap.add_argument("--resolver", default="8.8.8.8", help="DNS server IP")
    ap.add_argument("--suffix", default="example.com", help="Domain suffix to append")
    ap.add_argument("--length", type=int, help="Label length (<=63)")
    ap.add_argument("--digits", type=int, default=12, help="Min digits for digitheavy mode")
    ap.add_argument("--count", type=int, default=3, help="How many queries to send")
    ap.add_argument("--interval", type=float, default=0.2, help="Seconds between queries")
    args = ap.parse_args()

    
    defaults = {"longlabel": 60, "base32": 48, "hex": 50, "digitheavy": 30}
    length = args.length or defaults[args.mode]
    if length > 63 or length < 1:
        print("ERROR: --length must be between 1 and 63 (DNS label limit).", file=sys.stderr)
        sys.exit(2)

    send_queries(args.mode, args.resolver, args.suffix, args.count, args.interval, length, args.digits)

if __name__ == "__main__":
    main()
