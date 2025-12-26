#All 3 rules combined

import argparse, random, socket, struct, string, time, threading, sys

# ---------- DNS helpers ----------
QTYPE = {"A": 1, "TXT": 16}

def encode_name(name: str) -> bytes:
    out = b""
    for part in name.split("."):
        if not part: continue
        if len(part) > 63: raise ValueError("DNS label exceeds 63 characters.")
        out += bytes([len(part)]) + part.encode("ascii")
    return out + b"\x00"

def build_query(qname: str, qtype: str = "A") -> bytes:
    txid = random.getrandbits(16)
    hdr  = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)  # RD=1
    q    = encode_name(qname) + struct.pack("!HH", QTYPE[qtype], 1)  # IN
    return hdr + q

def send_series(resolver, labels, suffix, qtype, interval, jitter, tag, recv=False):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(0.5)
    n = len(labels)
    for i, label in enumerate(labels, 1):
        name = f"{label}.{suffix}".strip(".")
        pkt  = build_query(name, qtype)
        try:
            sock.sendto(pkt, (resolver, 53))
            if recv: sock.recvfrom(512)
        except socket.timeout:
            pass
        
        dt = interval + (random.uniform(-jitter, jitter) if jitter else 0.0)
        if dt > 0: time.sleep(dt)
        if i % max(1, n // 5) == 0:
            print(f"[{tag}] {i}/{n} sent")
    sock.close()
    print(f"[{tag}] done ({n} queries).")

# ---------- label generators ----------
def base32_label(n=48):
    return "".join(random.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567") for _ in range(n))

def long_label(n=60):
    return "".join(random.choice(string.ascii_lowercase + string.digits + "-") for _ in range(n))

def hex_label(n=50):
    return "".join(random.choice("0123456789ABCDEF-") for _ in range(n))

def filler_label(n=10):
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))

# ---------- main ----------
def main():
    ap = argparse.ArgumentParser(description="Trigger Entropy + Domain Randomisation + Timing/Frequency rules with varied pacing.")
    ap.add_argument("--resolver", default="8.8.8.8", help="DNS server IP")
    ap.add_argument("--suffix",   default="example.com", help="Base domain suffix")

    # Fast stream (Timing/Frequency) >=600/min
    ap.add_argument("--fast-count",    type=int,   default=600)
    ap.add_argument("--fast-interval", type=float, default=0.01)   # ~7s total
    ap.add_argument("--fast-jitter",   type=float, default=0.01)   
    ap.add_argument("--fast-qtype",    choices=["A","TXT"], default="A")
    ap.add_argument("--fast-len",      type=int,   default=10)

    # Slow stream (Entropy via base32)
    ap.add_argument("--slow-count",    type=int,   default=24)
    ap.add_argument("--slow-interval", type=float, default=2.0)    # ~48s total
    ap.add_argument("--slow-jitter",   type=float, default=0.3)
    ap.add_argument("--slow-qtype",    choices=["A","TXT"], default="A")
    ap.add_argument("--slow-len",      type=int,   default=48)

    # Medium stream (Domain randomisation via long/hex)
    ap.add_argument("--med-count",     type=int,   default=18)
    ap.add_argument("--med-interval",  type=float, default=1.2)    # ~22s total
    ap.add_argument("--med-jitter",    type=float, default=0.25)
    ap.add_argument("--med-qtype",     choices=["A","TXT"], default="A")
    ap.add_argument("--med-mode",      choices=["long","hex"], default="long")
    ap.add_argument("--med-len-long",  type=int,   default=60)
    ap.add_argument("--med-len-hex",   type=int,   default=50)

    args = ap.parse_args()

    
    for L in (args.fast-len if hasattr(args,"fast-len") else args.fast_len, args.slow_len, args.med_len_long, args.med_len_hex, args.fast_len):
        pass  
    if not (1 <= args.fast_len <= 63 and 1 <= args.slow_len <= 63 and
            1 <= args.med_len_long <= 63 and 1 <= args.med_len_hex <= 63):
        print("All label lengths must be between 1 and 63.", file=sys.stderr); sys.exit(2)

    
    slow_labels = [base32_label(args.slow_len) for _ in range(args.slow_count)]  
    if args.med_mode == "long":
        med_labels = [long_label(args.med_len_long) for _ in range(args.med_count)]  
    else:
        med_labels = [hex_label(args.med_len_hex) for _ in range(args.med_count)]    
    fast_labels = [filler_label(args.fast_len) for _ in range(args.fast_count)]     

    print("Starting 3 streams: FAST(rate), SLOW(entropy), MEDIUM(randomisation)...")
    threads = [
        threading.Thread(target=send_series, kwargs=dict(
            resolver=args.resolver, labels=fast_labels, suffix=args.suffix,
            qtype=args.fast_qtype, interval=args.fast_interval, jitter=args.fast_jitter, tag="FAST/RATE")),
        threading.Thread(target=send_series, kwargs=dict(
            resolver=args.resolver, labels=slow_labels, suffix=args.suffix,
            qtype=args.slow_qtype, interval=args.slow_interval, jitter=args.slow_jitter, tag="SLOW/ENTROPY")),
        threading.Thread(target=send_series, kwargs=dict(
            resolver=args.resolver, labels=med_labels, suffix=args.suffix,
            qtype=args.med_qtype, interval=args.med_interval, jitter=args.med_jitter, tag="MED/RANDOM")),
    ]
    for t in threads: t.start()
    for t in threads: t.join()
    print("All streams finished. Check Suricata fast.log / eve.json.")

if __name__ == "__main__":
    main()
