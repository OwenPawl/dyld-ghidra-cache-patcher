import struct
import subprocess


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def u64(b, o):
    return struct.unpack_from("<Q", b, o)[0]


def i32(b, o):
    return struct.unpack_from("<i", b, o)[0]


def sx(v, bits):
    sign = 1 << (bits - 1)
    return (v ^ sign) - sign


def run(cmd):
    print("+", " ".join(map(str, cmd)))
    p = subprocess.run(cmd, text=True)
    if p.returncode != 0:
        raise SystemExit(p.returncode)


def choose_samples(targets, n):
    targets = sorted(targets)
    if n <= 0 or not targets:
        return []
    if len(targets) <= n:
        return targets
    out = []
    for i in range(n):
        idx = round(i * (len(targets) - 1) / (n - 1))
        out.append(targets[idx])
    return sorted(set(out))
