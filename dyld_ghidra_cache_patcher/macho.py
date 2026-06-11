from pathlib import Path

from .arm64 import direct_branch_targets_from_bytes
from .utils import i32, u32, u64

MH_MAGIC_64 = 0xfeedfacf
LC_SEGMENT_64 = 0x19
S_ATTR_PURE_INSTRUCTIONS = 0x80000000
S_ATTR_SOME_INSTRUCTIONS = 0x00000400


def parse_macho(path):
    data = Path(path).read_bytes()
    if len(data) < 32 or u32(data, 0) != MH_MAGIC_64:
        raise SystemExit(f"not little-endian Mach-O 64: {path}")

    ncmds = u32(data, 16)
    off = 32

    segments = []
    code_ranges = []

    for _ in range(ncmds):
        if off + 8 > len(data):
            raise SystemExit("bad Mach-O: truncated load command")

        cmd = u32(data, off)
        cmdsize = u32(data, off + 4)

        if cmdsize < 8 or off + cmdsize > len(data):
            raise SystemExit("bad Mach-O: invalid load command size")

        if cmd == LC_SEGMENT_64:
            segname = data[off+8:off+24].split(b"\0", 1)[0].decode("utf-8", "replace")
            vmaddr = u64(data, off + 24)
            vmsize = u64(data, off + 32)
            fileoff = u64(data, off + 40)
            filesize = u64(data, off + 48)
            maxprot = i32(data, off + 56)
            initprot = i32(data, off + 60)
            nsects = u32(data, off + 64)

            segments.append({
                "segname": segname,
                "start": vmaddr,
                "end": vmaddr + vmsize,
                "fileoff": fileoff,
                "filesize": filesize,
                "maxprot": maxprot,
                "initprot": initprot,
            })

            sectoff = off + 72
            for i in range(nsects):
                q = sectoff + i * 80
                if q + 80 > off + cmdsize:
                    break

                sectname = data[q:q+16].split(b"\0", 1)[0].decode("utf-8", "replace")
                secseg = data[q+16:q+32].split(b"\0", 1)[0].decode("utf-8", "replace")
                addr = u64(data, q + 32)
                size = u64(data, q + 40)
                secoff = u32(data, q + 48)
                flags = u32(data, q + 68)

                is_code = bool(flags & S_ATTR_PURE_INSTRUCTIONS) or bool(flags & S_ATTR_SOME_INSTRUCTIONS)
                is_exec = bool((maxprot | initprot) & 4)

                if size and secoff < len(data) and (is_code or (is_exec and secseg == "__TEXT")):
                    code_ranges.append({
                        "segname": secseg,
                        "sectname": sectname,
                        "va": addr,
                        "fileoff": secoff,
                        "size": min(size, len(data) - secoff),
                    })

        off += cmdsize

    return data, segments, code_ranges

def in_segments(va, segments):
    return any(s["start"] <= va < s["end"] for s in segments)


def scan_image_direct_external_targets(image, mappings, find_mapping):
    data, segments, code_ranges = parse_macho(image)

    hits = []
    unknown = []

    for r in code_ranges:
        blob = data[r["fileoff"]:r["fileoff"] + r["size"]]
        for kind, src, dst in direct_branch_targets_from_bytes(blob, r["va"]):
            if in_segments(dst, segments):
                continue

            cm = find_mapping(dst, mappings)
            if cm is None:
                unknown.append((kind, src, dst))
                continue

            if not cm["execute"]:
                continue

            hits.append((kind, src, dst, cm))

    return hits, unknown
