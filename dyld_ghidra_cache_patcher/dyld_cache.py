import struct
from pathlib import Path

from .constants import PAGE
from .utils import u32


def parse_cache_mappings(cache_dir):
    mappings = []

    for p in sorted(Path(cache_dir).glob("dyld_shared_cache*")):
        if not p.is_file():
            continue

        try:
            with p.open("rb") as f:
                h = f.read(0x400)
        except Exception:
            continue

        if not h.startswith(b"dyld_v"):
            continue

        mapping_offset = u32(h, 0x10)
        mapping_count = u32(h, 0x14)

        with p.open("rb") as f:
            f.seek(mapping_offset)
            for _ in range(mapping_count):
                raw = f.read(32)
                if len(raw) != 32:
                    break

                addr, size, fileoff, maxp, initp = struct.unpack("<QQQII", raw)
                if not size:
                    continue

                mappings.append({
                    "cache_file": str(p),
                    "cache_basename": p.name,
                    "start": addr,
                    "end": addr + size,
                    "size": size,
                    "fileoff": fileoff,
                    "maxprot": maxp,
                    "initprot": initp,
                    "execute": bool((maxp | initp) & 4),
                })

    mappings.sort(key=lambda m: (m["start"], m["end"], m["cache_basename"]))
    return mappings

def find_mapping(va, mappings):
    # Small list, linear scan is fine and easier to trust.
    for m in mappings:
        if m["start"] <= va < m["end"]:
            return m
    return None

def read_u64_from_cache_va(mappings, va):
    cm = find_mapping(va, mappings)
    if cm is None:
        return None

    cache_file = Path(cm["cache_file"])
    file_offset = cm["fileoff"] + (va - cm["start"])

    try:
        with cache_file.open("rb") as f:
            f.seek(file_offset)
            raw = f.read(8)
    except Exception:
        return None

    if len(raw) != 8:
        return None

    return struct.unpack("<Q", raw)[0]

def read_page(cache_mapping, page):
    cache_file = Path(cache_mapping["cache_file"])
    file_offset = cache_mapping["fileoff"] + (page - cache_mapping["start"])

    with cache_file.open("rb") as f:
        f.seek(file_offset)
        data = f.read(PAGE)

    if len(data) != PAGE:
        raise SystemExit(f"short read {cache_file} page 0x{page:x}: got 0x{len(data):x}")

    return data

def page_key_from_mapping(cm, page):
    return (
        cm["cache_basename"],
        cm["cache_file"],
        cm["start"],
        cm["end"],
        cm["fileoff"],
        cm["maxprot"],
        cm["initprot"],
        page,
    )
