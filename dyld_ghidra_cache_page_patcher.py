#!/usr/bin/env python3
import argparse
import json
import struct
import subprocess
from pathlib import Path
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

PAGE = 0x4000

MH_MAGIC_64 = 0xfeedfacf
LC_SEGMENT_64 = 0x19
S_ATTR_PURE_INSTRUCTIONS = 0x80000000
S_ATTR_SOME_INSTRUCTIONS = 0x00000400

JAVA_SCRIPT_NAME = "AddDyldTargetedCachePages.java"

def u32(b, o): return struct.unpack_from("<I", b, o)[0]
def u64(b, o): return struct.unpack_from("<Q", b, o)[0]
def i32(b, o): return struct.unpack_from("<i", b, o)[0]

def sx(v, bits):
    sign = 1 << (bits - 1)
    return (v ^ sign) - sign

def run(cmd):
    print("+", " ".join(map(str, cmd)))
    p = subprocess.run(cmd, text=True)
    if p.returncode != 0:
        raise SystemExit(p.returncode)

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

def in_segments(va, segments):
    return any(s["start"] <= va < s["end"] for s in segments)

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

def direct_branch_targets_from_bytes(data, va0):
    size = len(data) & ~3
    for rel in range(0, size, 4):
        insn = u32(data, rel)

        if (insn & 0xfc000000) == 0x94000000:
            kind = "bl"
        elif (insn & 0x7c000000) == 0x14000000:
            kind = "b"
        else:
            continue

        imm26 = insn & 0x03ffffff
        src = va0 + rel
        dst = (src + (sx(imm26, 26) << 2)) & 0xffffffffffffffff
        yield kind, src, dst

def reg_rd(insn):
    return insn & 0x1f

def reg_rn(insn):
    return (insn >> 5) & 0x1f

def is_adrp(insn):
    return (insn & 0x9f000000) == 0x90000000

def is_add_immediate_64(insn):
    return (insn & 0xffc00000) == 0x91000000

def is_ldr_unsigned_64(insn):
    return (insn & 0xffc00000) == 0xf9400000

def is_br_reg(insn):
    return (insn & 0xfffffc1f) == 0xd61f0000

def is_blr_reg(insn):
    return (insn & 0xfffffc1f) == 0xd63f0000

def is_ret(insn):
    return (insn & 0xfffffc1f) == 0xd65f0000

def is_brk(insn):
    return (insn & 0xffe0001f) == 0xd4200000

def is_pac_hint(insn):
    return insn in {
        0xd503233f,  # paciasp
        0xd503237f,  # pacibsp
        0xd50323bf,  # autiasp
        0xd50323ff,  # autibsp
    }

def is_common_frame_setup(insn):
    # stp x29, x30, [sp, #-imm]!
    return (insn & 0xffc003ff) == 0xa98003fd

def adrp_target(insn, pc):
    immlo = (insn >> 29) & 0x3
    immhi = (insn >> 5) & 0x7ffff
    imm = sx((immhi << 2) | immlo, 21) << 12
    return (pc & ~0xfff) + imm

def add_immediate_value(insn):
    imm = (insn >> 10) & 0xfff
    if ((insn >> 22) & 1) != 0:
        imm <<= 12
    return imm

def ldr_unsigned_64_offset(insn):
    return ((insn >> 10) & 0xfff) * 8

def is_direct_b(insn):
    return (insn & 0x7c000000) == 0x14000000

def is_direct_bl(insn):
    return (insn & 0xfc000000) == 0x94000000

def is_direct_b_only(insn):
    return is_direct_b(insn) and not is_direct_bl(insn)

def count_stub_windows(insns):
    indirect_sliding = 0
    indirect_aligned = 0
    direct_sliding = 0
    direct_aligned = 0

    def classify_stub_start(i):
        if i + 2 >= len(insns):
            return None

        a = insns[i]
        b = insns[i + 1]
        c = insns[i + 2]
        d = insns[i + 3] if i + 3 < len(insns) else 0

        if not is_adrp(a):
            return None

        stub_reg = reg_rd(a)

        if not (is_add_immediate_64(b) or is_ldr_unsigned_64(b)):
            return None

        if reg_rd(b) != stub_reg or reg_rn(b) != stub_reg:
            return None

        if stub_reg in (16, 17) and is_br_reg(c) and reg_rn(c) == stub_reg:
            return "indirect"

        if is_direct_b_only(c) and is_brk(d):
            return "direct"

        return None

    for i in range(0, max(0, len(insns) - 2)):
        kind = classify_stub_start(i)
        if kind == "indirect":
            indirect_sliding += 1
        elif kind == "direct":
            direct_sliding += 1

    for i in range(0, max(0, len(insns) - 2), 4):
        kind = classify_stub_start(i)
        if kind == "indirect":
            indirect_aligned += 1
        elif kind == "direct":
            direct_aligned += 1

    return indirect_sliding, indirect_aligned, direct_sliding, direct_aligned

def classify_exec_page_locally(data):
    size = len(data) & ~3
    insns = [u32(data, off) for off in range(0, size, 4)]
    insn_count = len(insns)

    counts = {
        "insn_count": insn_count,
        "zero_words": 0,
        "adrp": 0,
        "add_imm_64": 0,
        "ldr_unsigned_64": 0,
        "br_reg": 0,
        "blr_reg": 0,
        "ret": 0,
        "brk": 0,
        "direct_b": 0,
        "direct_bl": 0,
        "pac_hint": 0,
        "frame_setup": 0,
    }

    for insn in insns:
        if insn == 0:
            counts["zero_words"] += 1
        if is_adrp(insn):
            counts["adrp"] += 1
        if is_add_immediate_64(insn):
            counts["add_imm_64"] += 1
        if is_ldr_unsigned_64(insn):
            counts["ldr_unsigned_64"] += 1
        if is_br_reg(insn):
            counts["br_reg"] += 1
        if is_blr_reg(insn):
            counts["blr_reg"] += 1
        if is_ret(insn):
            counts["ret"] += 1
        if is_brk(insn):
            counts["brk"] += 1
        if is_direct_bl(insn):
            counts["direct_bl"] += 1
        elif is_direct_b(insn):
            counts["direct_b"] += 1
        if is_pac_hint(insn):
            counts["pac_hint"] += 1
        if is_common_frame_setup(insn):
            counts["frame_setup"] += 1

    (
        indirect_stub_windows,
        aligned_indirect_stub_windows,
        direct_stub_windows,
        aligned_direct_stub_windows,
    ) = count_stub_windows(insns)
    counts["stub_windows"] = indirect_stub_windows
    counts["aligned_stub_windows"] = aligned_indirect_stub_windows
    counts["direct_stub_windows"] = direct_stub_windows
    counts["aligned_direct_stub_windows"] = aligned_direct_stub_windows

    normal_code_signals = (
        counts["direct_b"] +
        counts["direct_bl"] +
        counts["ret"] +
        counts["blr_reg"] +
        counts["pac_hint"] +
        counts["frame_setup"]
    )
    non_branch_normal_signals = (
        counts["direct_bl"] +
        counts["ret"] +
        counts["blr_reg"] +
        counts["pac_hint"] +
        counts["frame_setup"]
    )

    # dyld stub pages are dense islands of adrp/add-or-ldr/br slots, commonly
    # padded with brk. Some dyld stub islands use direct b instead of br; accept
    # those only when the page is densely made of the same adrp/add/b/brk slots.
    if (
        indirect_stub_windows >= 64
        and counts["br_reg"] >= 64
        and indirect_stub_windows >= max(64, normal_code_signals * 4)
        and counts["direct_bl"] <= 16
        and counts["ret"] <= 8
    ):
        classification = "stub_like_page"
        confidence = "high"
        reason = (
            f"local indirect stub density: stub_windows={indirect_stub_windows}, "
            f"br_reg={counts['br_reg']}, normal_signals={normal_code_signals}"
        )
    elif (
        direct_stub_windows >= 64
        and direct_stub_windows >= max(64, non_branch_normal_signals * 4)
        and counts["direct_bl"] <= 16
        and counts["ret"] <= 16
        and counts["frame_setup"] <= 4
    ):
        classification = "stub_like_page"
        confidence = "high"
        reason = (
            f"local direct-branch stub density: direct_stub_windows={direct_stub_windows}, "
            f"direct_b={counts['direct_b']}, non_branch_normal_signals={non_branch_normal_signals}"
        )
    elif (
        counts["direct_bl"] >= 16
        or counts["direct_b"] >= 32
        or counts["ret"] >= 4
        or counts["frame_setup"] >= 2
        or counts["pac_hint"] >= 8
    ):
        classification = "normal_code_like_page"
        confidence = "high"
        reason = (
            f"local normal-code signals: direct_b={counts['direct_b']}, "
            f"direct_bl={counts['direct_bl']}, ret={counts['ret']}, "
            f"frame_setup={counts['frame_setup']}, pac_hint={counts['pac_hint']}"
        )
    else:
        classification = "unknown_exec_page"
        confidence = "low"
        reason = (
            f"insufficient local signal: stub_windows={indirect_stub_windows}, "
            f"direct_stub_windows={direct_stub_windows}, "
            f"br_reg={counts['br_reg']}, normal_signals={normal_code_signals}"
        )

    return {
        "classification": classification,
        "confidence": confidence,
        "reason": reason,
        "features": counts,
    }

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

def indirect_stub_targets_from_bytes(data, va0, mappings):
    size = len(data) & ~3
    insns = [u32(data, off) for off in range(0, size, 4)]

    for i in range(0, max(0, len(insns) - 2), 4):
        a = insns[i]
        b = insns[i + 1]
        c = insns[i + 2]
        src = va0 + i * 4

        if not is_adrp(a):
            continue

        stub_reg = reg_rd(a)
        if stub_reg not in (16, 17):
            continue

        if not is_br_reg(c) or reg_rn(c) != stub_reg:
            continue

        base = adrp_target(a, src)

        if is_add_immediate_64(b) and reg_rd(b) == stub_reg and reg_rn(b) == stub_reg:
            yield {
                "kind": "adrp_add_br",
                "src": src,
                "dst": base + add_immediate_value(b),
            }
            continue

        if is_ldr_unsigned_64(b) and reg_rd(b) == stub_reg and reg_rn(b) == stub_reg:
            ptr_va = base + ldr_unsigned_64_offset(b)
            ptr = read_u64_from_cache_va(mappings, ptr_va)
            if ptr is not None:
                yield {
                    "kind": "adrp_ldr_br",
                    "src": src,
                    "dst": ptr,
                    "pointer": ptr_va,
                }
            continue

def scan_image_direct_external_targets(image, mappings):
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

def is_high_confidence_stub(local_info):
    return (
        local_info["classification"] == "stub_like_page"
        and local_info.get("confidence") == "high"
    )

def patch_decision(args, local_info, discovery_round):
    mode = args.find_mode
    grow_rounds = args.grow_rounds
    local_classification = local_info["classification"]
    confidence = local_info.get("confidence", "unknown")

    if mode == "fix":
        if is_high_confidence_stub(local_info):
            return True, (
                "fix mode accepts high-confidence local stub_like_page "
                "for Ghidra missing-flow repair"
            )
        return False, (
            f"fix mode rejects local {local_classification} "
            f"confidence={confidence}"
        )

    if mode == "grow":
        if discovery_round <= grow_rounds:
            return True, (
                f"grow mode accepts executable direct-flow page through "
                f"round {grow_rounds}: local {local_classification} "
                f"confidence={confidence}"
            )

        if is_high_confidence_stub(local_info):
            return True, (
                f"grow mode post-round-{grow_rounds} closure accepts "
                "high-confidence local stub_like_page"
            )

        return False, (
            f"grow mode post-round-{grow_rounds} closure rejects local "
            f"{local_classification} confidence={confidence}"
        )

    raise ValueError(mode)

def summarize_page_class(local_info, sample_addresses, args, discovery_round):
    local_classification = local_info["classification"]
    do_patch, decision_reason = patch_decision(args, local_info, discovery_round)

    return {
        "classification": local_classification,
        "local_classification": local_classification,
        "confidence": local_info["confidence"],
        "local_reason": local_info["reason"],
        "local_features": local_info["features"],
        "patch": do_patch,
        "patch_reason": decision_reason,
        "samples": [{"addr": f"0x{addr:x}"} for addr in sample_addresses],
    }

def classify_one_page(item, args, discovery_round):
    key, targets = item
    cache_basename, cache_file, mstart, mend, mfileoff, maxprot, initprot, page = key
    cm_for_page = {
        "cache_basename": cache_basename,
        "cache_file": cache_file,
        "start": mstart,
        "end": mend,
        "fileoff": mfileoff,
        "maxprot": maxprot,
        "initprot": initprot,
        "execute": bool((maxprot | initprot) & 4),
    }

    blob = read_page(cm_for_page, page)
    local_info = classify_exec_page_locally(blob)

    samples = choose_samples(targets, args.samples)
    return key, summarize_page_class(local_info, samples, args, discovery_round)

def classify_pages(page_to_targets, args, discovery_round):
    items = sorted(page_to_targets.items(), key=lambda kv: kv[0][-1])
    total = len(items)
    page_class = {}

    jobs = max(1, int(getattr(args, "jobs", 1)))

    if total == 0:
        return page_class

    print(
        f"    classifying {total} pages for discovery_round={discovery_round} "
        f"with jobs={jobs}, samples={args.samples}",
        flush=True,
    )

    if jobs == 1:
        counts = defaultdict(int)
        for i, item in enumerate(items, 1):
            key, info = classify_one_page(item, args, discovery_round)
            page_class[key] = info
            counts[info["classification"]] += 1
            print(
                f"      [{i:4d}/{total:4d}] 0x{key[-1]:x} "
                f"{info['classification']} confidence={info['confidence']} "
                f"patch={info['patch']}",
                flush=True,
            )

        print("    classification summary:", flush=True)
        for cls, count in sorted(counts.items()):
            print(f"      {cls:32s} {count}", flush=True)

        return page_class

    done = 0
    counts = defaultdict(int)

    with ThreadPoolExecutor(max_workers=jobs) as ex:
        futures = [ex.submit(classify_one_page, item, args, discovery_round) for item in items]

        for fut in as_completed(futures):
            key, info = fut.result()
            page_class[key] = info
            done += 1
            counts[info["classification"]] += 1

            print(
                f"      [{done:4d}/{total:4d}] 0x{key[-1]:x} "
                f"{info['classification']} confidence={info['confidence']} "
                f"patch={info['patch']}",
                flush=True,
            )

    print("    classification summary:", flush=True)
    for cls, count in sorted(counts.items()):
        print(f"      {cls:32s} {count}", flush=True)

    return page_class

def enforce_max_pages_fuse(args, accepted, context):
    max_pages = int(getattr(args, "max_pages", 0) or 0)
    if max_pages > 0 and len(accepted) > max_pages:
        raise SystemExit(
            f"--max-pages emergency fuse tripped during {context}: "
            f"{len(accepted)} patch pages exceeds limit {max_pages}. "
            "Raise --max-pages intentionally or narrow the find mode."
        )

def collect_pages(args):
    mappings = parse_cache_mappings(args.cache_dir)

    print(
        f"[+] find mode: {args.find_mode} "
        f"(grow_rounds={args.grow_rounds})",
        flush=True,
    )

    print("[+] scanning image direct b/bl targets...", flush=True)
    hits, unknown = scan_image_direct_external_targets(args.image, mappings)

    initial_page_to_targets = defaultdict(set)
    examples_by_page = defaultdict(list)

    for kind, src, dst, cm in hits:
        page = dst & ~(PAGE - 1)
        key = page_key_from_mapping(cm, page)
        initial_page_to_targets[key].add(dst)
        if len(examples_by_page[key]) < 8:
            examples_by_page[key].append({"kind": kind, "src": f"0x{src:x}", "dst": f"0x{dst:x}"})

    print(f"    external executable cache refs: {len(hits)}", flush=True)
    print(f"    initial target pages: {len(initial_page_to_targets)}", flush=True)
    print(f"    unknown non-cache targets: {len(unknown)}", flush=True)

    print("[+] round 0: classifying direct image target pages...", flush=True)
    page_info = classify_pages(initial_page_to_targets, args, 0)

    accepted = {k for k, info in page_info.items() if info["patch"]}
    rejected = {k for k, info in page_info.items() if not info["patch"]}
    enforce_max_pages_fuse(args, accepted, "round 0")

    discovery_round = {}
    parent_edge = {}

    for k in page_info:
        discovery_round[k] = 0
        parent_edge[k] = {
            "parent_page": None,
            "trigger_src": None,
            "trigger_dst": None,
            "reason": "direct image b/bl target",
        }

    def print_round_summary(round_label, keys):
        by_cls = defaultdict(int)
        patched = 0
        report_only = 0

        for k in keys:
            info = page_info[k]
            by_cls[info["classification"]] += 1
            if info["patch"]:
                patched += 1
            else:
                report_only += 1

        print(f"[+] {round_label} summary:", flush=True)
        print(f"    pages: {len(keys)}", flush=True)
        print(f"    patch: {patched}", flush=True)
        print(f"    report_only: {report_only}", flush=True)
        for cls, count in sorted(by_cls.items()):
            print(f"    {cls:32s} {count}", flush=True)

    print_round_summary("round 0", list(page_info.keys()))

    print("[+] recursively scanning accepted pages...", flush=True)

    current_round_pages = sorted(accepted, key=lambda k: k[-1])
    scanned = set()
    round_no = 1

    while current_round_pages:
        print(f"[+] recursive round {round_no}: scanning {len(current_round_pages)} parent pages", flush=True)

        next_page_to_targets = defaultdict(set)
        next_examples = defaultdict(list)
        next_parent_edge = {}

        scanned_this_round = 0
        total_to_scan = len(current_round_pages)

        for key in current_round_pages:
            scanned_this_round += 1

            if key in scanned:
                print(
                    f"    scan [{scanned_this_round:4d}/{total_to_scan:4d}] "
                    f"0x{key[-1]:x} already scanned",
                    flush=True,
                )
                continue

            scanned.add(key)

            cache_basename, cache_file, mstart, mend, mfileoff, maxprot, initprot, page = key
            cm_for_page = {
                "cache_basename": cache_basename,
                "cache_file": cache_file,
                "start": mstart,
                "end": mend,
                "fileoff": mfileoff,
                "maxprot": maxprot,
                "initprot": initprot,
                "execute": bool((maxprot | initprot) & 4),
            }

            blob = read_page(cm_for_page, page)

            new_from_this_parent = 0
            direct_branches_from_parent = 0

            for kind, src, dst in direct_branch_targets_from_bytes(blob, page):
                direct_branches_from_parent += 1

                cm = find_mapping(dst, mappings)
                if cm is None or not cm["execute"]:
                    continue

                dst_page = dst & ~(PAGE - 1)
                dst_key = page_key_from_mapping(cm, dst_page)

                if dst_key in page_info or dst_key in next_page_to_targets:
                    if len(next_examples[dst_key]) < 8:
                        next_examples[dst_key].append({"kind": kind, "src": f"0x{src:x}", "dst": f"0x{dst:x}"})
                    continue

                new_from_this_parent += 1
                next_page_to_targets[dst_key].add(dst)
                next_parent_edge[dst_key] = {
                    "parent_page": f"0x{page:x}",
                    "trigger_src": f"0x{src:x}",
                    "trigger_dst": f"0x{dst:x}",
                    "reason": f"recursive round {round_no} {kind}",
                }

                if len(next_examples[dst_key]) < 8:
                    next_examples[dst_key].append({"kind": kind, "src": f"0x{src:x}", "dst": f"0x{dst:x}"})

            print(
                f"    scan [{scanned_this_round:4d}/{total_to_scan:4d}] "
                f"0x{page:x} branches={direct_branches_from_parent} "
                f"new_candidate_pages={new_from_this_parent}",
                flush=True,
            )

        print(
            f"[+] recursive round {round_no}: discovered "
            f"{len(next_page_to_targets)} new candidate pages",
            flush=True,
        )

        if not next_page_to_targets:
            print(f"[+] recursive round {round_no}: no new pages; recursion is stable", flush=True)
            break

        print(f"[+] recursive round {round_no}: classifying new candidate pages...", flush=True)
        new_info = classify_pages(next_page_to_targets, args, round_no)

        round_keys = []
        round_accepted = []
        round_rejected = []

        for nk, ni in new_info.items():
            page_info[nk] = ni
            examples_by_page[nk].extend(next_examples[nk])
            discovery_round[nk] = round_no
            parent_edge[nk] = next_parent_edge.get(nk, {
                "parent_page": None,
                "trigger_src": None,
                "trigger_dst": None,
                "reason": f"recursive round {round_no}",
            })

            round_keys.append(nk)

            if ni["patch"]:
                accepted.add(nk)
                round_accepted.append(nk)
            else:
                rejected.add(nk)
                round_rejected.append(nk)

        enforce_max_pages_fuse(args, accepted, f"recursive round {round_no}")

        print_round_summary(f"recursive round {round_no}", round_keys)

        print(
            f"[+] recursive round {round_no}: accepted {len(round_accepted)} pages, "
            f"report_only {len(round_rejected)} pages",
            flush=True,
        )

        current_round_pages = sorted(round_accepted, key=lambda k: k[-1])
        round_no += 1

    for k, info in page_info.items():
        info["discovery_round"] = discovery_round.get(k, -1)
        info["parent_edge"] = parent_edge.get(k, {
            "parent_page": None,
            "trigger_src": None,
            "trigger_dst": None,
            "reason": "unknown",
        })

    print("[+] recursive scan complete", flush=True)
    print(f"    final accepted pages: {len(accepted)}", flush=True)
    print(f"    final report-only pages: {len(rejected)}", flush=True)
    print(f"    scanned pages: {len(scanned)}", flush=True)

    by_round = defaultdict(lambda: {"patch": 0, "report_only": 0})
    for k, info in page_info.items():
        r = info.get("discovery_round", -1)
        if info["patch"]:
            by_round[r]["patch"] += 1
        else:
            by_round[r]["report_only"] += 1

    print("[+] growth by discovery round:", flush=True)
    for r in sorted(by_round):
        print(
            f"    round {r}: patch={by_round[r]['patch']} "
            f"report_only={by_round[r]['report_only']}",
            flush=True,
        )

    return mappings, page_info, accepted, rejected, examples_by_page, unknown

def add_page_placeholder(rows, page, source, kind, cm, info, reason):
    rows.setdefault(page, {
        "start": f"0x{page:x}",
        "size": f"0x{PAGE:x}",
        "source": source,
        "kind": kind,
        "cache_file": cm["cache_basename"],
        "cache_path": cm["cache_file"],
        "file_offset": f"0x{cm['fileoff'] + (page - cm['start']):x}",
        "mapping_start": f"0x{cm['start']:x}",
        "mapping_end": f"0x{cm['end']:x}",
        "target_classification": info["local_classification"] if info else "not_classified",
        "target_confidence": info["confidence"] if info else "unknown",
        "reason": reason,
    })

def write_outputs(args, mappings, page_info, accepted, rejected, examples_by_page, unknown):
    outdir = Path(args.outdir)
    pages_dir = outdir / "page_slices"
    outdir.mkdir(parents=True, exist_ok=True)
    pages_dir.mkdir(parents=True, exist_ok=True)

    page_rows = []
    accepted_pages = {key[-1] for key in accepted}
    page_by_addr = {key[-1]: (key, info) for key, info in page_info.items()}
    placeholder_rows_by_target = {}
    placeholder_rows_by_page = {}

    for key, info in sorted(page_info.items(), key=lambda kv: kv[0][-1]):
        cache_basename, cache_file, mstart, mend, mfileoff, maxprot, initprot, page = key

        status = "patch" if key in accepted else "report_only"
        page_fileoff = mfileoff + (page - mstart)

        out_path = ""
        if key in accepted:
            cm = {
                "cache_basename": cache_basename,
                "cache_file": cache_file,
                "start": mstart,
                "end": mend,
                "fileoff": mfileoff,
                "maxprot": maxprot,
                "initprot": initprot,
                "execute": bool((maxprot | initprot) & 4),
            }

            blob = read_page(cm, page)
            out = pages_dir / f"{cache_basename}_page_0x{page:x}.bin"
            if not out.exists() or out.stat().st_size != PAGE:
                out.write_bytes(blob)
            out_path = str(out)

        tag = cache_basename.replace("dyld_shared_cache_arm64e.", "dsc")
        tag = tag.replace("dyld_shared_cache_arm64e", "dsc_main")

        page_rows.append({
            "status": status,
            "tag": tag,
            "start": f"0x{page:x}",
            "size": f"0x{PAGE:x}",
            "path": out_path,
            "cache_file": cache_basename,
            "cache_path": cache_file,
            "file_offset": f"0x{page_fileoff:x}",
            "mapping_start": f"0x{mstart:x}",
            "mapping_end": f"0x{mend:x}",
            "mapping_fileoff": f"0x{mfileoff:x}",
            "classification": info["classification"],
            "local_classification": info["local_classification"],
            "confidence": info["confidence"],
            "local_reason": info["local_reason"],
            "local_features": info["local_features"],
            "patch_decision": status,
            "patch_reason": info["patch_reason"],
            "examples": examples_by_page.get(key, []),
            "samples": info["samples"],
            "discovery_round": info.get("discovery_round", -1),
            "parent_edge": info.get("parent_edge", {}),
        })

        if key in accepted:
            cm = {
                "cache_basename": cache_basename,
                "cache_file": cache_file,
                "start": mstart,
                "end": mend,
                "fileoff": mfileoff,
                "maxprot": maxprot,
                "initprot": initprot,
                "execute": bool((maxprot | initprot) & 4),
            }
            blob = read_page(cm, page)

            for kind, src, dst in direct_branch_targets_from_bytes(blob, page):
                dst_page = dst & ~(PAGE - 1)
                if dst_page in accepted_pages:
                    continue

                dst_page_info = page_by_addr.get(dst_page)
                if dst_page_info is None:
                    continue

                _, dst_info = dst_page_info
                placeholder_rows_by_target.setdefault(dst, {
                    "target": f"0x{dst:x}",
                    "target_page": f"0x{dst_page:x}",
                    "source": f"0x{src:x}",
                    "kind": kind,
                    "target_classification": dst_info["local_classification"],
                    "target_confidence": dst_info["confidence"],
                    "reason": (
                        "non-executable placeholder for rejected direct-flow target; "
                        "keeps Ghidra operands assigned without importing dependency bytes"
                    ),
                })

            for target in indirect_stub_targets_from_bytes(blob, page, mappings):
                dst = target["dst"]
                cm = find_mapping(dst, mappings)
                if cm is None or not cm["execute"]:
                    continue

                dst_page = dst & ~(PAGE - 1)
                if dst_page in accepted_pages:
                    continue

                dst_page_info = page_by_addr.get(dst_page)
                info = dst_page_info[1] if dst_page_info else None
                add_page_placeholder(
                    placeholder_rows_by_page,
                    dst_page,
                    f"0x{target['src']:x}",
                    target["kind"],
                    cm,
                    info,
                    (
                        "non-executable placeholder page for indirect stub target; "
                        "keeps Ghidra thunk targets assigned without importing dependency bytes"
                    ),
                )

        elif key in rejected:
            cm = {
                "cache_basename": cache_basename,
                "cache_file": cache_file,
                "start": mstart,
                "end": mend,
                "fileoff": mfileoff,
                "maxprot": maxprot,
                "initprot": initprot,
                "execute": bool((maxprot | initprot) & 4),
            }
            add_page_placeholder(
                placeholder_rows_by_page,
                page,
                "",
                "rejected_page",
                cm,
                info,
                (
                    "non-executable placeholder page for rejected direct-flow target page; "
                    "keeps Ghidra operands assigned without importing dependency bytes"
                ),
            )

    patch_tsv = outdir / "targeted_cache_pages.tsv"
    with patch_tsv.open("w") as f:
        f.write(
            "tag\tstart\tsize\tpath\tclassification\t"
            "cache_file\tmapping_start\tmapping_end\tdiscovery_round\t"
            "local_classification\tconfidence\tfile_offset\tpatch_reason\n"
        )
        for r in page_rows:
            if r["status"] != "patch":
                continue
            f.write(
                f"{r['tag']}\t{r['start']}\t{r['size']}\t{r['path']}\t"
                f"{r['classification']}\t"
                f"{r['cache_file']}\t{r['mapping_start']}\t{r['mapping_end']}\t"
                f"{r.get('discovery_round', -1)}\t{r['local_classification']}\t"
                f"{r['confidence']}\t{r['file_offset']}\t{r['patch_reason']}\n"
            )

    placeholders_tsv = outdir / "external_target_placeholders.tsv"
    with placeholders_tsv.open("w") as f:
        f.write(
            "target\tsize\ttarget_page\tsource\tkind\ttarget_classification\t"
            "target_confidence\treason\n"
        )
        for _, r in sorted(placeholder_rows_by_target.items()):
            f.write(
                f"{r['target']}\t0x4\t{r['target_page']}\t{r['source']}\t{r['kind']}\t"
                f"{r['target_classification']}\t{r['target_confidence']}\t{r['reason']}\n"
            )

    placeholder_pages_tsv = outdir / "external_page_placeholders.tsv"
    with placeholder_pages_tsv.open("w") as f:
        f.write(
            "start\tsize\tsource\tkind\tcache_file\tfile_offset\tmapping_start\t"
            "mapping_end\ttarget_classification\ttarget_confidence\treason\n"
        )
        for _, r in sorted(placeholder_rows_by_page.items()):
            f.write(
                f"{r['start']}\t{r['size']}\t{r['source']}\t{r['kind']}\t"
                f"{r['cache_file']}\t{r['file_offset']}\t{r['mapping_start']}\t"
                f"{r['mapping_end']}\t{r['target_classification']}\t"
                f"{r['target_confidence']}\t{r['reason']}\n"
            )

    mappings_tsv = outdir / "dyld_cache_mappings.tsv"
    with mappings_tsv.open("w") as f:
        f.write("cache_file\tcache_path\tstart\tend\tfile_offset\tmaxprot\tinitprot\texecute\n")
        for m in mappings:
            f.write(
                f"{m['cache_basename']}\t{m['cache_file']}\t"
                f"0x{m['start']:x}\t0x{m['end']:x}\t0x{m['fileoff']:x}\t"
                f"0x{m['maxprot']:x}\t0x{m['initprot']:x}\t{int(m['execute'])}\n"
            )

    report_json = outdir / "cache_page_report.json"
    report_json.write_text(json.dumps({
        "mode": args.find_mode,
        "grow_rounds": args.grow_rounds,
        "recursive": True,
        "image": str(args.image),
        "cache_dir": str(args.cache_dir),
        "patch_page_count": sum(1 for r in page_rows if r["status"] == "patch"),
        "report_only_page_count": sum(1 for r in page_rows if r["status"] == "report_only"),
        "external_placeholder_count": len(placeholder_rows_by_target),
        "external_placeholders": list(sorted(placeholder_rows_by_target.values(), key=lambda r: r["target"])),
        "external_page_placeholder_count": len(placeholder_rows_by_page),
        "external_page_placeholders": list(sorted(placeholder_rows_by_page.values(), key=lambda r: r["start"])),
        "pages": page_rows,
        "unknown_non_cache_targets": [
            {"kind": k, "src": f"0x{s:x}", "dst": f"0x{d:x}"}
            for k, s, d in unknown
        ],
    }, indent=2))

    report_tsv = outdir / "cache_page_report.tsv"
    with report_tsv.open("w") as f:
        f.write(
            "status\tdiscovery_round\tlocal_classification\tconfidence\tpage\tcache_file\t"
            "file_offset\tpatch_reason\tlocal_reason\n"
        )
        for r in page_rows:
            f.write(
                f"{r['status']}\t{r.get('discovery_round', -1)}\t"
                f"{r['local_classification']}\t{r['confidence']}\t"
                f"{r['start']}\t{r['cache_file']}\t"
                f"{r['file_offset']}\t{r['patch_reason']}\t{r['local_reason']}\n"
            )

    print()
    print("[+] wrote:")
    print("   patch tsv:  ", patch_tsv)
    print("   placeholders:", placeholders_tsv)
    print("   page placeholders:", placeholder_pages_tsv)
    print("   cache mappings:", mappings_tsv)
    print("   report json:", report_json)
    print("   report tsv: ", report_tsv)
    print("   pages dir:  ", pages_dir)

    by_status_cls = defaultdict(int)
    for r in page_rows:
        by_status_cls[(r["status"], r["classification"])] += 1

    print()
    print("[+] page summary:")
    for (status, cls), count in sorted(by_status_cls.items()):
        print(f"   {status:11s} {cls:32s} {count}")

    return patch_tsv

def write_java_script(script_dir, tsv_path):
    script_dir = Path(script_dir)
    script_dir.mkdir(parents=True, exist_ok=True)

    script = script_dir / JAVA_SCRIPT_NAME

    script.write_text(f'''import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;

public class AddDyldTargetedCachePages extends GhidraScript {{
    private static final long PAGE = 0x4000L;
    private static final long CANONICAL_VA_MASK = 0x0000ffffffffffffL;

    private static class CacheMapping {{
        String cacheFile;
        long start;
        long end;
        boolean execute;

        CacheMapping(String cacheFile, long start, long end, boolean execute) {{
            this.cacheFile = cacheFile;
            this.start = start;
            this.end = end;
            this.execute = execute;
        }}
    }}

    private long parseHexLong(String s) {{
        s = s.trim();
        if (s.startsWith("0x") || s.startsWith("0X")) {{
            return Long.parseUnsignedLong(s.substring(2), 16);
        }}
        return Long.parseUnsignedLong(s, 16);
    }}

    private List<CacheMapping> readCacheMappings(File mappingsFile) throws Exception {{
        List<CacheMapping> mappings = new ArrayList<CacheMapping>();
        if (!mappingsFile.isFile()) {{
            return mappings;
        }}

        BufferedReader br = new BufferedReader(new FileReader(mappingsFile));
        try {{
            br.readLine();
            String line;
            while ((line = br.readLine()) != null) {{
                line = line.trim();
                if (line.length() == 0) {{
                    continue;
                }}

                String[] parts = line.split("\\t");
                if (parts.length < 8) {{
                    continue;
                }}

                mappings.add(new CacheMapping(
                    parts[0],
                    parseHexLong(parts[2]),
                    parseHexLong(parts[3]),
                    "1".equals(parts[7]) || "true".equalsIgnoreCase(parts[7])
                ));
            }}
        }}
        finally {{
            br.close();
        }}

        return mappings;
    }}

    private CacheMapping findMapping(List<CacheMapping> mappings, long va) {{
        for (CacheMapping m : mappings) {{
            if (va >= m.start && va < m.end) {{
                return m;
            }}
        }}
        return null;
    }}

    private long canonicalizeFlowTarget(List<CacheMapping> mappings, long raw) {{
        if (findMapping(mappings, raw) != null) {{
            return raw;
        }}

        long masked = raw & CANONICAL_VA_MASK;
        if (masked != raw && findMapping(mappings, masked) != null) {{
            return masked;
        }}

        return raw;
    }}

    private boolean overlapsAnyBlock(Memory memory, Address start, long size) throws Exception {{
        Address end = start.add(size - 1);
        MemoryBlock[] blocks = memory.getBlocks();

        for (MemoryBlock b : blocks) {{
            if (b.getStart().compareTo(end) <= 0 && b.getEnd().compareTo(start) >= 0) {{
                return true;
            }}
        }}

        return false;
    }}

    private MemoryBlock createNoBytePagePlaceholder(Memory memory, long page, String prefix) throws Exception {{
        Address start = toAddr(Long.toHexString(page));
        MemoryBlock block = memory.createUninitializedBlock(
            prefix + Long.toHexString(page),
            start,
            PAGE,
            false
        );

        block.setRead(false);
        block.setWrite(false);
        block.setExecute(false);
        block.setVolatile(true);
        return block;
    }}

    public void run() throws Exception {{
        String tsvPath = "{tsv_path}";
        File tsv = new File(tsvPath);

        if (!tsv.isFile()) {{
            println("ERROR: missing TSV: " + tsvPath);
            return;
        }}

        Memory memory = currentProgram.getMemory();

        int tx = currentProgram.startTransaction("Add targeted dyld cache pages");
        boolean commit = false;

        int total = 0;
        int added = 0;
        int skippedOverlap = 0;
        int skippedBadFile = 0;
        int placeholderTotal = 0;
        int placeholderAdded = 0;
        int placeholderSkippedOverlap = 0;
        int pagePlaceholderTotal = 0;
        int pagePlaceholderAdded = 0;
        int pagePlaceholderSkippedOverlap = 0;
        int flowPlaceholderTotal = 0;
        int flowPlaceholderAdded = 0;
        int flowPlaceholderSkippedOverlap = 0;
        int flowPlaceholderSkippedDuplicate = 0;
        int flowPlaceholderSkippedNonCache = 0;

        try {{
            BufferedReader br = new BufferedReader(new FileReader(tsv));
            try {{
                br.readLine();

                String line;
                while ((line = br.readLine()) != null) {{
                    line = line.trim();
                    if (line.length() == 0) {{
                        continue;
                    }}

                    String[] parts = line.split("\\t");
                    if (parts.length < 4) {{
                        println("Skipping malformed line: " + line);
                        continue;
                    }}

                    total++;

                    String tag = parts[0];
                    long startLong = parseHexLong(parts[1]);
                    long size = parseHexLong(parts[2]);
                    String path = parts[3];
                    String classification = parts.length > 4 ? parts[4] : "unknown";

                    Address start = toAddr(Long.toHexString(startLong));

                    if (overlapsAnyBlock(memory, start, size)) {{
                        skippedOverlap++;
                        continue;
                    }}

                    File file = new File(path);
                    if (!file.isFile() || file.length() != size) {{
                        println("Skipping bad file: " + path);
                        skippedBadFile++;
                        continue;
                    }}

                    FileInputStream fis = new FileInputStream(file);
                    try {{
                        String safeClass = classification.replaceAll("[^A-Za-z0-9_]", "_");
                        String blockName = "__" + tag + "_" + safeClass + "_page_" + Long.toHexString(startLong);

                        MemoryBlock block = memory.createInitializedBlock(
                            blockName,
                            start,
                            fis,
                            size,
                            monitor,
                            false
                        );

                        block.setRead(true);
                        block.setWrite(false);
                        block.setExecute(true);

                        added++;
                    }}
                    finally {{
                        fis.close();
                    }}
                }}
            }}
            finally {{
                br.close();
            }}

            File placeholders = new File(tsv.getParentFile(), "external_target_placeholders.tsv");
            if (placeholders.isFile()) {{
                BufferedReader pr = new BufferedReader(new FileReader(placeholders));
                try {{
                    pr.readLine();

                    String line;
                    while ((line = pr.readLine()) != null) {{
                        line = line.trim();
                        if (line.length() == 0) {{
                            continue;
                        }}

                        String[] parts = line.split("\\t");
                        if (parts.length < 2) {{
                            println("Skipping malformed placeholder line: " + line);
                            continue;
                        }}

                        placeholderTotal++;

                        long targetLong = parseHexLong(parts[0]);
                        long size = parseHexLong(parts[1]);
                        Address target = toAddr(Long.toHexString(targetLong));

                        if (overlapsAnyBlock(memory, target, size)) {{
                            placeholderSkippedOverlap++;
                            continue;
                        }}

                        String blockName = "__dyld_external_placeholder_" + Long.toHexString(targetLong);
                        MemoryBlock block = memory.createUninitializedBlock(
                            blockName,
                            target,
                            size,
                            false
                        );

                        block.setRead(false);
                        block.setWrite(false);
                        block.setExecute(false);
                        block.setVolatile(true);

                        placeholderAdded++;
                    }}
                }}
                finally {{
                    pr.close();
                }}
            }}

            File pagePlaceholders = new File(tsv.getParentFile(), "external_page_placeholders.tsv");
            if (pagePlaceholders.isFile()) {{
                BufferedReader ppr = new BufferedReader(new FileReader(pagePlaceholders));
                try {{
                    ppr.readLine();

                    String line;
                    while ((line = ppr.readLine()) != null) {{
                        line = line.trim();
                        if (line.length() == 0) {{
                            continue;
                        }}

                        String[] parts = line.split("\\t");
                        if (parts.length < 2) {{
                            println("Skipping malformed page placeholder line: " + line);
                            continue;
                        }}

                        pagePlaceholderTotal++;

                        long startLong = parseHexLong(parts[0]);
                        long size = parseHexLong(parts[1]);
                        Address start = toAddr(Long.toHexString(startLong));

                        if (overlapsAnyBlock(memory, start, size)) {{
                            pagePlaceholderSkippedOverlap++;
                            continue;
                        }}

                        String blockName = "__dyld_external_page_placeholder_" + Long.toHexString(startLong);
                        MemoryBlock block = memory.createUninitializedBlock(blockName, start, size, false);
                        block.setRead(false);
                        block.setWrite(false);
                        block.setExecute(false);
                        block.setVolatile(true);

                        pagePlaceholderAdded++;
                    }}
                }}
                finally {{
                    ppr.close();
                }}
            }}

            List<CacheMapping> cacheMappings = readCacheMappings(new File(tsv.getParentFile(), "dyld_cache_mappings.tsv"));
            if (!cacheMappings.isEmpty()) {{
                Set<Long> seenPages = new HashSet<Long>();
                InstructionIterator iit = currentProgram.getListing().getInstructions(true);
                while (iit.hasNext()) {{
                    Instruction instr = iit.next();
                    Address from = instr.getAddress();
                    MemoryBlock fromBlock = memory.getBlock(from);
                    if (fromBlock == null || !fromBlock.isExecute()) {{
                        continue;
                    }}

                    for (Address flow : instr.getFlows()) {{
                        if (flow == null) {{
                            continue;
                        }}

                        AddressSpace space = flow.getAddressSpace();
                        if (space != null && space.isExternalSpace()) {{
                            flowPlaceholderSkippedNonCache++;
                            continue;
                        }}

                        if (memory.getBlock(flow) != null) {{
                            continue;
                        }}

                        long rawTarget = flow.getOffset();
                        long target = canonicalizeFlowTarget(cacheMappings, rawTarget);
                        CacheMapping mapping = findMapping(cacheMappings, target);
                        if (mapping == null) {{
                            flowPlaceholderSkippedNonCache++;
                            continue;
                        }}

                        long page = target & ~(PAGE - 1);
                        flowPlaceholderTotal++;
                        if (seenPages.contains(page)) {{
                            flowPlaceholderSkippedDuplicate++;
                            continue;
                        }}
                        seenPages.add(page);

                        Address start = toAddr(Long.toHexString(page));
                        if (overlapsAnyBlock(memory, start, PAGE)) {{
                            flowPlaceholderSkippedOverlap++;
                            continue;
                        }}

                        createNoBytePagePlaceholder(memory, page, "__dyld_external_flow_placeholder_");
                        flowPlaceholderAdded++;
                    }}
                }}
            }}

            commit = true;
        }}
        finally {{
            currentProgram.endTransaction(tx, commit);
        }}

        println("targeted dyld cache page patch complete");
        println("total page records: " + total);
        println("added pages: " + added);
        println("skipped overlapping existing blocks: " + skippedOverlap);
        println("skipped bad/missing files: " + skippedBadFile);
        println("placeholder records: " + placeholderTotal);
        println("added placeholders: " + placeholderAdded);
        println("skipped overlapping placeholders: " + placeholderSkippedOverlap);
        println("page placeholder records: " + pagePlaceholderTotal);
        println("added page placeholders: " + pagePlaceholderAdded);
        println("skipped overlapping page placeholders: " + pagePlaceholderSkippedOverlap);
        println("flow placeholder candidate pages: " + flowPlaceholderTotal);
        println("added flow placeholders: " + flowPlaceholderAdded);
        println("skipped overlapping flow placeholders: " + flowPlaceholderSkippedOverlap);
        println("skipped duplicate flow placeholders: " + flowPlaceholderSkippedDuplicate);
        println("skipped non-cache flow targets: " + flowPlaceholderSkippedNonCache);
    }}
}}
''')

    return script

def filter_tsv_through_round(tsv, through_round):
    if through_round is None:
        return tsv

    if through_round < 0:
        raise SystemExit("--through-round must be >= 0")

    out = tsv.with_name(f"{tsv.stem}_through_round_{through_round}{tsv.suffix}")

    with tsv.open() as src:
        header = src.readline()
        if not header:
            raise SystemExit(f"empty TSV: {tsv}")

        cols = header.rstrip("\n").split("\t")
        try:
            round_idx = cols.index("discovery_round")
        except ValueError:
            raise SystemExit(
                f"{tsv} has no discovery_round column; rerun find with the current script "
                "before using --through-round"
            )

        kept = 0
        skipped = 0

        with out.open("w") as dst:
            dst.write(header)

            for line in src:
                if not line.strip():
                    continue

                parts = line.rstrip("\n").split("\t")
                if len(parts) <= round_idx:
                    skipped += 1
                    continue

                try:
                    discovered = int(parts[round_idx])
                except ValueError:
                    skipped += 1
                    continue

                if discovered <= through_round:
                    dst.write(line)
                    kept += 1
                else:
                    skipped += 1

    print(
        f"[+] --through-round {through_round}: kept {kept} page records, "
        f"skipped {skipped}; filtered TSV: {out}",
        flush=True,
    )
    return out

def normalize_find_args(args):
    if args.find_mode is None:
        args.find_mode = "fix"

    if args.find_mode == "fix":
        args.grow_rounds = -1
        if args.rounds is not None:
            print("[!] --rounds is ignored for --mode fix", flush=True)
    elif args.find_mode == "grow":
        if args.rounds is None:
            raise SystemExit("--mode grow requires --rounds N")

        if args.rounds < 0:
            raise SystemExit("--rounds must be >= 0")

        args.grow_rounds = args.rounds
    else:
        raise SystemExit(f"unknown find mode: {args.find_mode}")

def mode_find(args):
    normalize_find_args(args)
    mappings, page_info, accepted, rejected, examples_by_page, unknown = collect_pages(args)
    write_outputs(args, mappings, page_info, accepted, rejected, examples_by_page, unknown)

def mode_patch(args):
    outdir = Path(args.outdir)
    tsv = outdir / "targeted_cache_pages.tsv"

    if not tsv.is_file():
        raise SystemExit(f"missing {tsv}; run find first")

    tsv_for_patch = filter_tsv_through_round(tsv, args.through_round)
    script = write_java_script(args.script_dir, tsv_for_patch)

    print("[+] wrote Ghidra script:", script)
    print("[+] patching Ghidra program...")

    cmd = [
        str(args.analyze_headless),
        str(args.project_dir),
        str(args.project_name),
        "-process", args.program,
        "-scriptPath", str(args.script_dir),
        "-postScript", JAVA_SCRIPT_NAME,
        "-noanalysis",
    ]

    run(cmd)

def main():
    ap = argparse.ArgumentParser(
        description="Find and patch targeted dyld cache pages needed by an extracted Mach-O in Ghidra."
    )
    sub = ap.add_subparsers(dest="command", required=True)

    p_find = sub.add_parser(
        "find",
        description=(
            "Find dyld cache pages to add to Ghidra. Use --mode fix for minimal "
            "missing-flow repair, or --mode grow --rounds N for bounded context growth."
        ),
    )
    p_find.add_argument("--image", required=True, type=Path)
    p_find.add_argument("--cache-dir", required=True, type=Path)
    p_find.add_argument("--outdir", required=True, type=Path)
    p_find.add_argument(
        "--mode",
        dest="find_mode",
        choices=["fix", "grow"],
        default=None,
        help=(
            "fix patches only high-confidence stub-like pages until stable; "
            "grow accepts broad executable context through --rounds N, then closes through stubs"
        ),
    )
    p_find.add_argument(
        "--rounds",
        type=int,
        default=None,
        help="number of broad context-growth rounds for --mode grow",
    )
    p_find.add_argument("--samples", type=int, default=5)
    p_find.add_argument("--jobs", type=int, default=1)
    p_find.add_argument("--max-pages", type=int, default=0)
    p_find.set_defaults(func=mode_find)

    p_patch = sub.add_parser("patch")
    p_patch.add_argument("--outdir", required=True, type=Path)
    p_patch.add_argument("--project-dir", required=True, type=Path)
    p_patch.add_argument("--project-name", required=True)
    p_patch.add_argument("--program", required=True)
    p_patch.add_argument("--script-dir", default=Path.home() / "ghidra_scripts", type=Path)
    p_patch.add_argument("--analyze-headless", default=Path("/Applications/Ghidra/support/analyzeHeadless"), type=Path)
    p_patch.add_argument("--through-round", type=int, default=None)
    p_patch.set_defaults(func=mode_patch)

    args = ap.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()
