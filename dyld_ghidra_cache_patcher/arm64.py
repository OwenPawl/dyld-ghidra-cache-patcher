from .utils import sx, u32


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

def indirect_stub_targets_from_bytes(data, va0, read_u64):
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
            ptr = read_u64(ptr_va)
            if ptr is not None:
                yield {
                    "kind": "adrp_ldr_br",
                    "src": src,
                    "dst": ptr,
                    "pointer": ptr_va,
                }
            continue
