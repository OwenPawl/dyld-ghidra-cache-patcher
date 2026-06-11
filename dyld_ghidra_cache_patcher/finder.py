import json
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from .arm64 import (
    classify_exec_page_locally,
    direct_branch_targets_from_bytes,
    indirect_stub_targets_from_bytes,
)
from .constants import PAGE
from .dyld_cache import (
    find_mapping,
    page_key_from_mapping,
    parse_cache_mappings,
    read_page,
    read_u64_from_cache_va,
)
from .macho import scan_image_direct_external_targets
from .utils import choose_samples


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
    hits, unknown = scan_image_direct_external_targets(args.image, mappings, find_mapping)

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

            for target in indirect_stub_targets_from_bytes(blob, page, lambda va: read_u64_from_cache_va(mappings, va)):
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
