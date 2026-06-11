from importlib.resources import files
from pathlib import Path

from .constants import JAVA_SCRIPT_NAME, JAVA_TEMPLATE_NAME
from .utils import run


def write_java_script(script_dir, tsv_path):
    script_dir = Path(script_dir)
    script_dir.mkdir(parents=True, exist_ok=True)

    script = script_dir / JAVA_SCRIPT_NAME
    template = files("dyld_ghidra_cache_patcher.templates").joinpath(JAVA_TEMPLATE_NAME).read_text()
    script.write_text(template.replace("__TSV_PATH__", str(tsv_path)))
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



def patch_program(args):
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
