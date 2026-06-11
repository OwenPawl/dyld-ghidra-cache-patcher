import argparse
from pathlib import Path

from .finder import collect_pages, write_outputs
from .ghidra import patch_program


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
    patch_program(args)


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
