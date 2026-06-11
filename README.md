# dyld-ghidra-cache-patcher

Conservative Ghidra repair tooling for Mach-O images extracted from Apple dyld
shared caches.

The common failure this fixes is an extracted image that still contains real
AArch64 direct `b`/`bl` flows to executable dyld shared cache pages outside the
extracted Mach-O. Ghidra then reports errors such as:

```text
Could not follow disassembly flow into non-existing memory
```

This tool finds the small dyld cache pages that are needed to repair those
flows, classifies them locally from bytes, copies only high-confidence stub
pages, and patches them into an existing Ghidra program.

It does not depend on `ipsw`.

## What It Does

- Parses a Mach-O extracted from a dyld shared cache.
- Parses local dyld shared cache and subcache mappings.
- Scans executable Mach-O sections for direct AArch64 `b`/`bl` targets that
  leave the extracted image.
- Classifies 16 KiB executable cache pages locally as:
  - `stub_like_page`
  - `normal_code_like_page`
  - `unknown_exec_page`
- Writes page slices and audit reports.
- Generates and runs a Ghidra Java script that adds selected pages as
  read/execute memory blocks.
- Adds no-byte, non-executable placeholders for external cache targets so
  Ghidra can assign references without importing dependency code.

## What It Does Not Do

- It is not a full dyld shared cache loader.
- It does not reconstruct a self-contained Mach-O.
- It does not import dependency function bodies in `fix` mode.
- It does not recover external type information or Swift/Objective-C metadata.
- Placeholder blocks are address-coverage scaffolding, not real code.

## Requirements

- macOS
- Python 3.9 or newer
- Ghidra, for the `patch` command
- A dyld shared cache directory containing the main cache and subcaches
- A Mach-O image extracted from that cache

`find` uses only the Python standard library and local files. `patch` requires
Ghidra's `analyzeHeadless`.

## Install

Run directly from the checkout:

```sh
./dyld_ghidra_cache_page_patcher.py --help
```

Or install into a virtual environment:

```sh
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install .
dyld-ghidra-cache-patcher --help
```

## Modes

### `fix`

Minimal repair mode. This is the default and the recommended mode for diff
analysis.

`fix` accepts only high-confidence local `stub_like_page` pages and recursively
walks accepted stub pages until no new accepted stub pages are found. It is
designed to repair missing-flow errors without pulling in dependency code.

### `grow --rounds N`

Bounded context expansion mode.

`grow` accepts executable direct-flow pages broadly through round `N`, then
switches back to `fix`-style stub-only closure until stable. Use this only when
you intentionally want more surrounding cache context.

## Example

```sh
ROOT="/Volumes/reSSD/dyld_ios_27_0_24A5355q"

dyld-ghidra-cache-patcher find \
  --mode fix \
  --jobs 8 \
  --samples 4 \
  --image "$ROOT/extract/dyld_enriched/out_full/ShortcutsLanguage" \
  --cache-dir "$ROOT/cache" \
  --outdir "$ROOT/ghidra_missing_cache_patches/ShortcutsLanguage_fix"
```

Patch the discovered pages into a Ghidra program:

```sh
dyld-ghidra-cache-patcher patch \
  --outdir "$ROOT/ghidra_missing_cache_patches/ShortcutsLanguage_fix" \
  --project-dir "$ROOT/Ghidra" \
  --project-name "iOS27_Shortcuts_Dyld_Test" \
  --program "ShortcutsLanguage"
```

Grow one broad round, then close through stubs:

```sh
dyld-ghidra-cache-patcher find \
  --mode grow \
  --rounds 1 \
  --jobs 8 \
  --samples 4 \
  --image "$ROOT/extract/dyld_enriched/out_full/ShortcutsLanguage" \
  --cache-dir "$ROOT/cache" \
  --outdir "$ROOT/ghidra_missing_cache_patches/ShortcutsLanguage_grow_r1"
```

Patch only pages discovered through a specific round:

```sh
dyld-ghidra-cache-patcher patch \
  --outdir "$ROOT/ghidra_missing_cache_patches/ShortcutsLanguage_grow_r1" \
  --project-dir "$ROOT/Ghidra" \
  --project-name "iOS27_Shortcuts_Dyld_Test" \
  --program "ShortcutsLanguage" \
  --through-round 0
```

## Outputs

`find` writes:

- `targeted_cache_pages.tsv`: pages that should be copied into Ghidra
- `external_target_placeholders.tsv`: exact no-byte external placeholders
- `external_page_placeholders.tsv`: no-byte external page placeholders
- `dyld_cache_mappings.tsv`: cache mapping ranges used by `patch`
- `cache_page_report.tsv`: compact audit report
- `cache_page_report.json`: full audit report
- `page_slices/`: copied 16 KiB cache pages for accepted records

The report includes page address, subcache file, file offset, discovery round,
local classification, confidence, patch decision, and reason.

## Diff Analysis Guidance

For diffing extracted images from two OS builds, run `find --mode fix` and
`patch` on both programs with the same settings before analysis. This removes
many extraction artifacts while keeping the comparison focused on the target
image.

Avoid `grow` for strict baselines unless the added context is intentional.

## Repository Layout

- `dyld_ghidra_cache_page_patcher.py`: tiny compatibility wrapper
- `dyld_ghidra_cache_patcher/cli.py`: command-line interface
- `dyld_ghidra_cache_patcher/arm64.py`: AArch64 decoding and local page classifier
- `dyld_ghidra_cache_patcher/macho.py`: extracted Mach-O parsing and branch scanning
- `dyld_ghidra_cache_patcher/dyld_cache.py`: dyld shared cache mapping and page reads
- `dyld_ghidra_cache_patcher/finder.py`: discovery, closure, report generation
- `dyld_ghidra_cache_patcher/ghidra.py`: Ghidra patch script generation and launch
- `dyld_ghidra_cache_patcher/templates/`: bundled Java script template

## License

Apache License 2.0, matching Ghidra's top-level license.
