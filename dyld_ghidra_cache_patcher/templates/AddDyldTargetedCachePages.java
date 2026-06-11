import java.io.BufferedReader;
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

public class AddDyldTargetedCachePages extends GhidraScript {
    private static final long PAGE = 0x4000L;
    private static final long CANONICAL_VA_MASK = 0x0000ffffffffffffL;

    private static class CacheMapping {
        String cacheFile;
        long start;
        long end;
        boolean execute;

        CacheMapping(String cacheFile, long start, long end, boolean execute) {
            this.cacheFile = cacheFile;
            this.start = start;
            this.end = end;
            this.execute = execute;
        }
    }

    private long parseHexLong(String s) {
        s = s.trim();
        if (s.startsWith("0x") || s.startsWith("0X")) {
            return Long.parseUnsignedLong(s.substring(2), 16);
        }
        return Long.parseUnsignedLong(s, 16);
    }

    private List<CacheMapping> readCacheMappings(File mappingsFile) throws Exception {
        List<CacheMapping> mappings = new ArrayList<CacheMapping>();
        if (!mappingsFile.isFile()) {
            return mappings;
        }

        BufferedReader br = new BufferedReader(new FileReader(mappingsFile));
        try {
            br.readLine();
            String line;
            while ((line = br.readLine()) != null) {
                line = line.trim();
                if (line.length() == 0) {
                    continue;
                }

                String[] parts = line.split("\t");
                if (parts.length < 8) {
                    continue;
                }

                mappings.add(new CacheMapping(
                    parts[0],
                    parseHexLong(parts[2]),
                    parseHexLong(parts[3]),
                    "1".equals(parts[7]) || "true".equalsIgnoreCase(parts[7])
                ));
            }
        }
        finally {
            br.close();
        }

        return mappings;
    }

    private CacheMapping findMapping(List<CacheMapping> mappings, long va) {
        for (CacheMapping m : mappings) {
            if (va >= m.start && va < m.end) {
                return m;
            }
        }
        return null;
    }

    private long canonicalizeFlowTarget(List<CacheMapping> mappings, long raw) {
        if (findMapping(mappings, raw) != null) {
            return raw;
        }

        long masked = raw & CANONICAL_VA_MASK;
        if (masked != raw && findMapping(mappings, masked) != null) {
            return masked;
        }

        return raw;
    }

    private boolean overlapsAnyBlock(Memory memory, Address start, long size) throws Exception {
        Address end = start.add(size - 1);
        MemoryBlock[] blocks = memory.getBlocks();

        for (MemoryBlock b : blocks) {
            if (b.getStart().compareTo(end) <= 0 && b.getEnd().compareTo(start) >= 0) {
                return true;
            }
        }

        return false;
    }

    private MemoryBlock createNoBytePagePlaceholder(Memory memory, long page, String prefix) throws Exception {
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
    }

    public void run() throws Exception {
        String tsvPath = "__TSV_PATH__";
        File tsv = new File(tsvPath);

        if (!tsv.isFile()) {
            println("ERROR: missing TSV: " + tsvPath);
            return;
        }

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

        try {
            BufferedReader br = new BufferedReader(new FileReader(tsv));
            try {
                br.readLine();

                String line;
                while ((line = br.readLine()) != null) {
                    line = line.trim();
                    if (line.length() == 0) {
                        continue;
                    }

                    String[] parts = line.split("\t");
                    if (parts.length < 4) {
                        println("Skipping malformed line: " + line);
                        continue;
                    }

                    total++;

                    String tag = parts[0];
                    long startLong = parseHexLong(parts[1]);
                    long size = parseHexLong(parts[2]);
                    String path = parts[3];
                    String classification = parts.length > 4 ? parts[4] : "unknown";

                    Address start = toAddr(Long.toHexString(startLong));

                    if (overlapsAnyBlock(memory, start, size)) {
                        skippedOverlap++;
                        continue;
                    }

                    File file = new File(path);
                    if (!file.isFile() || file.length() != size) {
                        println("Skipping bad file: " + path);
                        skippedBadFile++;
                        continue;
                    }

                    FileInputStream fis = new FileInputStream(file);
                    try {
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
                    }
                    finally {
                        fis.close();
                    }
                }
            }
            finally {
                br.close();
            }

            File placeholders = new File(tsv.getParentFile(), "external_target_placeholders.tsv");
            if (placeholders.isFile()) {
                BufferedReader pr = new BufferedReader(new FileReader(placeholders));
                try {
                    pr.readLine();

                    String line;
                    while ((line = pr.readLine()) != null) {
                        line = line.trim();
                        if (line.length() == 0) {
                            continue;
                        }

                        String[] parts = line.split("\t");
                        if (parts.length < 2) {
                            println("Skipping malformed placeholder line: " + line);
                            continue;
                        }

                        placeholderTotal++;

                        long targetLong = parseHexLong(parts[0]);
                        long size = parseHexLong(parts[1]);
                        Address target = toAddr(Long.toHexString(targetLong));

                        if (overlapsAnyBlock(memory, target, size)) {
                            placeholderSkippedOverlap++;
                            continue;
                        }

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
                    }
                }
                finally {
                    pr.close();
                }
            }

            File pagePlaceholders = new File(tsv.getParentFile(), "external_page_placeholders.tsv");
            if (pagePlaceholders.isFile()) {
                BufferedReader ppr = new BufferedReader(new FileReader(pagePlaceholders));
                try {
                    ppr.readLine();

                    String line;
                    while ((line = ppr.readLine()) != null) {
                        line = line.trim();
                        if (line.length() == 0) {
                            continue;
                        }

                        String[] parts = line.split("\t");
                        if (parts.length < 2) {
                            println("Skipping malformed page placeholder line: " + line);
                            continue;
                        }

                        pagePlaceholderTotal++;

                        long startLong = parseHexLong(parts[0]);
                        long size = parseHexLong(parts[1]);
                        Address start = toAddr(Long.toHexString(startLong));

                        if (overlapsAnyBlock(memory, start, size)) {
                            pagePlaceholderSkippedOverlap++;
                            continue;
                        }

                        String blockName = "__dyld_external_page_placeholder_" + Long.toHexString(startLong);
                        MemoryBlock block = memory.createUninitializedBlock(blockName, start, size, false);
                        block.setRead(false);
                        block.setWrite(false);
                        block.setExecute(false);
                        block.setVolatile(true);

                        pagePlaceholderAdded++;
                    }
                }
                finally {
                    ppr.close();
                }
            }

            List<CacheMapping> cacheMappings = readCacheMappings(new File(tsv.getParentFile(), "dyld_cache_mappings.tsv"));
            if (!cacheMappings.isEmpty()) {
                Set<Long> seenPages = new HashSet<Long>();
                InstructionIterator iit = currentProgram.getListing().getInstructions(true);
                while (iit.hasNext()) {
                    Instruction instr = iit.next();
                    Address from = instr.getAddress();
                    MemoryBlock fromBlock = memory.getBlock(from);
                    if (fromBlock == null || !fromBlock.isExecute()) {
                        continue;
                    }

                    for (Address flow : instr.getFlows()) {
                        if (flow == null) {
                            continue;
                        }

                        AddressSpace space = flow.getAddressSpace();
                        if (space != null && space.isExternalSpace()) {
                            flowPlaceholderSkippedNonCache++;
                            continue;
                        }

                        if (memory.getBlock(flow) != null) {
                            continue;
                        }

                        long rawTarget = flow.getOffset();
                        long target = canonicalizeFlowTarget(cacheMappings, rawTarget);
                        CacheMapping mapping = findMapping(cacheMappings, target);
                        if (mapping == null) {
                            flowPlaceholderSkippedNonCache++;
                            continue;
                        }

                        long page = target & ~(PAGE - 1);
                        flowPlaceholderTotal++;
                        if (seenPages.contains(page)) {
                            flowPlaceholderSkippedDuplicate++;
                            continue;
                        }
                        seenPages.add(page);

                        Address start = toAddr(Long.toHexString(page));
                        if (overlapsAnyBlock(memory, start, PAGE)) {
                            flowPlaceholderSkippedOverlap++;
                            continue;
                        }

                        createNoBytePagePlaceholder(memory, page, "__dyld_external_flow_placeholder_");
                        flowPlaceholderAdded++;
                    }
                }
            }

            commit = true;
        }
        finally {
            currentProgram.endTransaction(tx, commit);
        }

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
    }
}
