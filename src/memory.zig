//  @zux0x3a
//
//
//
//   L1 structural    - only executable IMAGE sub-regions (kills .data/.rdata).
//   L2 quantitative  - grade by private_pages and private_ratio.
//   L3 corroboration - require at least one independent signal on the same
//                      allocation base (signature hit, missing PEB entry,
//                      hook prologue, on-disk diff, etc.).
//   L4 CLR-aware     - per-module suppression for ngen/R2R JIT targets
//                      rather than blanket-skipping when CLR is present.
//   L5 on-disk diff  - map the module file with SEC_IMAGE and compare the
//                      first bytes of each private executable page against
//                      the on-disk copy at the same RVA.

const std = @import("std");
const w = @import("win32.zig");
const scanner = @import("scanner.zig");
const console = @import("console.zig");
const sigs = @import("signatures.zig");

pub const READ_CHUNK: usize = 64 * 1024;

const SYSTEM_SKIP_PREFIXES = [_][]const u8{
    "c:\\windows\\",
    "c:\\program files\\dotnet\\",
    "c:\\program files (x86)\\dotnet\\",
    "c:\\program files\\common files\\microsoft shared\\",
    "c:\\program files (x86)\\common files\\microsoft shared\\",
};

const CLR_JIT_TARGET_PATTERNS = [_][]const u8{
    "mscor",
    "clr",
    "coreclr",
    "system.private.corelib",
    "ntdll", // hot-patch tables
};
const CLR_JIT_TARGET_SUFFIXES = [_][]const u8{
    ".ni.dll",
    ".r2r.dll",
};

pub const MemoryWalkStats = struct {
    total_regions: u32 = 0,
    committed_regions: u32 = 0,
    skipped_system: u32 = 0,
    read_errors: u32 = 0,
    bytes_scanned: u64 = 0,
};

pub const RegionInfo = struct {
    base: usize,
    size: usize,
    protect: u32,
    region_type: u32,
    is_executable: bool,
};

const ModuleInfo = struct {
    base: usize,
    size: usize,
    path: []u8, // lowercased ascii, owned
    basename: []const u8, // slice into path
    is_system: bool,
    is_clr_jit_target: bool,
};

const ModuleMap = struct {
    entries: std.ArrayList(ModuleInfo),
    by_base: std.AutoHashMap(usize, usize), // base -> index into entries
    gpa: std.mem.Allocator,

    fn deinit(self: *ModuleMap) void {
        for (self.entries.items) |e| self.gpa.free(e.path);
        self.entries.deinit(self.gpa);
        self.by_base.deinit();
    }

    pub fn get(self: *const ModuleMap, base: usize) ?*const ModuleInfo {
        const idx = self.by_base.get(base) orelse return null;
        return &self.entries.items[idx];
    }
};

//
// Candidate finding for the L3 corroboration pass: we collect modified_code
// candidates during the walk and only emit them at the end if they survive
// corroboration.
//
const ModifiedCandidate = struct {
    allocation_base: usize,
    region_base: usize,
    region_size: usize,
    private_pages: u32,
    region_pages: u32,
    has_hook_prologue: bool,
    has_disk_diff: bool,
};

pub fn walkAndScan(
    io_scanner: *scanner.Scanner,
    process: w.HANDLE,
    pid: u32,
    results: *scanner.ScanResults,
    verbose: bool,
    rule_based: bool,
    writer: console.Writer,
) !MemoryWalkStats {
    var stats = MemoryWalkStats{};
    var address: usize = 0;
    var mbi: w.MEMORY_BASIC_INFORMATION = undefined;
    const allocator = results.gpa;

    var module_map = try buildModuleMap(allocator, pid);
    defer module_map.deinit();

    var peb_set = try scanner.buildPebModuleSet(allocator, pid);
    defer peb_set.deinit();

    const is_clr = scanner.isDotNetProcess(pid);
    if (is_clr) {
        try results.addSuspicion(.{ .kind = .clr_init, .address = 0, .size = 0 });
    }

    var candidates: std.ArrayList(ModifiedCandidate) = .empty;
    defer candidates.deinit(allocator);

    var buf: [READ_CHUNK]u8 = undefined;

    while (true) {
        const qr = w.VirtualQueryEx(process, address, &mbi, @sizeOf(w.MEMORY_BASIC_INFORMATION));
        if (qr == 0) break;

        stats.total_regions += 1;

        if (mbi.State == w.MEM_COMMIT and w.isReadable(mbi.Protect)) {
            stats.committed_regions += 1;

            const mod_opt = module_map.get(mbi.AllocationBase);
            const is_system = mod_opt != null and mod_opt.?.is_system;
            const is_clr_jit_target = mod_opt != null and mod_opt.?.is_clr_jit_target;

            if (mbi.Type == w.MEM_IMAGE and
                !is_system and
                !scanner.pebContainsModule(&peb_set, mbi.AllocationBase))
            {
                // IMAGE region not in PEB => DLL hollowing / module stomping.
                try results.addSuspicion(.{
                    .kind = .missing_peb_entry,
                    .address = mbi.AllocationBase,
                    .size = mbi.RegionSize,
                });
            }

            // L1 + L4: only executable sub-regions of non-system, non-CLR-JIT
            // image allocations are candidates for "modified code". The vast
            // majority of historical FPs came from .data/.rdata pages whose
            // COW status is normal and meaningless as an IOC.
            if (mbi.Type == w.MEM_IMAGE and
                w.isExecutable(mbi.Protect) and
                !is_system and
                !is_clr_jit_target)
            {
                const private_pages = scanner.countPrivatePages(process, mbi.BaseAddress, mbi.RegionSize);
                if (private_pages > 0) {
                    const region_pages: u32 = @intCast(mbi.RegionSize / 0x1000);
                    var cand = ModifiedCandidate{
                        .allocation_base = mbi.AllocationBase,
                        .region_base = mbi.BaseAddress,
                        .region_size = mbi.RegionSize,
                        .private_pages = private_pages,
                        .region_pages = if (region_pages == 0) 1 else region_pages,
                        .has_hook_prologue = false,
                        .has_disk_diff = false,
                    };

                    // L3 sub-signal: scan the private pages for hook prologues
                    // (16 bytes at page start is enough for the common
                    // x64/x86 trampoline forms).
                    cand.has_hook_prologue = scanHookPrologues(
                        allocator,
                        process,
                        mbi.BaseAddress,
                        mbi.RegionSize,
                    );

                    // L5: on-disk diff vs the file mapping.
                    if (mod_opt) |mi| {
                        cand.has_disk_diff = diffAgainstDisk(
                            allocator,
                            process,
                            mi.*,
                            mbi.BaseAddress,
                            mbi.RegionSize,
                        );
                    }

                    try candidates.append(allocator, cand);
                }
            }

            if (mbi.Type == w.MEM_PRIVATE and w.isExecutable(mbi.Protect) and !is_clr) {
                try results.addSuspicion(.{
                    .kind = .private_rwx,
                    .address = mbi.BaseAddress,
                    .size = mbi.RegionSize,
                });
            }

            if (mbi.Type == w.MEM_IMAGE and is_system) {
                stats.skipped_system += 1;
                address = mbi.BaseAddress + mbi.RegionSize;
                continue;
            }

            const region_info = RegionInfo{
                .base = mbi.BaseAddress,
                .size = mbi.RegionSize,
                .protect = mbi.Protect,
                .region_type = mbi.Type,
                .is_executable = w.isExecutable(mbi.Protect),
            };

            if (verbose) {
                writer.print("  Region 0x{X:0>16} size=0x{X:0>8} type={s} prot=0x{X:0>4}{s}\n", .{
                    region_info.base,
                    region_info.size,
                    regionTypeStr(mbi.Type),
                    region_info.protect,
                    if (region_info.is_executable) " [EXEC]" else "",
                });
            }

            // Entropy + shellcode heuristic analysis.
            // Scope: MEM_PRIVATE executable (active shellcode) and
            //        MEM_PRIVATE writable-not-executable (staged payloads
            //        awaiting VirtualProtect). Skip tiny regions, system
            //        allocations, and CLR JIT targets.
            if (mbi.Type == w.MEM_PRIVATE and
                !is_system and !is_clr_jit_target and
                mbi.RegionSize >= 256 and
                (w.isExecutable(mbi.Protect) or w.isWritableNotExecutable(mbi.Protect)))
            {
                const is_exec = w.isExecutable(mbi.Protect);
                if (try scanner.analyzeRegionEntropy(
                    process,
                    mbi.BaseAddress,
                    mbi.RegionSize,
                    is_exec,
                    allocator,
                )) |analysis| {
                    const verdict = analysis.gradeVerdict();
                    if (verdict != .clr_init) {
                        try results.addSuspicion(.{
                            .kind = verdict,
                            .address = mbi.BaseAddress,
                            .size = mbi.RegionSize,
                        });
                        if (verbose) {
                            writer.print(
                                "  [!] {s} @ 0x{X} peak={d:.2} chi2={d:.1} null%={d:.4} prelude={} gradient={}\n",
                                .{
                                    @as(sigs.Suspicion, .{
                                        .kind = verdict,
                                        .address = 0,
                                        .size = 0,
                                    }).label(),
                                    mbi.BaseAddress,
                                    analysis.peak_entropy,
                                    analysis.chi_squared,
                                    analysis.null_byte_ratio,
                                    analysis.has_shellcode_prelude,
                                    analysis.has_entropy_gradient,
                                },
                            );
                        }
                    }
                }
            }

            // this section for rule based scan.
            var offset: usize = 0;
            while (offset < mbi.RegionSize) {
                const to_read = @min(READ_CHUNK, mbi.RegionSize - offset);
                var bytes_read: usize = 0;

                const ok = w.ReadProcessMemory(
                    process,
                    mbi.BaseAddress + offset,
                    &buf,
                    to_read,
                    &bytes_read,
                );

                if (ok == w.FALSE or bytes_read == 0) {
                    stats.read_errors += 1;
                    break;
                }

                const slice = buf[0..bytes_read];
                if (rule_based) {
                    try io_scanner.scan(slice, mbi.BaseAddress + offset, results);
                    try io_scanner.scan16UTFLE(slice, mbi.BaseAddress + offset, results);
                }

                if (mbi.Type == w.MEM_PRIVATE and offset == 0) {
                    scanner.scanPeHeaders(slice, mbi.BaseAddress, results);
                }

                if (offset == 0 and !is_system and !is_clr_jit_target and
                    (mbi.Type == w.MEM_PRIVATE or mbi.Type == w.MEM_IMAGE))
                {
                    if (sigs.findXorPeHeader(slice)) |m| {
                        try results.addSuspicion(.{
                            .kind = .xor_pe_header,
                            .address = mbi.BaseAddress + m.offset,
                            .size = m.key_len,
                        });
                        if (verbose) {
                            writer.print(
                                "  [!] XOR_PE_HEADER @ 0x{X} key_len={d} key=",
                                .{ mbi.BaseAddress + m.offset, m.key_len },
                            );
                            var ki: usize = 0;
                            while (ki < m.key_len) : (ki += 1) {
                                writer.print("{X:0>2}", .{m.key[ki]});
                            }
                            writer.write("\n");
                        }
                    }
                }

                stats.bytes_scanned += bytes_read;
                offset += bytes_read;
            }

            results.regions_scanned += 1;
        }

        const next = mbi.BaseAddress + mbi.RegionSize;
        if (next <= address) break;
        address = next;
    }

    // L3 final pass: convert candidates into graded suspicions. A candidate is
    // promoted only if it has at least one corroborating signal beyond
    // "private_pages > 0" - or if the quantitative signal is overwhelming on
    // its own (high private_ratio).
    try gradeAndEmitCandidates(results, candidates.items);

    // L8 - Thread start-address validation (TSAV). Runs AFTER the modified-
    // code grading pass so it can cross-correlate against already-emitted
    // suspicions: a thread that starts inside an allocation we've already
    // flagged as modified/hollowed/RWX is far higher confidence.
    try runThreadStartValidation(
        allocator,
        process,
        pid,
        &module_map,
        &peb_set,
        results,
        verbose,
        writer,
    );

    results.bytes_scanned = stats.bytes_scanned;
    return stats;
}

fn runThreadStartValidation(
    allocator: std.mem.Allocator,
    process: w.HANDLE,
    pid: u32,
    module_map: *const ModuleMap,
    peb_set: *const std.AutoHashMap(usize, void),
    results: *scanner.ScanResults,
    verbose: bool,
    writer: console.Writer,
) !void {
    // Build the "bad allocation base" set from already-emitted suspicions.
    // A thread whose start address (or suspended RIP) lands in one of these
    // is a high-confidence injection IOC.
    var bad_bases: std.AutoHashMap(usize, void) = .init(allocator);
    defer bad_bases.deinit();

    for (results.suspicious.items) |s| {
        switch (s.kind) {
            .missing_peb_entry,
            .private_rwx,
            .modified_code_high,
            .modified_code_medium,
            .disk_mem_diff,
            .hook_prologue,
            => try bad_bases.put(s.address, {}),
            else => {},
        }
    }

    // Detect WoW64 once per process.
    var wow_flag: w.BOOL = 0;
    const is_wow64 = w.IsWow64Process(process, &wow_flag) != w.FALSE and wow_flag != 0;

    const ctx = scanner.TsavContext{
        .process = process,
        .pid = pid,
        .is_wow64 = is_wow64,
        .bad_alloc_bases = &bad_bases,
        .peb_bases = peb_set,
    };

    const verdicts = scanner.validateThreadStartAddresses(allocator, ctx, module_map) catch return;
    defer allocator.free(verdicts);

    var anomaly_count: u32 = 0;
    for (verdicts) |v| {
        if (!v.isSuspicious()) continue;
        anomaly_count += 1;

        const kind = threadStatusToSuspicion(v.status);
        try results.addSuspicion(.{
            .kind = kind,
            .address = if (v.rip_address != 0) v.rip_address else v.start_address,
            .size = v.thread_id,
        });

        if (verbose) {
            writer.print("  [!] TID:{d} {s} start=0x{X}", .{
                v.thread_id, v.label(), v.start_address,
            });
            if (v.rip_address != 0 and v.rip_address != v.start_address) {
                writer.print(" rip=0x{X}", .{v.rip_address});
            }
            if (v.module_name_len > 0) {
                writer.print(" host={s}", .{v.module_name[0..v.module_name_len]});
            }
            writer.write("\n");
        }
    }

    // Always emit an aggregate count so non-verbose output still surfaces
    // "N suspicious threads" at a glance.
    if (anomaly_count > 0) {
        try results.addSuspicion(.{
            .kind = .thread_start_anomaly,
            .address = 0,
            .size = anomaly_count,
        });
    }
}

fn threadStatusToSuspicion(st: scanner.ThreadStatus) sigs.SuspicionType {
    return switch (st) {
        .shellcode_private => .thread_shellcode_private,
        .staged_private_rw => .thread_staged_private_rw,
        .mapped_nonpe => .thread_mapped_nonpe,
        .hollowed_host => .thread_hollowed_host,
        .modified_host => .thread_modified_host,
        .spoof_trampoline => .thread_spoof_trampoline,
        .suspended_rip_anomaly => .thread_suspended_rip_anomaly,
        .ok, .query_failed => .thread_start_anomaly, // unreachable but exhaustive
    };
}

fn gradeAndEmitCandidates(
    results: *scanner.ScanResults,
    items: []const ModifiedCandidate,
) !void {

    //
    // Build a quick lookup of allocation bases that already have signature
    // hits or missing-PEB suspicions -> those count as corroboration.
    //
    var corroborated: std.AutoHashMap(usize, void) = .init(results.gpa);
    defer corroborated.deinit();

    for (results.suspicious.items) |s| {
        if (s.kind == .missing_peb_entry or s.kind == .private_rwx) {
            try corroborated.put(s.address, {});
        }
    }
    for (results.hits.items) |hit| {

        // region_base on a signature hit may equal an allocation base or a
        // sub-region base; both are useful corroborators.
        try corroborated.put(hit.region_base, {});
    }

    for (items) |c| {
        const ratio_bp: u32 = (c.private_pages * 10_000) / c.region_pages;

        const has_external = corroborated.contains(c.allocation_base);

        // []
        // Independent grading rules:
        //   high  - hook prologue OR on-disk diff OR ratio >= 25%
        //   med   - external corroboration OR ratio >= 5% OR private >= 8
        // Anything below the medium bar is dropped entirely; without at least
        // one independent signal, "this IMAGE region has private pages" is
        // indistinguishable from normal loader behaviour.
        //
        const kind: sigs.SuspicionType =
            if (c.has_hook_prologue or c.has_disk_diff or ratio_bp >= 2500)
                .modified_code_high
            else if (has_external or ratio_bp >= 500 or c.private_pages >= 8)
                .modified_code_medium
            else
                continue;

        if (c.has_hook_prologue) {
            try results.addSuspicion(.{
                .kind = .hook_prologue,
                .address = c.region_base,
                .size = c.region_size,
                .private_pages = c.private_pages,
                .region_pages = c.region_pages,
            });
        }
        if (c.has_disk_diff) {
            try results.addSuspicion(.{
                .kind = .disk_mem_diff,
                .address = c.region_base,
                .size = c.region_size,
                .private_pages = c.private_pages,
                .region_pages = c.region_pages,
            });
        }

        try results.addSuspicion(.{
            .kind = kind,
            .address = c.region_base,
            .size = c.region_size,
            .private_pages = c.private_pages,
            .region_pages = c.region_pages,
        });
    }
}

/// Read the first 16 bytes of each private page in the region and look for
/// classic x86/x64 inline-hook prologues. Returns true on the first match.
fn scanHookPrologues(
    allocator: std.mem.Allocator,
    process: w.HANDLE,
    base: usize,
    region_size: usize,
) bool {
    const pages = scanner.collectPrivatePages(allocator, process, base, region_size) catch return false;
    defer allocator.free(pages);

    var prologue: [16]u8 = undefined;
    for (pages) |page_addr| {
        var got: usize = 0;
        if (w.ReadProcessMemory(process, page_addr, &prologue, 16, &got) == w.FALSE) continue;
        if (got < 5) continue;
        if (isHookPrologue(prologue[0..got])) return true;
    }
    return false;
}

fn isHookPrologue(bytes: []const u8) bool {
    if (bytes.len < 5) return false;

    // E9 ?? ?? ?? ??               near JMP rel32
    if (bytes[0] == 0xE9) return true;

    // FF 25 ?? ?? ?? ??            JMP [rip+disp32] / JMP [disp32]
    if (bytes.len >= 6 and bytes[0] == 0xFF and bytes[1] == 0x25) return true;

    // 68 ?? ?? ?? ?? C3            PUSH imm32 ; RET
    if (bytes.len >= 6 and bytes[0] == 0x68 and bytes[5] == 0xC3) return true;

    // 48 B8 ?? ?? ?? ?? ?? ?? ?? ?? FF E0   MOV RAX,imm64 ; JMP RAX
    if (bytes.len >= 12 and
        bytes[0] == 0x48 and bytes[1] == 0xB8 and
        bytes[10] == 0xFF and bytes[11] == 0xE0) return true;

    // 49 BB ?? ?? ?? ?? ?? ?? ?? ?? 41 FF E3 MOV R11,imm64 ; JMP R11 (Detours)
    if (bytes.len >= 13 and
        bytes[0] == 0x49 and bytes[1] == 0xBB and
        bytes[10] == 0x41 and bytes[11] == 0xFF and bytes[12] == 0xE3) return true;

    return false;
}
//
/// Map the module file from disk with SEC_IMAGE so the loader applies the
/// same layout as the live image (sections, relocations, alignment). Then
/// compare the first 16 bytes of each private executable page in memory
/// against the same RVA on disk. Any byte-level difference at offset 0 of
/// an executable page is a strong "real modification" signal.
//
fn diffAgainstDisk(
    allocator: std.mem.Allocator,
    process: w.HANDLE,
    mod: ModuleInfo,
    base: usize,
    region_size: usize,
) bool {
    // Convert module path back to UTF-16 for CreateFileW.
    var wide_path: [w.MAX_PATH]u16 = undefined;
    if (mod.path.len + 1 > wide_path.len) return false;
    for (mod.path, 0..) |c, i| wide_path[i] = c;
    wide_path[mod.path.len] = 0;
    const wpath_z: [*:0]const u16 = @ptrCast(&wide_path);

    const file = w.CreateFileW(
        wpath_z,
        w.GENERIC_READ,
        w.FILE_SHARE_READ,
        null,
        w.OPEN_EXISTING,
        w.FILE_ATTRIBUTE_NORMAL,
        null,
    ) orelse return false;
    if (file == w.INVALID_HANDLE_VALUE) return false;
    defer _ = w.CloseHandle(file);

    const mapping = w.CreateFileMappingW(
        file,
        null,
        w.PAGE_READONLY_FLAG | w.SEC_IMAGE_NO_EXECUTE,
        0,
        0,
        null,
    ) orelse return false;
    defer _ = w.CloseHandle(mapping);

    const view = w.MapViewOfFile(mapping, w.FILE_MAP_READ, 0, 0, 0) orelse return false;
    defer _ = w.UnmapViewOfFile(view);

    const disk_base = @intFromPtr(view);

    const pages = scanner.collectPrivatePages(allocator, process, base, region_size) catch return false;
    defer allocator.free(pages);

    var live: [16]u8 = undefined;
    for (pages) |page_addr| {
        if (page_addr < mod.base) continue;
        const rva = page_addr - mod.base;
        if (rva >= mod.size) continue;

        var got: usize = 0;
        if (w.ReadProcessMemory(process, page_addr, &live, 16, &got) == w.FALSE) continue;
        if (got == 0) continue;

        const disk_ptr: [*]const u8 = @ptrFromInt(disk_base + rva);
        if (!std.mem.eql(u8, live[0..got], disk_ptr[0..got])) {
            return true;
        }
    }
    return false;
}

fn buildModuleMap(allocator: std.mem.Allocator, pid: u32) !ModuleMap {
    var map = ModuleMap{
        .entries = .empty,
        .by_base = .init(allocator),
        .gpa = allocator,
    };

    const snap = w.CreateToolhelp32Snapshot(w.TH32CS_SNAPMODULE | w.TH32CS_SNAPMODULE32, pid) orelse return map;
    defer _ = w.CloseHandle(snap);

    var me: w.MODULEENTRY32W = undefined;
    me.dwSize = @sizeOf(w.MODULEENTRY32W);
    if (w.Module32FirstW(snap, &me) == w.FALSE) return map;

    while (true) {
        const wide = w.wideToSlice(&me.szExePath);
        const path = lowerAsciiCopy(allocator, wide) catch {
            if (w.Module32NextW(snap, &me) == w.FALSE) break;
            continue;
        };
        const basename = basenameOf(path);

        const info = ModuleInfo{
            .base = me.modBaseAddr,
            .size = me.modBaseSize,
            .path = path,
            .basename = basename,
            .is_system = matchesAnyPrefix(path, &SYSTEM_SKIP_PREFIXES),
            .is_clr_jit_target = isClrJitTarget(basename),
        };

        try map.entries.append(allocator, info);
        try map.by_base.put(me.modBaseAddr, map.entries.items.len - 1);

        if (w.Module32NextW(snap, &me) == w.FALSE) break;
    }
    return map;
}

fn lowerAsciiCopy(allocator: std.mem.Allocator, wide: []const u16) ![]u8 {
    const out = try allocator.alloc(u8, wide.len);
    for (wide, 0..) |wc, i| {
        if (wc > 127) {
            out[i] = '?';
            continue;
        }
        var c: u8 = @truncate(wc);
        if (c >= 'A' and c <= 'Z') c += 32;
        out[i] = c;
    }
    return out;
}

fn basenameOf(path: []const u8) []const u8 {
    var i: usize = path.len;
    while (i > 0) {
        i -= 1;
        if (path[i] == '\\' or path[i] == '/') return path[i + 1 ..];
    }
    return path;
}

fn matchesAnyPrefix(path: []const u8, prefixes: []const []const u8) bool {
    for (prefixes) |prefix| {
        if (path.len >= prefix.len and std.mem.eql(u8, path[0..prefix.len], prefix)) return true;
    }
    return false;
}

fn isClrJitTarget(basename: []const u8) bool {
    for (CLR_JIT_TARGET_PATTERNS) |needle| {
        if (basename.len >= needle.len and std.mem.eql(u8, basename[0..needle.len], needle)) return true;
    }
    for (CLR_JIT_TARGET_SUFFIXES) |suffix| {
        if (basename.len >= suffix.len and
            std.mem.eql(u8, basename[basename.len - suffix.len ..], suffix)) return true;
    }
    return false;
}

fn regionTypeStr(t: u32) []const u8 {
    if (t == w.MEM_IMAGE) return "IMAGE  ";
    if (t == w.MEM_MAPPED) return "MAPPED ";
    if (t == w.MEM_PRIVATE) return "PRIVATE";
    return "UNKNOWN";
}

/// Behavior when `dumpMemRegion` encounters an uncommitted / unreadable page
/// within the requested range.
pub const DumpPolicy = enum {
    strict_committed,
    pad_zero,
};

pub const DumpStats = struct {
    requested_bytes: usize,
    committed_bytes: usize, // bytes that were actually read from the target
    padded_bytes: usize, // zeros written for uncommitted ranges (pad_zero only)
    regions_visited: u32, // count of distinct MEMORY_BASIC_INFORMATION blocks traversed
    gaps: u32, // number of uncommitted regions encountered

    pub fn isComplete(self: DumpStats) bool {
        return self.committed_bytes + self.padded_bytes >= self.requested_bytes;
    }
};

pub fn dumpMemRegion(
    io: std.Io,
    process: w.HANDLE,
    pid: u32,
    start_address: usize,
    size: usize,
    policy: DumpPolicy,
    allocator: std.mem.Allocator,
) !DumpStats {
    _ = allocator;
    if (size == 0) return error.EmptyRequest;

    var name_buf: [256]u8 = undefined;
    const name = std.fmt.bufPrint(
        &name_buf,
        "dump_{d}_0x{X}_{d}.bin",
        .{ pid, start_address, size },
    ) catch return error.BufferTooSmall;

    const cwd = std.Io.Dir.cwd();
    const file = try cwd.createFile(io, name, .{});
    defer file.close(io);

    var buf: [READ_CHUNK]u8 = undefined;
    const zero_buf: [READ_CHUNK]u8 = [_]u8{0} ** READ_CHUNK;

    var stats = DumpStats{
        .requested_bytes = size,
        .committed_bytes = 0,
        .padded_bytes = 0,
        .regions_visited = 0,
        .gaps = 0,
    };

    var offset: usize = 0;
    while (offset < size) {
        const cur_addr = start_address + offset;
        const remaining = size - offset;

        var mbi: w.MEMORY_BASIC_INFORMATION = undefined;
        const qr = w.VirtualQueryEx(process, cur_addr, &mbi, @sizeOf(w.MEMORY_BASIC_INFORMATION));
        if (qr == 0) {
            const last = w.GetLastError();
            std.debug.print(
                "[!] VirtualQueryEx failed at 0x{X} (GetLastError={d}). " ++
                    "Common causes: handle lacks PROCESS_QUERY_INFORMATION, " ++
                    "address outside target's VA space, or target is 32-bit " ++
                    "and address is in WoW64-inaccessible high memory.\n",
                .{ cur_addr, last },
            );
            return error.VirtualQueryFailed;
        }
        stats.regions_visited += 1;

        const region_end = mbi.BaseAddress + mbi.RegionSize;
        const bytes_left_in_region = region_end - cur_addr;
        const chunk = @min(remaining, bytes_left_in_region);

        const readable = mbi.State == w.MEM_COMMIT and w.isReadable(mbi.Protect);

        if (!readable) {
            stats.gaps += 1;
            switch (policy) {
                .strict_committed => {
                    std.debug.print(
                        "[*] Stopping at 0x{X}: uncommitted gap (State=0x{X} " ++
                            "Protect=0x{X} Type=0x{X}); committed so far: {d}/{d} bytes\n",
                        .{ cur_addr, mbi.State, mbi.Protect, mbi.Type, stats.committed_bytes, size },
                    );
                    return stats;
                },
                .pad_zero => {
                    // Write `chunk` zeros then advance.
                    var pad_left = chunk;
                    while (pad_left > 0) {
                        const w_amt = @min(pad_left, zero_buf.len);
                        try file.writeStreamingAll(io, zero_buf[0..w_amt]);
                        pad_left -= w_amt;
                    }
                    stats.padded_bytes += chunk;
                    offset += chunk;
                    continue;
                },
            }
        }

        // Region is committed + readable. Read in READ_CHUNK pieces until we exhaust this region or hit `size`.
        var consumed: usize = 0;
        while (consumed < chunk) {
            const want = @min(chunk - consumed, READ_CHUNK);
            var bytes_read: usize = 0;
            const ok = w.ReadProcessMemory(process, cur_addr + consumed, &buf, want, &bytes_read);
            if (ok == w.FALSE or bytes_read == 0) {
                const last = w.GetLastError();
                std.debug.print(
                    "[!!] ReadProcessMemory API failed at 0x{X} (want={d}, got={d}, GetLastError={d})\n",
                    .{ cur_addr + consumed, want, bytes_read, last },
                );
                return error.ReadProcessMemoryFailed;
            }

            try file.writeStreamingAll(io, buf[0..bytes_read]);
            stats.committed_bytes += bytes_read;
            consumed += bytes_read;
        }
        offset += consumed;
    }

    return stats;
}
