//! ============================================================================
//! File: Scanner.zig
//! Author: Lawrence Amer (@zux0x3a - 0xsp.com)
//!
//! Summary:
//! Scan processes's memory regions with different scan levels, each performed scan output the results as struct "ScanResults"
//! this module has TSAV functions, main scanners logics for both IOC structual and Signature scanning.
//! ============================================================================

const std = @import("std");
const sigs = @import("signatures.zig");
const api = @import("win32.zig");

const OBJ_CASE_INSENSITIVE: u32 = 0x00000040;
const SECTION_QUERY: u32 = 0x0001;

pub const Scanner = struct {
    loaded: sigs.LoadedRules,
    ascii_index: [256][]u32,
    utf16_index: [256][]u32,
    index_storage: []u32,
    allocator: std.mem.Allocator,

    pub fn initFromFile(allocator: std.mem.Allocator, path: []const u8) !Scanner {
        var s = Scanner{
            .loaded = try sigs.readRules(allocator, path),
            .ascii_index = undefined,
            .utf16_index = undefined,
            .index_storage = &.{},
            .allocator = allocator,
        };
        try s.buildIndex();
        return s;
    }
    pub fn initFromDir(allocator: std.mem.Allocator, dir_path: []const u8) !Scanner {
        var s = Scanner{
            .loaded = try sigs.readRulesDirWin32(allocator, dir_path),
            .ascii_index = undefined,
            .utf16_index = undefined,
            .index_storage = &.{},
            .allocator = allocator,
        };
        try s.buildIndex();
        return s;
    }

    /// Build a valid scanner with zero loaded signatures - lets the
    /// structural-only scan path proceed without special-casing throughout
    /// `walkAndScan`. Rule scanning is a no-op (empty index, empty list).
    pub fn initEmpty(allocator: std.mem.Allocator) !Scanner {
        var s = Scanner{
            .loaded = .{
                .merged_sigs = try allocator.alloc(sigs.Signature, 0),
                .raw_buffers = .empty,
                .parsed_list = .empty,
                .allocator = allocator,
            },
            .ascii_index = undefined,
            .utf16_index = undefined,
            .index_storage = &.{},
            .allocator = allocator,
        };
        try s.buildIndex();
        return s;
    }

    pub fn deinit(self: *Scanner) void {
        self.allocator.free(self.index_storage);
        self.loaded.deinit();
    }
    pub fn signatures(self: *const Scanner) []const sigs.Signature {
        return self.loaded.merged_sigs;
    }

    fn buildIndex(self: *Scanner) !void {
        const sigs_list = self.signatures();

        var ascii_counts = [_]u32{0} ** 256;
        var utf16_counts = [_]u32{0} ** 256;
        for (sigs_list) |sig| {
            if (sig.pattern.len == 0) continue;
            ascii_counts[sig.pattern[0]] += 1;
            utf16_counts[sig.pattern[0]] += 1;
        }

        var total: u32 = 0;
        for (ascii_counts) |c| total += c;
        for (utf16_counts) |c| total += c;

        self.index_storage = try self.allocator.alloc(u32, total);

        var offset: u32 = 0;
        for (0..256) |b| {
            const start = offset;
            const cnt = ascii_counts[b];
            self.ascii_index[b] = self.index_storage[start..][0..cnt];
            offset += cnt;
        }
        for (0..256) |b| {
            const start = offset;
            const cnt = utf16_counts[b];
            self.utf16_index[b] = self.index_storage[start..][0..cnt];
            offset += cnt;
        }

        var ascii_pos = [_]u32{0} ** 256;
        var utf16_pos = [_]u32{0} ** 256;
        for (sigs_list, 0..) |sig, si| {
            if (sig.pattern.len == 0) continue;
            const first = sig.pattern[0];
            self.ascii_index[first][ascii_pos[first]] = @intCast(si);
            ascii_pos[first] += 1;
            self.utf16_index[first][utf16_pos[first]] = @intCast(si);
            utf16_pos[first] += 1;
        }
    }

    pub fn scan(self: *Scanner, buf: []const u8, region_base: usize, results: *ScanResults) !void {
        const sigs_list = self.signatures();
        if (buf.len == 0) return;

        var pos: usize = 0;
        while (pos < buf.len) : (pos += 1) {
            // : (pos +=1) the code executed after the end of each iteration right before the checking the condition again pos < buf.len
            const candidates = self.ascii_index[buf[pos]];
            if (candidates.len == 0) continue;

            for (candidates) |si| {
                const sig = sigs_list[si];
                const pat = sig.pattern;
                if (pos + pat.len > buf.len) continue;
                if (!std.mem.eql(u8, buf[pos..][0..pat.len], pat)) continue;

                try results.addHit(.{
                    .sig_index = si,
                    .offset = pos,
                    .encoding = .ascii,
                    .region_base = region_base,
                });
            }
        }
    }

    pub fn scan16UTFLE(self: *Scanner, buf: []const u8, region_base: usize, results: *ScanResults) !void {
        const sigs_list = self.signatures();
        if (buf.len < 2) return;

        var pos: usize = 0;
        while (pos + 1 < buf.len) : (pos += 1) {
            if (buf[pos + 1] != 0) continue;
            const candidates = self.utf16_index[buf[pos]];
            if (candidates.len == 0) continue;

            for (candidates) |si| {
                const sig = sigs_list[si];
                const pat = sig.pattern;
                const wide_len = pat.len * 2;
                if (pos + wide_len > buf.len) continue;

                var matched = true;
                for (pat, 0..) |c, i| {
                    const bi = pos + i * 2;
                    if (buf[bi] != c or buf[bi + 1] != 0) {
                        matched = false;
                        break;
                    }
                }
                if (!matched) continue;

                try results.addHit(.{
                    .sig_index = si,
                    .offset = pos,
                    .encoding = .utf16le,
                    .region_base = region_base,
                });
            }
        }
    }
};

/// Outcome of a single thread's start-address / RIP validation. The values are
/// ordered roughly by severity (lower = better).
pub const ThreadStatus = enum {
    ok, // start address inside a PEB-loaded, non-hollowed, non-modified module
    query_failed, // couldn't OpenThread or NtQueryInformationThread failed
    spoof_trampoline, // start address points at a known APC/EarlyBird spoof target
    modified_host, // start address inside an IMAGE region flagged by L1-L5
    hollowed_host, // start address inside an IMAGE region with no PEB entry
    mapped_nonpe, // start address inside MEM_MAPPED that's not a PE
    staged_private_rw, // MEM_PRIVATE, writable but not yet executable
    shellcode_private, // MEM_PRIVATE + executable - the classic shellcode case
    suspended_rip_anomaly, // RIP of a suspended thread points outside any module
};

/// Struct to hold results of a thread start-address check.
pub const ThreadVerdict = struct {
    thread_id: u32,
    start_address: usize,
    status: ThreadStatus,
    module_name: [64]u8, // owning module if ok (or host module if modified/hollowed)
    module_name_len: usize,
    // The suspended-RIP check fills this if it disagrees with start_address.
    rip_address: usize = 0,

    pub fn isSuspicious(self: ThreadVerdict) bool {
        return switch (self.status) {
            .ok, .query_failed => false,
            else => true,
        };
    }

    pub fn label(self: ThreadVerdict) []const u8 {
        return switch (self.status) {
            .ok => "OK",
            .query_failed => "QUERY_FAILED",
            .spoof_trampoline => "SPOOF_TRAMPOLINE",
            .modified_host => "MODIFIED_HOST",
            .hollowed_host => "HOLLOWED_HOST",
            .mapped_nonpe => "MAPPED_NONPE",
            .staged_private_rw => "STAGED_PRIVATE_RW",
            .shellcode_private => "SHELLCODE_PRIVATE",
            .suspended_rip_anomaly => "SUSPENDED_RIP_ANOMALY",
        };
    }
};

pub const Hit = struct {
    sig_index: usize,
    offset: usize,
    encoding: Encoding,
    region_base: usize,
};

pub const Encoding = enum {
    ascii,
    utf16le,

    pub fn toString(self: Encoding) []const u8 {
        return switch (self) {
            .ascii => "ascii",
            .utf16le => "utf16le",
        };
    }
};

pub const CategoryScore = struct {
    score: u32 = 0,
    hit_count: u32 = 0,
    category: sigs.Category,
    first_offset: usize = 0,
};

pub const ScanResults = struct {
    hits: std.ArrayList(Hit),
    category_scores: [category_count]CategoryScore,
    pe_headers_found: u32 = 0,
    dotnet_headers_found: u32 = 0,
    regions_scanned: u32 = 0,
    bytes_scanned: u64 = 0,
    gpa: std.mem.Allocator,
    signatures: []const sigs.Signature,
    suspicious: std.ArrayList(sigs.Suspicion), // structual IOCs

    const category_count = @typeInfo(sigs.Category).@"enum".fields.len;

    pub fn init(allocator: std.mem.Allocator, sigs_slice: []const sigs.Signature) ScanResults {
        var cs: [category_count]CategoryScore = undefined;
        inline for (@typeInfo(sigs.Category).@"enum".fields, 0..) |f, i| {
            cs[i] = .{ .category = @enumFromInt(f.value) };
        }
        return .{
            .hits = .empty,
            .category_scores = cs,
            .gpa = allocator,
            .signatures = sigs_slice,
            .suspicious = .empty,
        };
    }

    pub fn deinit(self: *ScanResults) void {
        self.hits.deinit(self.gpa);
        self.suspicious.deinit(self.gpa);
    }
    pub fn addSuspicion(self: *ScanResults, s: sigs.Suspicion) !void {
        try self.suspicious.append(self.gpa, s);
    }
    pub fn addHit(self: *ScanResults, hit: Hit) !void {
        try self.hits.append(self.gpa, hit);
        const sig = &self.signatures[hit.sig_index];
        const ci = @intFromEnum(sig.category);
        self.category_scores[ci].score += sig.risk_score;
        self.category_scores[ci].hit_count += 1;
        if (self.category_scores[ci].first_offset == 0) {
            self.category_scores[ci].first_offset = hit.region_base + hit.offset;
        }
    }
};

pub fn analyzeRegionEntropy(
    process: api.HANDLE,
    base: usize,
    region_size: usize,
    is_executable: bool,
    allocator: std.mem.Allocator,
) !?sigs.EntropyAnalysis {
    if (region_size < 64) return null;

    const sample_size = @min(region_size, 64 * 1024);
    const buf = try allocator.alloc(u8, sample_size);
    defer allocator.free(buf);

    var bytes_read: usize = 0;
    const ok = api.ReadProcessMemory(process, base, buf.ptr, sample_size, &bytes_read);
    if (ok == api.FALSE or bytes_read == 0) return null;

    const data = buf[0..bytes_read];
    if (data.len < 64) return null;

    const sw = sigs.slidingWindowEntropy(data);
    const prelude = sigs.detectShellcodePrelude(data);
    const gradient = sigs.detectEntropyGradient(data);

    const peak_window_start = sw.offset;
    const peak_window_end = @min(peak_window_start + sigs.ENTROPY_WINDOW, data.len);
    const peak_slice = data[peak_window_start..peak_window_end];

    return .{
        .peak_entropy = sw.peak,
        .peak_offset = sw.offset,
        .chi_squared = sigs.chiSquaredUniformity(peak_slice),
        .null_byte_ratio = sigs.nullByteRatio(peak_slice),
        .has_shellcode_prelude = prelude,
        .has_entropy_gradient = gradient,
        .region_is_executable = is_executable,
    };
}

fn checkSectionExists(name: [*:0]const u16) bool {
    var us: api.UNICODE_STRING = undefined;
    api.RtlInitUnicodeString(&us, name);

    var oa: api.OBJECT_ATTRIBUTES = .{
        .Length = @sizeOf(api.OBJECT_ATTRIBUTES),
        .RootDirectory = null,
        .ObjectName = &us,
        .Attributes = OBJ_CASE_INSENSITIVE,
        .SecurityDescriptor = null,
        .SecurityQualityOfService = null,
    };

    var section: ?api.HANDLE = null;
    const status = api.NtOpenSection(&section, SECTION_QUERY, &oa);

    if (section) |h| _ = api.NtClose(h);
    return status == api.STATUS_SUCCESS or status == api.STATUS_ACCESS_DENIED;
}

pub fn isDotNetProcess(pid: u32) bool {
    var section_name: [128]u16 = undefined;

    var pid_buf: [16]u8 = undefined;
    const pid_str = std.fmt.bufPrint(&pid_buf, "{d}", .{pid}) catch return false;

    // .NET v4: \BaseNamedObjects\Cor_Private_IPCBlock_v4_<PID>
    const prefix_v4 = [_]u16{ '\\', 'B', 'a', 's', 'e', 'N', 'a', 'm', 'e', 'd', 'O', 'b', 'j', 'e', 'c', 't', 's', '\\', 'C', 'o', 'r', '_', 'P', 'r', 'i', 'v', 'a', 't', 'e', '_', 'I', 'P', 'C', 'B', 'l', 'o', 'c', 'k', '_', 'v', '4', '_' };

    var pos: usize = 0;
    for (prefix_v4) |c| {
        section_name[pos] = c;
        pos += 1;
    }
    for (pid_str) |c| {
        section_name[pos] = c;
        pos += 1;
    }
    section_name[pos] = 0;

    const name_v4: [*:0]const u16 = @ptrCast(&section_name);
    if (checkSectionExists(name_v4)) return true;

    // .NET v2: \BaseNamedObjects\Cor_Private_IPCBlock_<PID>
    const prefix_v2 = [_]u16{ '\\', 'B', 'a', 's', 'e', 'N', 'a', 'm', 'e', 'd', 'O', 'b', 'j', 'e', 'c', 't', 's', '\\', 'C', 'o', 'r', '_', 'P', 'r', 'i', 'v', 'a', 't', 'e', '_', 'I', 'P', 'C', 'B', 'l', 'o', 'c', 'k', '_' };

    pos = 0;
    for (prefix_v2) |c| {
        section_name[pos] = c;
        pos += 1;
    }
    for (pid_str) |c| {
        section_name[pos] = c;
        pos += 1;
    }
    section_name[pos] = 0;

    const name_v2: [*:0]const u16 = @ptrCast(&section_name);
    return checkSectionExists(name_v2);
}

/// Build set of all PEB module base addresses (modules loaded via LdrLoadDll).
pub fn buildPebModuleSet(allocator: std.mem.Allocator, pid: u32) !std.AutoHashMap(usize, void) {
    var set = std.AutoHashMap(usize, void).init(allocator);

    const snap = api.CreateToolhelp32Snapshot(api.TH32CS_SNAPMODULE | api.TH32CS_SNAPMODULE32, pid) orelse return set;
    defer _ = api.CloseHandle(snap);

    var me: api.MODULEENTRY32W = undefined;
    me.dwSize = @sizeOf(api.MODULEENTRY32W);
    if (api.Module32FirstW(snap, &me) == api.FALSE) return set;

    while (true) {
        try set.put(me.modBaseAddr, {});
        if (api.Module32NextW(snap, &me) == api.FALSE) break;
    }
    return set;
}

/// Count private (non-shared) pages within an IMAGE region.
/// Private pages = modified at runtime = shellcode / hook IOC.
///
/// Single batched K32QueryWorkingSetEx call one syscall per region instead of
/// one per page (~50-100x faster on a 5 MB region with ~1280 pages).
pub fn countPrivatePages(process: api.HANDLE, base: usize, region_size: usize) u32 {
    const page_count: usize = region_size / 0x1000;
    if (page_count == 0) return 0;

    const buf = std.heap.page_allocator.alloc(api.PSAPI_WORKING_SET_EX_INFORMATION, page_count) catch return 0;
    defer std.heap.page_allocator.free(buf);

    var i: usize = 0;
    while (i < page_count) : (i += 1) {
        buf[i] = .{ .VirtualAddress = base + i * 0x1000, .VirtualAttributes = .{} };
    }

    const cb_total: u32 = @intCast(@sizeOf(api.PSAPI_WORKING_SET_EX_INFORMATION) * page_count);
    if (api.K32QueryWorkingSetEx(process, buf.ptr, cb_total) == 0) return 0;

    var count: u32 = 0;
    for (buf) |e| {
        if (e.VirtualAttributes.Valid == 1 and e.VirtualAttributes.Shared == 0) count += 1;
    }
    return count;
}

/// Enumerate private page base addresses within a region. Caller owns the
/// returned slice and must free it with the provided allocator.
pub fn collectPrivatePages(
    allocator: std.mem.Allocator,
    process: api.HANDLE,
    base: usize,
    region_size: usize,
) ![]usize {
    const page_count: usize = region_size / 0x1000;
    if (page_count == 0) return allocator.alloc(usize, 0);

    const buf = try allocator.alloc(api.PSAPI_WORKING_SET_EX_INFORMATION, page_count);
    defer allocator.free(buf);

    var i: usize = 0;
    while (i < page_count) : (i += 1) {
        buf[i] = .{ .VirtualAddress = base + i * 0x1000, .VirtualAttributes = .{} };
    }

    const cb_total: u32 = @intCast(@sizeOf(api.PSAPI_WORKING_SET_EX_INFORMATION) * page_count);
    if (api.K32QueryWorkingSetEx(process, buf.ptr, cb_total) == 0) {
        return allocator.alloc(usize, 0);
    }

    var hits: usize = 0;
    for (buf) |e| {
        if (e.VirtualAttributes.Valid == 1 and e.VirtualAttributes.Shared == 0) hits += 1;
    }

    const out = try allocator.alloc(usize, hits);
    var w_idx: usize = 0;
    for (buf) |e| {
        if (e.VirtualAttributes.Valid == 1 and e.VirtualAttributes.Shared == 0) {
            out[w_idx] = e.VirtualAddress;
            w_idx += 1;
        }
    }
    return out;
}

/// Check if a MEM_IMAGE region is in the PEB module list. Hollowed?
pub fn pebContainsModule(peb_set: *const std.AutoHashMap(usize, void), allocation_base: usize) bool {
    return peb_set.contains(allocation_base);
}

pub fn scanPeHeaders(buf: []const u8, region_base: usize, results: *ScanResults) void {
    if (buf.len < 64) return;

    if (buf[0] == 'M' and buf[1] == 'Z') {
        if (buf.len > 0x40) {
            const e_lfanew = std.mem.readInt(u32, buf[0x3C..0x40], .little);
            if (e_lfanew > 0 and e_lfanew + 4 <= buf.len) {
                if (buf[e_lfanew] == 'P' and buf[e_lfanew + 1] == 'E' and
                    buf[e_lfanew + 2] == 0 and buf[e_lfanew + 3] == 0)
                {
                    results.pe_headers_found += 1;

                    if (scanForBsjb(buf)) {
                        results.dotnet_headers_found += 1;
                    }
                    _ = region_base;
                }
            }
        }
    }
}

fn scanForBsjb(buf: []const u8) bool {
    const needle = "BSJB";
    if (buf.len < needle.len) return false;
    var i: usize = 0;
    while (i <= buf.len - needle.len) : (i += 1) {
        if (std.mem.eql(u8, buf[i..][0..needle.len], needle)) return true;
    }
    return false;
}

///
/// Compile-time addresses of well-known spoof-trampoline targets used by
/// EarlyBird / APC / NtSetInformationThread tricks to make a malicious thread
/// look like it started at a benign function. Resolved lazily.
///
const SpoofTrampolineCache = struct {
    initialized: bool = false,
    addrs: [16]usize = [_]usize{0} ** 16,
    count: usize = 0,
};
var spoof_cache: SpoofTrampolineCache = .{};

///
/// Spoof-target denylist: function names that legitimate code essentially
/// never sets as `Win32StartAddress`, but which APC / EarlyBird shellcode
/// loaders frequently spoof to. Walks kernel32 / ntdll / shell32 / advapi32.
/// this list is prepared based on common vector presence, could be modified/add/delete.
///
const SPOOF_TARGETS = [_]struct { dll: [*:0]const u8, name: [*:0]const u8 }{
    .{ .dll = "kernel32", .name = "LoadLibraryA" },
    .{ .dll = "kernel32", .name = "LoadLibraryW" },
    .{ .dll = "kernel32", .name = "LoadLibraryExA" },
    .{ .dll = "kernel32", .name = "LoadLibraryExW" },
    .{ .dll = "kernel32", .name = "WinExec" },
    .{ .dll = "kernel32", .name = "CreateProcessA" },
    .{ .dll = "kernel32", .name = "CreateProcessW" },
    .{ .dll = "kernel32", .name = "VirtualAlloc" },
    .{ .dll = "kernel32", .name = "VirtualAllocEx" },
    .{ .dll = "ntdll", .name = "RtlExitUserThread" },
    .{ .dll = "ntdll", .name = "RtlExitUserProcess" },
    .{ .dll = "ntdll", .name = "NtTerminateProcess" },
    .{ .dll = "shell32", .name = "ShellExecuteW" },
    .{ .dll = "shell32", .name = "ShellExecuteA" },
};

/// Build the denylist of trampoline addresses by resolving each (dll,name)
/// pair in the **scanner process**. Note: this only matches when the target
/// process loads the same DLL at the same base, which is the default on Win7+
/// where system DLLs share an ASLR base across processes within a session.
/// Without per-process resolution this catches the common 32-bit-on-64-bit
/// case poorly, but is good enough for the typical IIS / w3wp scenario.
fn initSpoofCache() void {
    if (spoof_cache.initialized) return;
    spoof_cache.initialized = true;

    for (SPOOF_TARGETS) |t| {
        const h = api.GetModuleHandleA(t.dll) orelse continue;
        const addr = api.GetProcAddress(h, t.name) orelse continue;
        if (spoof_cache.count >= spoof_cache.addrs.len) break;
        spoof_cache.addrs[spoof_cache.count] = @intFromPtr(addr);
        spoof_cache.count += 1;
    }
}

fn isSpoofTrampoline(addr: usize) bool {
    for (spoof_cache.addrs[0..spoof_cache.count]) |a| {
        if (a == addr) return true;
    }
    return false;
}

/// Per-process state passed into the validator. Encapsulates everything
/// queryAndVerdict needs for classification.
pub const TsavContext = struct {
    process: api.HANDLE,
    pid: u32,
    is_wow64: bool,
    bad_alloc_bases: *const std.AutoHashMap(usize, void),
    peb_bases: *const std.AutoHashMap(usize, void),
};

pub fn validateThreadStartAddresses(
    allocator: std.mem.Allocator,
    ctx: TsavContext,
    module_map: anytype,
) ![]ThreadVerdict {
    initSpoofCache();

    var results: std.ArrayList(ThreadVerdict) = .empty;
    defer results.deinit(allocator);

    const snap = api.CreateToolhelp32Snapshot(api.TH32CS_SNAPTHREAD, 0) orelse
        return try results.toOwnedSlice(allocator);
    defer _ = api.CloseHandle(snap);

    var te: api.THREADENTRY32 = undefined;
    te.dwSize = @sizeOf(api.THREADENTRY32);

    if (api.Thread32First(snap, &te) == api.FALSE) {
        return try results.toOwnedSlice(allocator);
    }

    while (true) {
        if (te.th32OwnerProcessID == ctx.pid) {
            const verdict = checkThreadStart(ctx, te.th32ThreadID, module_map);
            try results.append(allocator, verdict);
        }
        if (api.Thread32Next(snap, &te) == api.FALSE) break;
    }

    return try results.toOwnedSlice(allocator);
}

fn checkThreadStart(
    ctx: TsavContext,
    tid: u32,
    module_map: anytype,
) ThreadVerdict {
    //  need both QUERY_INFORMATION and GET_CONTEXT for the RIP check.
    // Fall back progressively if the wider rights are denied.
    const full_rights = api.THREAD_QUERY_INFORMATION | api.THREAD_GET_CONTEXT;
    if (api.OpenThread(full_rights, api.FALSE, tid)) |h| {
        defer _ = api.CloseHandle(h);
        return queryAndVerdict(h, tid, ctx, module_map, true);
    }
    if (api.OpenThread(api.THREAD_QUERY_INFORMATION, api.FALSE, tid)) |h| {
        defer _ = api.CloseHandle(h);
        return queryAndVerdict(h, tid, ctx, module_map, false);
    }
    if (api.OpenThread(api.THREAD_QUERY_LIMITED_INFORMATION, api.FALSE, tid)) |h| {
        defer _ = api.CloseHandle(h);
        return queryAndVerdict(h, tid, ctx, module_map, false);
    }
    return emptyVerdict(tid, .query_failed);
}

fn emptyVerdict(tid: u32, st: ThreadStatus) ThreadVerdict {
    return .{
        .thread_id = tid,
        .start_address = 0,
        .status = st,
        .module_name = [_]u8{0} ** 64,
        .module_name_len = 0,
    };
}

fn queryAndVerdict(
    hThread: api.HANDLE,
    tid: u32,
    ctx: TsavContext,
    module_map: anytype,
    have_context: bool,
) ThreadVerdict {
    var start_addr: usize = 0;
    const status = api.NtQueryInformationThread(
        hThread,
        .ThreadQuerySetWin32StartAddress,
        &start_addr,
        @sizeOf(usize),
        null,
    );
    if (status != 0) return emptyVerdict(tid, .query_failed);

    var verdict = classifyAddress(start_addr, ctx, module_map);
    verdict.thread_id = tid;
    verdict.start_address = start_addr;

    // If start_address classified as OK we still do a RIP cross-check. The
    // classic Win32StartAddress spoof rewrites the field but cannot easily
    // rewrite the actual instruction pointer of a suspended thread.
    //
    if (have_context and verdict.status == .ok) {
        if (readThreadRip(hThread, ctx.is_wow64)) |rip| {
            if (rip != 0 and rip != start_addr) {
                const rip_verdict = classifyAddress(rip, ctx, module_map);
                if (rip_verdict.isSuspicious()) {
                    var out = rip_verdict;
                    out.thread_id = tid;
                    out.start_address = start_addr;
                    out.rip_address = rip;
                    //
                    // Even a hollowed/modified host found via RIP rather than
                    // start_address is recorded as suspended_rip_anomaly so
                    // operators see the discrepanccy clearly.
                    //
                    if (out.status != .shellcode_private and
                        out.status != .staged_private_rw)
                    {
                        out.status = .suspended_rip_anomaly;
                    }
                    return out;
                }
            }
        }
    }
    return verdict;
}

///
/// Classify a single virtual address (start_addr or RIP) against the target
/// process. Uses VirtualQueryEx to determine region type + protection, then
/// cross-references the module map, PEB module list, and the set of
/// allocation bases that already have L1-L5 suspicions.
///
fn classifyAddress(
    addr: usize,
    ctx: TsavContext,
    module_map: anytype,
) ThreadVerdict {
    if (addr == 0) return emptyVerdict(0, .query_failed);

    if (isSpoofTrampoline(addr)) {
        return .{
            .thread_id = 0,
            .start_address = addr,
            .status = .spoof_trampoline,
            .module_name = [_]u8{0} ** 64,
            .module_name_len = 0,
        };
    }

    var mbi: api.MEMORY_BASIC_INFORMATION = undefined;
    const qr = api.VirtualQueryEx(ctx.process, addr, &mbi, @sizeOf(api.MEMORY_BASIC_INFORMATION));
    if (qr == 0) {
        // VirtualQuery failed but we still have an address. Treat as anomaly
        // unless it landed in a known module (defensive fallthrough).
        return classifyAddressFallback(addr, module_map);
    }

    const alloc_base = mbi.AllocationBase;

    switch (mbi.Type) {
        api.MEM_IMAGE => {
            const mod_opt = module_map.get(alloc_base);
            const in_peb = pebContainsModule(ctx.peb_bases, alloc_base);
            const is_bad = ctx.bad_alloc_bases.contains(alloc_base);

            if (!in_peb) {
                return makeVerdictWithName(addr, .hollowed_host, mod_opt);
            }
            if (is_bad) {
                return makeVerdictWithName(addr, .modified_host, mod_opt);
            }
            return makeVerdictWithName(addr, .ok, mod_opt);
        },
        api.MEM_PRIVATE => {
            if (api.isExecutable(mbi.Protect)) {
                return .{
                    .thread_id = 0,
                    .start_address = addr,
                    .status = .shellcode_private,
                    .module_name = [_]u8{0} ** 64,
                    .module_name_len = 0,
                };
            }
            return .{
                .thread_id = 0,
                .start_address = addr,
                .status = .staged_private_rw,
                .module_name = [_]u8{0} ** 64,
                .module_name_len = 0,
            };
        },
        api.MEM_MAPPED => {
            return .{
                .thread_id = 0,
                .start_address = addr,
                .status = .mapped_nonpe,
                .module_name = [_]u8{0} ** 64,
                .module_name_len = 0,
            };
        },
        else => {
            return classifyAddressFallback(addr, module_map);
        },
    }
}

fn classifyAddressFallback(addr: usize, module_map: anytype) ThreadVerdict {
    // Linear scan as last resort.
    var it = module_map.by_base.iterator();
    while (it.next()) |entry| {
        const idx = entry.value_ptr.*;
        const mod_info = &module_map.entries.items[idx];
        if (addr >= mod_info.base and addr < mod_info.base + mod_info.size) {
            const opt: ?*const @TypeOf(mod_info.*) = mod_info;
            return makeVerdictWithName(addr, .ok, opt);
        }
    }
    return .{
        .thread_id = 0,
        .start_address = addr,
        .status = .shellcode_private,
        .module_name = [_]u8{0} ** 64,
        .module_name_len = 0,
    };
}

/// `mod_opt` must be `?*const ModuleInfo`. Callers should pass `null`
fn makeVerdictWithName(addr: usize, st: ThreadStatus, mod_opt: anytype) ThreadVerdict {
    var name_buf: [64]u8 = [_]u8{0} ** 64;
    var name_len: usize = 0;
    if (mod_opt) |mi| {
        name_len = @min(mi.basename.len, 63);
        @memcpy(name_buf[0..name_len], mi.basename[0..name_len]);
    }
    return .{
        .thread_id = 0,
        .start_address = addr,
        .status = st,
        .module_name = name_buf,
        .module_name_len = name_len,
    };
}

/// Read the instruction pointer from a thread's CONTEXT. Returns null if the
/// thread is running (GetThreadContext on a running thread is racy and
/// generally rejected anyway), or if the call fails.
///
fn readThreadRip(hThread: api.HANDLE, is_wow64: bool) ?usize {
    if (is_wow64) {
        var ctx: api.Wow64ContextBuf = undefined;
        @memset(&ctx.bytes, 0);
        // ContextFlags lives at offset 0 in WOW64_CONTEXT.
        std.mem.writeInt(u32, ctx.bytes[0..4], api.WOW64_CONTEXT_CONTROL, .little);
        if (api.Wow64GetThreadContext(hThread, &ctx) == api.FALSE) return null;
        const eip = std.mem.readInt(u32, ctx.bytes[api.WOW64_CONTEXT_EIP_OFFSET..][0..4], .little);
        return @intCast(eip);
    } else {
        var ctx: api.ContextAmd64Buf = undefined;
        @memset(&ctx.bytes, 0);
        std.mem.writeInt(u32, ctx.bytes[api.CONTEXT_AMD64_CONTEXT_FLAGS_OFFSET..][0..4], api.CONTEXT_CONTROL_AMD64, .little);
        if (api.GetThreadContext(hThread, &ctx) == api.FALSE) return null;
        const rip = std.mem.readInt(u64, ctx.bytes[api.CONTEXT_AMD64_RIP_OFFSET..][0..8], .little);
        return @intCast(rip);
    }
}
