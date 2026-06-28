const std = @import("std");

pub const Category = enum {
    engine_xslt, // Engine 1: XSLT msxsl:script compilation
    engine_codedom, // Engine 2: CSharpCodeProvider in-memory compilation
    engine_managed, // Engine 3: Assembly.Load / Process.Start / direct managed
    c2_tcp, // T1: TCP channel
    c2_http, // T2: HTTP beacon
    c2_sql, // T3: SQL dead-drop
    c2_smtp, // T4: SMTP exfiltration
    c2_file, // T5: File-based C2 via App_Data
    c2_dns, // T6: DNS exfiltration
    evasion, // Access control, fake 404, scanner blacklist
    reflective_load, // PE/MZ + BSJB in non-file-backed memory
    webshell_generic, // Generic webshell indicators

    pub fn toMitre(self: Category) []const u8 {
        return switch (self) {
            .engine_xslt => "T1220",
            .engine_codedom => "T1027.004",
            .engine_managed => "T1620",
            .c2_tcp => "T1071.001",
            .c2_http => "T1071.001",
            .c2_sql => "T1071.002",
            .c2_smtp => "T1048.003",
            .c2_file => "T1105",
            .c2_dns => "T1048.001",
            .evasion => "T1562.001",
            .reflective_load => "T1620",
            .webshell_generic => "T1505.003",
        };
    }

    pub fn toString(self: Category) []const u8 {
        return switch (self) {
            .engine_xslt => "ENGINE_XSLT",
            .engine_codedom => "ENGINE_CODEDOM",
            .engine_managed => "ENGINE_MANAGED",
            .c2_tcp => "C2_TCP",
            .c2_http => "C2_HTTP",
            .c2_sql => "C2_SQL",
            .c2_smtp => "C2_SMTP",
            .c2_file => "C2_FILE",
            .c2_dns => "C2_DNS",
            .evasion => "EVASION",
            .reflective_load => "REFLECTIVE_LOAD",
            .webshell_generic => "WEBSHELL_GENERIC",
        };
    }
};

pub const Severity = enum {
    critical,
    high,
    medium,
    low,
    info,

    pub fn toString(self: Severity) []const u8 {
        return switch (self) {
            .critical => "CRITICAL",
            .high => "HIGH",
            .medium => "MEDIUM",
            .low => "LOW",
            .info => "INFO",
        };
    }

    pub fn fromScore(score: u32) Severity {
        if (score >= 8) return .critical;
        if (score >= 5) return .high;
        if (score >= 3) return .medium;
        if (score >= 1) return .low;
        return .info;
    }
};

pub const SuspicionType = enum {
    clr_init,
    missing_peb_entry,
    modified_code_low,
    modified_code_medium,
    modified_code_high,
    private_rwx,
    unsigned_image,
    inconsistent_perms,
    dotnet_ngen,
    hook_prologue,
    disk_mem_diff,
    thread_start_anomaly, // TSAV => Thread Start Address Validation (generic)
    // Discriminated TSAV outcomes (see scanner.ThreadStatus):
    thread_shellcode_private,
    thread_staged_private_rw,
    thread_mapped_nonpe,
    thread_hollowed_host,
    thread_modified_host,
    thread_spoof_trampoline,
    thread_suspended_rip_anomaly,
    xor_pe_header, // PE found in memory under single/multi-byte XOR (Donut, sleep_mask, etc.)
    entropy_encrypted, // peak window entropy >= 7.5 + corroboration (prelude, chi-sq, TSAV)
    entropy_shellcode, // shellcode prelude match or entropy gradient (decoder stub + payload)
    entropy_suspicious, // peak window entropy >= 7.0, no corroboration
    heap_api_table, // heap-resident resolved API pointer table (API hashing)
};

pub const Suspicion = struct {
    kind: SuspicionType,
    address: usize,
    size: usize,
    private_pages: u32 = 0,
    region_pages: u32 = 0,
    // Optional human-readable evidence (e.g. contributing module names for
    // HEAP_API_TABLE). Fixed-size to avoid allocator/lifetime concerns.
    evidence_buf: [192]u8 = [_]u8{0} ** 192,
    evidence_len: u8 = 0,

    pub fn evidence(self: *const Suspicion) []const u8 {
        return self.evidence_buf[0..self.evidence_len];
    }

    pub fn setEvidence(self: *Suspicion, s: []const u8) void {
        const n: u8 = @intCast(@min(s.len, self.evidence_buf.len));
        @memcpy(self.evidence_buf[0..n], s[0..n]);
        self.evidence_len = n;
    }

    /// Plain-English explanation of what this finding means and why it
    /// matters. Shown beneath the headline label in the console report.
    pub fn description(self: Suspicion) []const u8 {
        return switch (self.kind) {
            .clr_init => "Process hosts the .NET runtime (informational, not malicious by itself).",
            .missing_peb_entry => "Loaded image not registered in the PEB module list - DLL hollowing or module stomping.",
            .modified_code_low => "Image has a few private (modified) executable pages - weak signal.",
            .modified_code_medium => "Image has private executable pages corroborated by an external signal.",
            .modified_code_high => "Image has many private executable pages or a hook prologue / disk-diff confirmed.",
            .private_rwx => "Executable + writable private region - classic shellcode buffer.",
            .unsigned_image => "Loaded module is not Authenticode-signed.",
            .inconsistent_perms => "Page permissions differ between memory and the on-disk PE layout.",
            .dotnet_ngen => "Native-compiled .NET image - benign unless paired with other IOCs.",
            .hook_prologue => "Function start patched with a JMP / trampoline - inline API hook.",
            .disk_mem_diff => "Image bytes in memory differ from the file on disk at the same RVA.",
            .thread_start_anomaly => "One or more threads start at addresses that fail validation.",
            .thread_shellcode_private => "Thread start address is inside a private executable region (shellcode thread).",
            .thread_staged_private_rw => "Thread starts inside a private RW region - likely staged payload pre-VirtualProtect.",
            .thread_mapped_nonpe => "Thread starts inside a MEM_MAPPED region with no PE header.",
            .thread_hollowed_host => "Thread starts inside a module whose allocation was flagged as hollowed.",
            .thread_modified_host => "Thread starts inside a module whose code pages were flagged as modified.",
            .thread_spoof_trampoline => "Thread start looks like a call-stack spoofing trampoline.",
            .thread_suspended_rip_anomaly => "Suspended thread's RIP lands in a flagged allocation.",
            .xor_pe_header => "MZ/PE header obfuscated with a short XOR key - staged payload.",
            .entropy_encrypted => "High-entropy private region with corroborating signals - encrypted payload.",
            .entropy_shellcode => "Shellcode prelude or entropy gradient detected (decoder stub + payload).",
            .entropy_suspicious => "High peak entropy but no corroboration - weak signal.",
            .heap_api_table => "Heap-resident function pointer table referencing multiple system DLLs - hallmark of runtime API resolution / API hashing used by C2 implants.",
        };
    }

    pub fn label(self: Suspicion) []const u8 {
        return switch (self.kind) {
            .clr_init => "CLR_INIT",
            .missing_peb_entry => "MISSING_PEB",
            .modified_code_low => "MODIFIED_CODE_LOW",
            .modified_code_medium => "MODIFIED_CODE_MED",
            .modified_code_high => "MODIFIED_CODE_HIGH",
            .private_rwx => "PRIVATE_RWX",
            .unsigned_image => "UNSIGNED_MODULE",
            .inconsistent_perms => "DISK_MEM_MISMATCH",
            .dotnet_ngen => "DOTNET_NGEN",
            .hook_prologue => "HOOK_PROLOGUE",
            .disk_mem_diff => "DISK_MEM_DIFF",
            .thread_start_anomaly => "THREAD_START_ANOMALY",
            .thread_shellcode_private => "TSAV_SHELLCODE_PRIVATE",
            .thread_staged_private_rw => "TSAV_STAGED_PRIVATE_RW",
            .thread_mapped_nonpe => "TSAV_MAPPED_NONPE",
            .thread_hollowed_host => "TSAV_HOLLOWED_HOST",
            .thread_modified_host => "TSAV_MODIFIED_HOST",
            .thread_spoof_trampoline => "TSAV_SPOOF_TRAMPOLINE",
            .thread_suspended_rip_anomaly => "TSAV_SUSPENDED_RIP",
            .xor_pe_header => "XOR_PE_HEADER",
            .entropy_encrypted => "ENTROPY_ENCRYPTED",
            .entropy_shellcode => "ENTROPY_SHELLCODE",
            .entropy_suspicious => "ENTROPY_SUSPICIOUS",
            .heap_api_table => "HEAP_API_TABLE",
        };
    }

    pub fn severity(self: Suspicion) []const u8 {
        return switch (self.kind) {
            .thread_shellcode_private,
            .thread_suspended_rip_anomaly,
            .xor_pe_header,
            .entropy_encrypted,
            => "INFO",
            .missing_peb_entry,
            .modified_code_high,
            .private_rwx,
            .disk_mem_diff,
            .thread_hollowed_host,
            .thread_modified_host,
            .thread_staged_private_rw,
            .thread_start_anomaly,
            .entropy_shellcode,
            => "INFO",
            .modified_code_medium,
            .hook_prologue,
            .inconsistent_perms,
            .thread_mapped_nonpe,
            .thread_spoof_trampoline,
            .entropy_suspicious,
            => "MEDIUM",
            .modified_code_low, .unsigned_image, .dotnet_ngen => "LOW",
            .clr_init => "INFO",
            .heap_api_table => "HIGH",
        };
    }
};

pub const XorPeMatch = struct {
    key: [16]u8 = [_]u8{0} ** 16,
    key_len: u8 = 0,
    offset: usize = 0,

    pub fn keyByte(self: XorPeMatch, i: usize) u8 {
        return self.key[i % self.key_len];
    }
};

pub const XOR_KEY_LENGTHS = [_]u8{ 1, 4, 8, 16 };

const DOS_STUB_ANCHOR: []const u8 = "This program cannot be run in DOS mode.";

const DOS_STUB_OFFSET: usize = 0x4E;

pub const Signature = struct {
    pattern: []const u8,
    risk_score: u32,
    category: Category,
    description: []const u8,
};

pub const LoadedRules = struct {
    merged_sigs: []Signature,
    raw_buffers: std.ArrayList([]const u8),
    parsed_list: std.ArrayList(std.json.Parsed([]Signature)),
    allocator: std.mem.Allocator,

    pub fn deinit(self: *LoadedRules) void {
        self.allocator.free(self.merged_sigs);
        for (self.parsed_list.items) |*p| p.deinit();
        self.parsed_list.deinit(self.allocator);
        for (self.raw_buffers.items) |buf| self.allocator.free(buf);
        self.raw_buffers.deinit(self.allocator);
    }
};

pub fn readRules(allocator: std.mem.Allocator, path: []const u8) !LoadedRules {
    const result = try loadOneFile(allocator, path);

    var raw_buffers: std.ArrayList([]const u8) = .empty;
    try raw_buffers.append(allocator, result.raw);

    var parsed_list: std.ArrayList(std.json.Parsed([]Signature)) = .empty;
    try parsed_list.append(allocator, result.parsed);

    const merged = try allocator.alloc(Signature, result.parsed.value.len);
    @memcpy(merged, result.parsed.value);

    return .{
        .merged_sigs = merged,
        .raw_buffers = raw_buffers,
        .parsed_list = parsed_list,
        .allocator = allocator,
    };
}

pub fn readRulesDirWin32(allocator: std.mem.Allocator, dir_path: []const u8) !LoadedRules {
    var raw_buffers: std.ArrayList([]const u8) = .empty;
    var parsed_list: std.ArrayList(std.json.Parsed([]Signature)) = .empty;
    var total_count: usize = 0;

    var find_data: WIN32_FIND_DATAA = std.mem.zeroes(WIN32_FIND_DATAA);

    const pattern = try std.fmt.allocPrint(allocator, "{s}\\*.json\x00", .{dir_path});
    defer allocator.free(pattern);
    const pattern_z: [*:0]const u8 = @ptrCast(pattern.ptr);

    const find_handle = FindFirstFileA(pattern_z, &find_data) orelse {
        return .{
            .merged_sigs = try allocator.alloc(Signature, 0),
            .raw_buffers = raw_buffers,
            .parsed_list = parsed_list,
            .allocator = allocator,
        };
    };
    defer _ = FindClose(find_handle);

    while (true) {
        const fname = std.mem.sliceTo(&find_data.cFileName, 0);
        if (fname.len > 5) {
            const full_path = try std.fmt.allocPrint(allocator, "{s}\\{s}", .{ dir_path, fname });
            defer allocator.free(full_path);

            if (loadOneFile(allocator, full_path)) |result| {
                try raw_buffers.append(allocator, result.raw);
                try parsed_list.append(allocator, result.parsed);
                total_count += result.parsed.value.len;
            } else |_| {}
        }

        if (FindNextFileA(find_handle, &find_data) == 0) break;
    }

    const merged = try allocator.alloc(Signature, total_count);
    var offset: usize = 0;
    for (parsed_list.items) |p| {
        @memcpy(merged[offset..][0..p.value.len], p.value);
        offset += p.value.len;
    }

    return .{
        .merged_sigs = merged,
        .raw_buffers = raw_buffers,
        .parsed_list = parsed_list,
        .allocator = allocator,
    };
}

const FileLoadResult = struct {
    raw: []const u8,
    parsed: std.json.Parsed([]Signature),
};

fn loadOneFile(allocator: std.mem.Allocator, path: []const u8) !FileLoadResult {
    const path_z = try allocator.dupeZ(u8, path);
    defer allocator.free(path_z);

    const raw_handle = CreateFileA(
        path_z.ptr,
        GENERIC_READ,
        FILE_SHARE_READ,
        null,
        OPEN_EXISTING,
        0,
        null,
    );
    const handle = raw_handle orelse return error.FileOpenFailed;
    if (handle == @as(FILEHANDLE, @ptrFromInt(~@as(usize, 0)))) return error.FileOpenFailed;
    defer _ = CloseHandle(handle);

    const size = GetFileSize(handle, null);
    if (size == 0 or size == 0xFFFFFFFF) return error.FileReadFailed;

    const data = try allocator.alloc(u8, size);
    errdefer allocator.free(data);

    var bytes_read: u32 = 0;
    if (ReadFile(handle, data.ptr, size, &bytes_read, null) == 0) {
        return error.FileReadFailed;
    }

    const parsed = std.json.parseFromSlice([]Signature, allocator, data[0..bytes_read], .{ .allocate = .alloc_always }) catch |err| {
        return err;
    };

    return .{ .raw = data[0..bytes_read], .parsed = parsed };
}

pub fn findXorPeHeader(buf: []const u8) ?XorPeMatch {
    const min_pe_size: usize = DOS_STUB_OFFSET + DOS_STUB_ANCHOR.len;
    if (buf.len < min_pe_size) return null;

    inline for (XOR_KEY_LENGTHS) |key_len| {
        if (findXorPeWithKeyLen(buf, key_len)) |m| return m;
    }
    return null;
}

fn findXorPeWithKeyLen(buf: []const u8, comptime key_len: u8) ?XorPeMatch {
    const min_pe_size: usize = DOS_STUB_OFFSET + DOS_STUB_ANCHOR.len;
    if (buf.len < min_pe_size) return null;
    const max_offset = buf.len - min_pe_size;

    var offset: usize = 0;
    while (offset <= max_offset) : (offset += 1) {
        var key: [16]u8 = [_]u8{0} ** 16;
        key[0] = buf[offset] ^ 'M';
        if (key_len >= 2) key[1] = buf[offset + 1] ^ 'Z';

        if (key_len == 1 and key[0] == 0) continue;

        if (key_len > 2) {
            var ki: usize = 2;
            while (ki < key_len) : (ki += 1) {
                const stub_idx = findStubIndexForKeyPos(ki, key_len);
                const ct = buf[offset + DOS_STUB_OFFSET + stub_idx];
                const pt = DOS_STUB_ANCHOR[stub_idx];
                key[ki] = ct ^ pt;
            }
            // Reject trivial all-zero key for any length.
            var all_zero = true;
            var z: usize = 0;
            while (z < key_len) : (z += 1) {
                if (key[z] != 0) {
                    all_zero = false;
                    break;
                }
            }
            if (all_zero) continue;
        }

        if (!verifyDosStub(buf, offset, key[0..key_len])) continue;

        if (!verifyPeMagic(buf, offset, key[0..key_len])) continue;

        var out = XorPeMatch{ .offset = offset, .key_len = key_len };
        @memcpy(out.key[0..key_len], key[0..key_len]);
        return out;
    }
    return null;
}

fn findStubIndexForKeyPos(target_pos: usize, key_len: u8) usize {
    var p: usize = 0;
    while (p < key_len) : (p += 1) {
        if ((DOS_STUB_OFFSET + p) % key_len == target_pos) return p;
    }
    unreachable;
}

fn verifyDosStub(buf: []const u8, pe_offset: usize, key: []const u8) bool {
    if (pe_offset + DOS_STUB_OFFSET + DOS_STUB_ANCHOR.len > buf.len) return false;
    var i: usize = 0;
    while (i < DOS_STUB_ANCHOR.len) : (i += 1) {
        const ct = buf[pe_offset + DOS_STUB_OFFSET + i];
        const k = key[(DOS_STUB_OFFSET + i) % key.len];
        if ((ct ^ k) != DOS_STUB_ANCHOR[i]) return false;
    }
    return true;
}

fn verifyPeMagic(buf: []const u8, pe_offset: usize, key: []const u8) bool {
    // e_lfanew lives at offset 0x3C in IMAGE_DOS_HEADER (4 bytes, little-endian).
    if (pe_offset + 0x40 > buf.len) return false;

    var e_lfanew_bytes: [4]u8 = undefined;
    var i: usize = 0;
    while (i < 4) : (i += 1) {
        const ct = buf[pe_offset + 0x3C + i];
        const k = key[(0x3C + i) % key.len];
        e_lfanew_bytes[i] = ct ^ k;
    }
    const e_lfanew = std.mem.readInt(u32, &e_lfanew_bytes, .little);

    // Sanity: e_lfanew should be small (< 4 KB for a typical PE) and aligned.
    if (e_lfanew < 0x40 or e_lfanew > 0x1000) return false;
    if (pe_offset + e_lfanew + 4 > buf.len) return false;

    // Decrypt `PE\0\0` at e_lfanew and verify.
    const pe_chars = [_]u8{ 'P', 'E', 0, 0 };
    var j: usize = 0;
    while (j < 4) : (j += 1) {
        const ct = buf[pe_offset + e_lfanew + j];
        const k = key[(e_lfanew + j) % key.len];
        if ((ct ^ k) != pe_chars[j]) return false;
    }
    return true;
}

pub fn shannonEntropy(buf: []const u8) f64 {
    if (buf.len == 0) return 0.0;
    var counts: [256]u32 = [_]u32{0} ** 256;
    for (buf) |b| {
        counts[b] += 1;
    }

    const len_f: f64 = @floatFromInt(buf.len);
    var entropy: f64 = 0.0;
    for (counts) |c| {
        if (c == 0) continue;
        const p: f64 = @as(f64, @floatFromInt(c)) / len_f;
        entropy -= p * @log2(p);
    }
    return entropy;
}

pub const ENTROPY_WINDOW: usize = 256;
pub const ENTROPY_STRIDE: usize = 64;

pub const EntropyAnalysis = struct {
    peak_entropy: f64 = 0.0,
    peak_offset: usize = 0,
    chi_squared: f64 = 0.0,
    null_byte_ratio: f64 = 0.0,
    has_shellcode_prelude: bool = false,
    has_entropy_gradient: bool = false,
    region_is_executable: bool = false,

    pub fn gradeVerdict(self: EntropyAnalysis) SuspicionType {
        // CRITICAL: very high entropy + structural shellcode evidence
        if (self.peak_entropy >= 7.5 and
            (self.has_shellcode_prelude or
                (self.chi_squared < 300.0 and self.null_byte_ratio < 0.008)))
        {
            return .entropy_encrypted;
        }

        if (self.has_entropy_gradient) {
            return .entropy_shellcode;
        }
        if (self.has_shellcode_prelude and self.peak_entropy >= 6.5) {
            return .entropy_shellcode;
        }

        return .clr_init;
    }
};

/// Sliding-window entropy scan. Returns the peak window entropy and
/// the offset where it was found.\
///
pub fn slidingWindowEntropy(buf: []const u8) struct { peak: f64, offset: usize } {
    if (buf.len < ENTROPY_WINDOW) {
        return .{ .peak = shannonEntropy(buf), .offset = 0 };
    }

    var peak: f64 = 0.0;
    var peak_off: usize = 0;
    var off: usize = 0;
    while (off + ENTROPY_WINDOW <= buf.len) : (off += ENTROPY_STRIDE) {
        const e = shannonEntropy(buf[off..][0..ENTROPY_WINDOW]);
        if (e > peak) {
            peak = e;
            peak_off = off;
        }
    }
    return .{ .peak = peak, .offset = peak_off };
}

///
/// Chi-squared statistic against a uniform byte distribution.
/// Perfectly uniform (encrypted) data produces values near 256.
/// Normal code / text produces values in the thousands.
///
pub fn chiSquaredUniformity(buf: []const u8) f64 {
    if (buf.len == 0) return 0.0;
    var counts: [256]u32 = [_]u32{0} ** 256;
    for (buf) |b| counts[b] += 1;

    const expected: f64 = @as(f64, @floatFromInt(buf.len)) / 256.0;
    var chi_sq: f64 = 0.0;
    for (counts) |c| {
        const observed: f64 = @floatFromInt(c);
        const diff = observed - expected;
        chi_sq += (diff * diff) / expected;
    }
    return chi_sq;
}

/// Ratio of null (0x00) bytes in the buffer.
/// Encrypted data has ~1/256 = 0.0039; x86 code has much higher null density.
pub fn nullByteRatio(buf: []const u8) f64 {
    if (buf.len == 0) return 0.0;
    var count: u32 = 0;
    for (buf) |b| {
        if (b == 0) count += 1;
    }
    return @as(f64, @floatFromInt(count)) / @as(f64, @floatFromInt(buf.len));
}

/// Detect shellcode-specific instruction sequences in the first 64 bytes.
///
/// Only multi-byte patterns that are genuinely rare in legitimate code.
/// Single-byte opcodes (FC, 60, 9C) and common instructions (XOR RCX,RCX)
/// are excluded -- they appear in JIT output, browser engines, and system
/// stubs far too often to be useful without additional context.
///
/// Patterns kept (all >= 5 bytes, low FP rate):
///   E8 00 00 00 00                    CALL $+5 (GetPC, position-independent code)
///   64 A1 30 00 00 00                 MOV EAX, FS:[0x30] (PEB access, x86)
///   65 48 8B 04 25 60 00 00 00        MOV RAX, GS:[0x60] (PEB access, x64)
///   64 8B 35 30 00 00 00              MOV ESI, FS:[0x30] (PEB via ESI, x86)
///   64 8B 1D 30 00 00 00              MOV EBX, FS:[0x30] (PEB via EBX, x86)
///   FC 48 83 E4 F0                    CLD; AND RSP,-10h (Metasploit x64 full opener)
///   60 89 E5                          PUSHAD; MOV EBP,ESP (Metasploit x86 opener)
///   FC E8                             CLD; CALL (Metasploit block_api pattern)
pub fn detectShellcodePrelude(buf: []const u8) bool {
    if (buf.len < 5) return false;
    const n = @min(buf.len, 64);
    const b = buf[0..n];

    // FC 48 83 E4 F0 -- CLD; AND RSP, -0x10 (Metasploit x64 standard)
    if (n >= 5 and b[0] == 0xFC and b[1] == 0x48 and b[2] == 0x83 and
        b[3] == 0xE4 and b[4] == 0xF0) return true;
    // FC E8 -- CLD; CALL rel32 (Metasploit block_api_direct)
    if (n >= 2 and b[0] == 0xFC and b[1] == 0xE8) return true;

    // 60 89 E5 -- PUSHAD; MOV EBP, ESP (Metasploit x86)
    if (n >= 3 and b[0] == 0x60 and b[1] == 0x89 and b[2] == 0xE5) return true;

    var i: usize = 0;
    while (i < n) : (i += 1) {
        // CALL $+5 -- GetPC (position-independent code, nearly unique to shellcode)
        if (i + 5 <= n and
            b[i] == 0xE8 and b[i + 1] == 0x00 and b[i + 2] == 0x00 and
            b[i + 3] == 0x00 and b[i + 4] == 0x00) return true;

        // MOV EAX, FS:[0x30] -- PEB access x86
        if (i + 6 <= n and
            b[i] == 0x64 and b[i + 1] == 0xA1 and
            b[i + 2] == 0x30 and b[i + 3] == 0x00 and
            b[i + 4] == 0x00 and b[i + 5] == 0x00) return true;

        // MOV RAX, GS:[0x60] -- PEB access x64
        if (i + 9 <= n and
            b[i] == 0x65 and b[i + 1] == 0x48 and b[i + 2] == 0x8B and
            b[i + 3] == 0x04 and b[i + 4] == 0x25 and
            b[i + 5] == 0x60 and b[i + 6] == 0x00 and
            b[i + 7] == 0x00 and b[i + 8] == 0x00) return true;

        // MOV ESI, FS:[0x30] -- PEB via ESI x86
        if (i + 7 <= n and
            b[i] == 0x64 and b[i + 1] == 0x8B and b[i + 2] == 0x35 and
            b[i + 3] == 0x30 and b[i + 4] == 0x00 and
            b[i + 5] == 0x00 and b[i + 6] == 0x00) return true;

        // MOV EBX, FS:[0x30] -- PEB via EBX x86
        if (i + 7 <= n and
            b[i] == 0x64 and b[i + 1] == 0x8B and b[i + 2] == 0x1D and
            b[i + 3] == 0x30 and b[i + 4] == 0x00 and
            b[i + 5] == 0x00 and b[i + 6] == 0x00) return true;
    }

    return false;
}

pub fn detectEntropyGradient(buf: []const u8) bool {
    const header_size: usize = 64;
    const body_window: usize = ENTROPY_WINDOW;
    if (buf.len < header_size + body_window) return false;

    const header_entropy = shannonEntropy(buf[0..header_size]);
    const body_entropy = shannonEntropy(buf[header_size..][0..body_window]);
    return header_entropy < 6.5 and body_entropy >= 7.0 and (body_entropy - header_entropy) >= 1.5;
}

const FILEHANDLE = *anyopaque;

const FILETIME = extern struct {
    dwLowDateTime: u32,
    dwHighDateTime: u32,
};

const WIN32_FIND_DATAA = extern struct {
    dwFileAttributes: u32,
    ftCreationTime: FILETIME,
    ftLastAccessTime: FILETIME,
    ftLastWriteTime: FILETIME,
    nFileSizeHigh: u32,
    nFileSizeLow: u32,
    dwReserved0: u32,
    dwReserved1: u32,
    cFileName: [260]u8,
    cAlternateFileName: [14]u8,
};

const GENERIC_READ: u32 = 0x80000000;
const FILE_SHARE_READ: u32 = 0x00000001;
const OPEN_EXISTING: u32 = 3;

// to be cleaned-up later .. lazy
extern "kernel32" fn FindFirstFileA(lpFileName: [*:0]const u8, lpFindFileData: *WIN32_FIND_DATAA) callconv(.c) ?FILEHANDLE;
extern "kernel32" fn FindNextFileA(hFindFile: FILEHANDLE, lpFindFileData: *WIN32_FIND_DATAA) callconv(.c) i32;
extern "kernel32" fn FindClose(hFindFile: FILEHANDLE) callconv(.c) i32;
extern "kernel32" fn CreateFileA(lpFileName: [*:0]const u8, dwDesiredAccess: u32, dwShareMode: u32, lpSecurityAttributes: ?*anyopaque, dwCreationDisposition: u32, dwFlagsAndAttributes: u32, hTemplateFile: ?*anyopaque) callconv(.c) ?FILEHANDLE;
extern "kernel32" fn GetFileSize(hFile: FILEHANDLE, lpFileSizeHigh: ?*u32) callconv(.c) u32;
extern "kernel32" fn ReadFile(hFile: FILEHANDLE, lpBuffer: [*]u8, nNumberOfBytesToRead: u32, lpNumberOfBytesRead: *u32, lpOverlapped: ?*anyopaque) callconv(.c) i32;
extern "kernel32" fn CloseHandle(hObject: FILEHANDLE) callconv(.c) i32;
