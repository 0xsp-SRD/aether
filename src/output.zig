// Output formatting: JSON results and colored console report.
// Uses direct Win32 console output (console.zig) instead of Zig's std.io.

const std = @import("std");
const sigs = @import("signatures.zig");
const scanner = @import("scanner.zig");
const memory = @import("memory.zig");
const console = @import("console.zig");

pub fn HexStrip(s: []const u8) []const u8 {
    if (s.len >= 2 and s[0] == '0' and (s[1] == 'x' or s[1] == 'X')) {
        return s[2..];
    }
    return s;
}

pub fn writeJsonResults(
    w: console.Writer,
    pid: u32,
    results: *const scanner.ScanResults,
    stats: *const memory.MemoryWalkStats,
    scan_time_ms: u64,
) void {
    w.print("{{\"pid\":{d},", .{pid});
    w.print("\"scan_time_ms\":{d},", .{scan_time_ms});
    w.print("\"regions_scanned\":{d},", .{results.regions_scanned});
    w.print("\"regions_total\":{d},", .{stats.total_regions});
    w.print("\"regions_skipped_system\":{d},", .{stats.skipped_system});
    w.print("\"bytes_scanned\":{d},", .{results.bytes_scanned});
    w.print("\"read_errors\":{d},", .{stats.read_errors});
    w.print("\"pe_headers_in_private\":{d},", .{results.pe_headers_found});
    w.print("\"dotnet_assemblies_in_private\":{d},", .{results.dotnet_headers_found});

    w.write("\"findings\":[");
    var sfirst = true;
    for (results.suspicious.items) |s| {
        if (!sfirst) w.write("");
        sfirst = false;

        w.write("{");
        w.print("\"type\":\"{s}\",", .{s.label()});
        w.print("\"severity\":\"{s}\",", .{s.severity()});
        w.print("\"address\":\"0x{X}\",", .{s.address});
        w.print("\"size\":{d}", .{s.size});

        if (s.private_pages > 0 or s.region_pages > 0) {
            w.print(",\"private_pages\":{d}", .{s.private_pages});
            w.print(",\"region_pages\":{d}", .{s.region_pages});
        }

        if (s.kind == .thread_start_anomaly and s.address == 0) {
            w.print(",\"thread_count\":{d}", .{s.size});
        }

        if (@intFromEnum(s.kind) >= @intFromEnum(sigs.SuspicionType.thread_shellcode_private) and
            @intFromEnum(s.kind) <= @intFromEnum(sigs.SuspicionType.thread_suspended_rip_anomaly))
        {
            w.print(",\"thread_id\":{d}", .{s.size});
        }

        if (s.kind == .entropy_encrypted or s.kind == .entropy_shellcode or s.kind == .entropy_suspicious) {
            w.print(",\"region_bytes\":{d}", .{s.size});
        }

        w.write("}");
    }
    w.write("],");

    w.write("\"findings\":[");
    var first = true;
    for (&results.category_scores) |*cs| {
        if (cs.score < 3) continue;
        if (!first) w.write(",");
        first = false;

        const severity = sigs.Severity.fromScore(cs.score);
        w.write("{");
        w.print("\"category\":\"{s}\",", .{cs.category.toString()});
        w.print("\"severity\":\"{s}\",", .{severity.toString()});
        w.print("\"score\":{d},", .{cs.score});
        w.print("\"hit_count\":{d},", .{cs.hit_count});
        w.print("\"mitre\":\"{s}\",", .{cs.category.toMitre()});

        w.write("\"hits\":[");
        var hfirst = true;
        for (results.hits.items) |hit| {
            const sig = &results.signatures[hit.sig_index];
            if (sig.category != cs.category) continue;
            if (!hfirst) w.write(",");
            hfirst = false;

            w.write("{");
            w.write("\"pattern\":\"");
            writeJsonEscaped(w, sig.pattern);
            w.write("\",");
            w.print("\"weight\":{d},", .{sig.weight});
            w.print("\"offset\":\"0x{X}\",", .{hit.region_base + hit.offset});
            w.print("\"encoding\":\"{s}\",", .{hit.encoding.toString()});
            w.write("\"description\":\"");
            writeJsonEscaped(w, sig.description);
            w.write("\"");
            w.write("}");
        }
        w.write("]");
        w.write("}");
    }
    w.write("]");

    if (results.pe_headers_found > 0) {
        w.write(",\"reflective_loads\":{");
        w.print("\"pe_headers\":{d},", .{results.pe_headers_found});
        w.print("\"dotnet_assemblies\":{d},", .{results.dotnet_headers_found});
        const sev: []const u8 = if (results.dotnet_headers_found > 0) "CRITICAL" else "HIGH";
        w.print("\"severity\":\"{s}\",", .{sev});
        w.write("\"mitre\":\"T1620\",");
        w.write("\"description\":\"PE headers found in MEM_PRIVATE regions (non-file-backed assemblies)\"");
        w.write("}");
    }

    w.write("}\n");
}

pub fn writeConsoleReport(
    w: console.Writer,
    pid: u32,
    results: *const scanner.ScanResults,
    stats: *const memory.MemoryWalkStats,
    scan_time_ms: u64,
) void {
    var has_findings = false;
    w.print("\n  Scan Results for PID {d}\n", .{pid});
    w.write("  ==================================================\n");
    w.print("  Regions: {d} total, {d} scanned, {d} system-skipped\n", .{
        stats.total_regions,
        results.regions_scanned,
        stats.skipped_system,
    });

    const mb = @as(f64, @floatFromInt(results.bytes_scanned)) / (1024.0 * 1024.0);
    w.print("  Bytes scanned: {d:.2} MB\n", .{mb});
    w.print("  Read errors: {d}\n", .{stats.read_errors});
    w.print("  Scan time: {d} ms\n\n", .{scan_time_ms});

    if (results.pe_headers_found > 0) {
        w.write("  \x1b[91m\x1b[1m[CRITICAL]\x1b[0m REFLECTIVE_LOAD | ");
        w.print("{d} PE headers in MEM_PRIVATE", .{results.pe_headers_found});
        if (results.dotnet_headers_found > 0) {
            w.print(" ({d} with .NET BSJB metadata)", .{results.dotnet_headers_found});
        }
        w.write(" [T1620]\n");
    }

    if (results.suspicious.items.len > 0) {
        w.write("  ==================================================\n");
        w.print("   Structural Scan IOCs ({d})  \n", .{results.suspicious.items.len});
        w.write("  ==================================================\n");
        for (results.suspicious.items) |s| {
            has_findings = true;
            if (s.private_pages > 0) {
                w.print(" \x1b[93m[{s}]\x1b[0m {s} @ 0x{X} ({d} private / {d} pages)\n", .{
                    s.severity(),
                    s.label(),
                    s.address,
                    s.private_pages,
                    s.region_pages,
                });
            } else {
                w.print(" \x1b[93m[{s}]\x1b[0m {s} @ 0x{X} ({d} bytes)\n", .{
                    s.severity(),
                    s.label(),
                    s.address,
                    s.size,
                });
            }
        }
        w.write("\n");
    }

    for (&results.category_scores) |*cs| {
        if (cs.score < 3) continue;
        has_findings = true;

        const severity = sigs.Severity.fromScore(cs.score);
        const color = severityColor(severity);

        w.print("  {s}[{s}]\x1b[0m {s} | score={d} hits={d} [{s}]\n", .{
            color,
            severity.toString(),
            cs.category.toString(),
            cs.score,
            cs.hit_count,
            cs.category.toMitre(),
        });

        for (results.hits.items) |hit| {
            const sig = &results.signatures[hit.sig_index];
            if (sig.category != cs.category) continue;
            w.print("    +{d} \"{s}\" @ 0x{X} ({s})\n", .{
                sig.weight,
                sig.pattern,
                hit.region_base + hit.offset,
                hit.encoding.toString(),
            });
        }
    }

    if (!has_findings) { //and results.pe_headers_found == 0
        w.write("  \x1b[92m[CLEAN]\x1b[0m No attack signatures found in process memory.\n");
    }

    w.write("\n");
}

fn severityColor(sev: sigs.Severity) []const u8 {
    return switch (sev) {
        .critical => "\x1b[91m\x1b[1m",
        .high => "\x1b[91m",
        .medium => "\x1b[93m",
        .low => "\x1b[96m",
        .info => "\x1b[92m",
    };
}

fn writeJsonEscaped(w: console.Writer, s: []const u8) void {
    for (s) |c| {
        switch (c) {
            '"' => w.write("\\\""),
            '\\' => w.write("\\\\"),
            '\n' => w.write("\\n"),
            '\r' => w.write("\\r"),
            '\t' => w.write("\\t"),
            else => {
                if (c < 0x20) {
                    w.print("\\u{X:0>4}", .{c});
                } else {
                    w.writeByte(c);
                }
            },
        }
    }
}
