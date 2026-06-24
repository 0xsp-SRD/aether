// Aether: process memory forensic tool built with love in Zig.
// author : Lawrence Amer @zux0x3a
// site : https://0xsp.com
// Scans process memory for artifacts,C2 channel strings, reflectively loaded .NET assemblies, structual IOC based scan and evasion
// technique indicators of compromise.
//

const std = @import("std");
const w = @import("win32.zig");
const privilege = @import("privilege.zig");
const memory = @import("memory.zig");
const scanner = @import("scanner.zig");
const output = @import("output.zig");
const console = @import("console.zig");
const sig = @import("signatures.zig");
const netstat = @import("network_m.zig");

const BANNER =
    \\
    \\
    \\        ___       __  __
    \\       /   | ___ / /_/ /_  ___  _____
    \\      / /| |/ _ \\ __/ __ \\/ _ \\/ ___/
    \\     / ___ /  __/ /_/ / / /  __/ /
    \\    /_/  |_\\___/\\__/_/ /_/\\___/_/
    \\
    \\    Memory Forensics & Threat-hunting tool
    \\    Author : Lawrence Amer - @zux0x3a
    \\    Docs: https://0xsp.com/docs/aether-getting-started/
    \\    Tag: Stable - v0.9
    \\
;

const USAGE =
    \\USAGE:
    \\  aether.exe --scan --pid <PID> [OPTIONS]
    \\  aether.exe --scan --lookup "ProcessName"
    \\
    \\OPTIONS:
    \\  --pid, -p <PID>       Target process ID to scan
    \\  --lookup "name"       Find PIDs by process name
    \\  --json, -j            Output results as JSON (for d-tect.py integration)
    \\  --verbose, -v         Show per-region scan details
    \\  --scan-all, -a        Scan all matching PIDs
    \\  --rules, -r <dir>     Rules directory (default: rules/)
    \\  --config, -c <file>   Single rule file (legacy)
    \\  --help, -h            Show this help
    \\  --hunt PID MS DUR     hunt beaconing: poll every MS ms for DUR seconds.
    \\  --dump PID OFF SIZE   dump memory region. OFF is hex (e.g. 0x7FFE...);
    \\                        SIZE is bytes in decimal (e.g. 12068), or hex
    \\                        with explicit 0x prefix. Default: stops at first
    \\                        uncommitted byte and reports stats.
    \\  --dump-pad-zero       zero-fill uncommitted gaps in the dump so the
    \\                        output is exactly SIZE bytes.
    \\EXAMPLES:
    \\  aether.exe --lookup "w3wp.exe"
    \\  aether.exe --scan --pid 4820
    \\  aether.exe --scan --pid 4820 --json --rules rules/
    \\  aether.exe --pid 1234 --config rules/cobalt_strike.json
    \\  aether.exe --scan-all --json
    \\  aether.exe --hunt 4890 2000 120
    \\ # Dump 8192 bytes starting at 0x7FFE2A100000 from PID 4820
    \\  aether.exe --dump 4820 0x7FFE2A100000 8192
    \\ # Dump 1 MB (1048576 bytes)
    \\  aether.exe --dump 4820 0x2B3F0000 1048576
    \\ # Hex size still works if prefixed with 0x
    \\  aether.exe --dump 4820 0x2B3F0000 0x100000
    \\ # Dump with gap-padding (forces same-sized output)
    \\  aether.exe --dump 16580 0x2796FF50000 12068 --dump-pad-zero
    \\
    \\RULE PACKS:
    \\  cobalt_strike.json    Cobalt Strike beacon artifacts
    \\  meterpreter.json      Metasploit Meterpreter implant
    \\  sliver.json           Sliver C2 implant (BishopFox)
    \\  brute_ratel.json      Brute Ratel C4 badger
    \\  havoc.json            Havoc C2 demon
    \\  sharp_tools.json      .NET offensive tools (Rubeus, Seatbelt, SharpHound...)
    \\  mimikatz.json         Mimikatz credential theft
    \\  powershell_cradles.json  PowerShell attack cradles & AMSI bypass
    \\  dotnet_loaders.json   Generic .NET loaders & injectors
    \\  mythic_poshc2.json    Mythic / PoshC2 / Nighthawk implants
    \\  phantom_loader.json   Phantom ASP.NET Loader.
;

var rules_based = false;

const Args = struct {
    pid: ?u32 = null,
    lookup_mode: ?[]const u8 = null,
    json_mode: bool = false,
    verbose: bool = false,
    scan: bool = false,
    all_rules: ?[]const u8 = null,
    help: bool = false,
    networking: ?u32 = null, // ? can be null or hold a value.
    hunt: ?HuntsConfig = null,
    rules_dir: ?[]const u8 = null,
    config_file: ?[]const u8 = null,
    dump: ?DumpConfig = null,
    readmem: ?ReadMemConfig = null,
    scan_all: bool = false,

    var rules_dir_buf: [512]u8 = undefined;
    var config_file_buf: [512]u8 = undefined;
    var lookup_buf: [256]u8 = undefined;
};

const HuntsConfig = struct {
    pid: u32,
    sleep_ms: u32 = 2000,
    duration_s: u32 = 120,
};
const DumpConfig = struct {
    pid: u32,
    start: usize,
    size: usize,
    pad_zero: bool = false,
};

const ReadMemConfig = struct {
    pid: u32,
    start: usize,
    size: usize,
};

fn wideToUtf8(wide: [*:0]const u16, buf: []u8) []const u8 {
    var i: usize = 0;
    var out_i: usize = 0;
    while (wide[i] != 0 and out_i < buf.len) : (i += 1) {
        const c = wide[i];
        if (c < 128) {
            buf[out_i] = @truncate(c);
            out_i += 1;
        }
    }
    return buf[0..out_i];
}

fn parseArgs() Args {
    var args_result = Args{};

    var argc: i32 = 0;
    const argv_ptr = w.CommandLineToArgvW(w.GetCommandLineW(), &argc) orelse return args_result;
    defer _ = w.LocalFree(@ptrCast(@constCast(argv_ptr)));

    const argv_count: usize = if (argc > 0) @intCast(argc) else return args_result;

    var arg_buf: [512]u8 = undefined;
    var expect_pid = false;
    var expect_procname = false;
    var expect_rules = false;
    var expect_config = false;
    var expect_pid_additional = false;

    var expect_dump_pid = false;
    var expect_readmem_pid = false;
    var expect_dump_start = false;
    var expect_readmem_start = false;
    var expect_dump_size = false;
    var expect_readmem_size = false;

    var hunt_args_left: u8 = 0;
    var hunt_pid: u32 = undefined;
    var hunt_sleep: u32 = 2000;
    var hunt_duration: u32 = 120;

    var i: usize = 1;
    while (i < argv_count) : (i += 1) {
        const arg = wideToUtf8(argv_ptr[i], &arg_buf);

        if (hunt_args_left > 0) {
            hunt_args_left -= 1;
            if (hunt_args_left == 2) {
                hunt_pid = std.fmt.parseInt(u32, arg, 10) catch 0;
            } else if (hunt_args_left == 1) {
                hunt_sleep = std.fmt.parseInt(u32, arg, 10) catch hunt_sleep;
            } else {
                hunt_duration = std.fmt.parseInt(u32, arg, 10) catch hunt_duration;
                args_result.hunt = .{ .pid = hunt_pid, .sleep_ms = hunt_sleep, .duration_s = hunt_duration };
            }
            continue;
        }

        // dump memory section
        if (expect_dump_pid) {
            expect_dump_pid = false;
            expect_dump_start = true;
            const pid = std.fmt.parseInt(u32, arg, 10) catch 0;
            // Preserve pad_zero flag if it was set before --dump appeared on
            // the command line.
            const preserved_pad = if (args_result.dump) |d| d.pad_zero else false;
            args_result.dump = .{
                .pid = pid,
                .start = 0,
                .size = 0,
                .pad_zero = preserved_pad,
            };
            continue;
        }

        if (expect_dump_start) {
            expect_dump_start = false;
            expect_dump_size = true;
            if (args_result.dump) |*d| {
                d.start = std.fmt.parseInt(usize, output.HexStrip(arg), 16) catch 0;
            }
            continue;
        }
        if (expect_dump_size) {
            expect_dump_size = false;
            if (args_result.dump) |*d| {
                d.size = std.fmt.parseInt(usize, arg, 0) catch 0;
            }
            continue;
        }
        // END - dump memory section
        //
        //
        // read memory section
        if (expect_readmem_pid) {
            expect_readmem_pid = false;
            expect_readmem_start = true;
            const pid = std.fmt.parseInt(u32, arg, 10) catch 0;
            // Preserve pad_zero flag if it was set before --dump appeared on
            // the command line.
            //const preserved_pad = if (args_result.dump) |d| d.pad_zero else false;
            args_result.readmem = .{
                .pid = pid,
                .start = 0,
                .size = 0,
            };
            continue;
        }
        if (expect_readmem_start) {
            expect_readmem_start = false;
            expect_readmem_size = true;
            if (args_result.readmem) |*d| {
                d.start = std.fmt.parseInt(usize, output.HexStrip(arg), 16) catch 0;
            }
            continue;
        }
        if (expect_readmem_size) {
            expect_readmem_size = false;
            if (args_result.readmem) |*d| {
                d.size = std.fmt.parseInt(usize, arg, 0) catch 0;
            }
            continue;
        }

        if (expect_pid) {
            expect_pid = false;
            args_result.pid = std.fmt.parseInt(u32, arg, 10) catch null;
            continue;
        }

        if (expect_pid_additional) {
            expect_pid_additional = false;
            args_result.networking = std.fmt.parseInt(u32, arg, 10) catch null;
            continue;
        }
        if (expect_procname) {
            expect_procname = false;
            @memcpy(Args.lookup_buf[0..arg.len], arg);
            args_result.lookup_mode = Args.lookup_buf[0..arg.len];
            continue;
        }
        if (expect_rules) {
            expect_rules = false;
            @memcpy(Args.rules_dir_buf[0..arg.len], arg);
            args_result.rules_dir = Args.rules_dir_buf[0..arg.len];
            continue;
        }
        if (expect_config) {
            expect_config = false;
            @memcpy(Args.config_file_buf[0..arg.len], arg);
            args_result.config_file = Args.config_file_buf[0..arg.len];
            continue;
        }
        if (eq(arg, "--networking")) {
            //   args_result.testing = true;
            expect_pid_additional = true;
        } else if (eq(arg, "--hunt") or eq(arg, "-b")) {
            //     expect_pid_hunt = true;
            hunt_args_left = 3;
        } else if (eq(arg, "--lookup") or eq(arg, "-l")) {
            expect_procname = true;
        } else if (eq(arg, "--json") or eq(arg, "-j")) {
            args_result.json_mode = true;
        } else if (eq(arg, "--verbose") or eq(arg, "-v")) {
            args_result.verbose = true;
        } else if (eq(arg, "--scan") or eq(arg, "-s")) {
            args_result.scan = true;
        } else if (eq(arg, "--scan-all") or eq(arg, "-A")) {
            args_result.scan_all = true;
        } else if (eq(arg, "--help") or eq(arg, "-h")) {
            args_result.help = true;
        } else if (eq(arg, "--pid") or eq(arg, "-p")) {
            expect_pid = true;
        } else if (eq(arg, "--rules") or eq(arg, "-r")) {
            //args_result.all_rules = true;
            expect_rules = true;
        } else if (eq(arg, "--config") or eq(arg, "-c")) {
            expect_config = true;
        } else if (eq(arg, "--dump")) {
            expect_dump_pid = true;
        } else if (eq(arg, "--read")) {
            expect_readmem_pid = true;
        } else if (eq(arg, "--dump-pad-zero")) {
            //
            // Order-independent: applies whether it appears before or after
            // the --dump triplet. If --dump hasn't been seen yet, we set a
            // sentinel that gets folded into the DumpConfig once parsed.
            if (args_result.dump) |*d| {
                d.pad_zero = true;
            } else {
                args_result.dump = .{ .pid = 0, .start = 0, .size = 0, .pad_zero = true };
            }
        }
        //    else {
        //       if (args_result.pid == null) {
        //             args_result.pid = std.fmt.parseInt(u32, arg, 10) catch null;
        //        }
        //    }
    }
    return args_result;
}

fn eq(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

fn conAsciiToWide(ascii: []const u8, buf: []u16) []const u16 {
    const len = @min(ascii.len, buf.len);
    for (ascii[0..len], 0..) |c, j| {
        buf[j] = c;
    }
    return buf[0..len];
}

fn findallpids(allocator: std.mem.Allocator, ProcName: []const u8) ![]u32 {
    var pids: std.ArrayList(u32) = .empty;
    defer pids.deinit(allocator);

    const snap = w.CreateToolhelp32Snapshot(w.TH32CS_SNAPPROCESS, 0) orelse return &.{};
    defer _ = w.CloseHandle(snap);

    var pe: w.PROCESSENTRY32W = undefined;
    pe.dwSize = @sizeOf(w.PROCESSENTRY32W);

    if (w.Process32FirstW(snap, &pe) == w.FALSE) return &.{};

    var wideBuf: [256]u16 = undefined;
    const target = conAsciiToWide(ProcName, &wideBuf);
    while (true) {
        if (eq(ProcName, "--ALL")) { //if param -ALL passed, it will scan all system. add it into scan-all
            try pids.append(allocator, pe.th32ProcessID);
            if (w.Process32NextW(snap, &pe) == w.FALSE) break;
        } else {
            const name_slice = w.wideToSlice(&pe.szExeFile);
            if (wideEqlICase(name_slice, target)) {
                try pids.append(allocator, pe.th32ProcessID);
            }
            if (w.Process32NextW(snap, &pe) == w.FALSE) break;
        }
    }

    return try pids.toOwnedSlice(allocator);
}

fn wideEqlICase(a: []const u16, b: []const u16) bool {
    if (a.len != b.len) return false;
    for (a, b) |ac, bc| {
        var al = ac;
        var bl = bc;
        if (al >= 'A' and al <= 'Z') al += 32;
        if (bl >= 'A' and bl <= 'Z') bl += 32;
        if (al != bl) return false;
    }
    return true;
}

fn setupScanner(
    args: Args,
    gpa: std.mem.Allocator,
    err_out: console.Writer,
    out_scanner: *scanner.Scanner,
    out_rules_based: *bool,
) !void {
    if (args.config_file) |path| {
        out_scanner.* = scanner.Scanner.initFromFile(gpa, path) catch |err| {
            err_out.print("[!] Failed to load config file: {s} (error: {any})\n", .{ path, err });
            return err;
        };
        out_rules_based.* = out_scanner.signatures().len > 0;
        if (!args.json_mode) {
            err_out.print("[+] Loaded {d} signatures from {s}\n", .{ out_scanner.signatures().len, path });
        }
        return;
    }
    if (args.rules_dir) |dir| {
        out_scanner.* = scanner.Scanner.initFromDir(gpa, dir) catch |err| {
            err_out.print("[!] Failed to load rules directory: {s} (error: {any})\n", .{ dir, err });
            return err;
        };
        out_rules_based.* = out_scanner.signatures().len > 0;
        if (!args.json_mode) {
            err_out.print("[+] Loaded {d} signatures from {s}/\n", .{ out_scanner.signatures().len, dir });
        }
        return;
    }
    // No explicit rules path: empty scanner, structural-only mode.
    out_scanner.* = try scanner.Scanner.initEmpty(gpa);
    out_rules_based.* = false;
    if (!args.json_mode) {
        err_out.write("[*] No --rules / --config given - structural IOC scan only\n");
    }
}

fn scanProcess(scn: *scanner.Scanner, pid: u32, json_mode: bool, verbose: bool, allocator: std.mem.Allocator, out: console.Writer, rule_based: bool, err_out: console.Writer) !bool {
    if (!json_mode) {
        err_out.print("[*] Accuiring handle for PID:{d}...\n", .{pid});
    }

    const handle = w.OpenProcess(
        w.PROCESS_VM_READ | w.PROCESS_QUERY_INFORMATION,
        w.FALSE,
        pid,
    ) orelse {
        const last_err = w.GetLastError();
        if (!json_mode) {
            err_out.print("[!] OpenProcess failed for PID:{d} (error {d})\n", .{ pid, last_err });
            if (last_err == 5) {
                err_out.write("[!] Access denied -- run from an elevated cmd.exe\n");
            }
        }
        return false;
    };
    defer _ = w.CloseHandle(handle);

    if (!json_mode) {
        err_out.write("[+] Handle acquired. Scanning memory...\n");
    }

    var results = scanner.ScanResults.init(allocator, scn.signatures());
    defer results.deinit();

    const timer_start = w.GetTickCount64();

    const stats = try memory.walkAndScan(scn, handle, pid, &results, verbose, rule_based, err_out);
    const timer_end = w.GetTickCount64();
    const elapsed: u64 = timer_end -| timer_start;

    if (json_mode) {
        output.writeJsonResults(out, pid, &results, &stats, elapsed);
    } else {
        output.writeConsoleReport(err_out, pid, &results, &stats, elapsed);
    }

    for (&results.category_scores) |*cs| {
        if (cs.score >= 3) return true;
    }
    return results.pe_headers_found > 0;
    // return false;
}

pub fn main(init: std.process.Init) !void {
    const allocator = std.heap.smp_allocator;
    const gpa = init.gpa;
    const io = init.io;
    const out = console.stdout();
    const err_out = console.stderr();
    console.enableUtf8();
    console.disableQuickEdit();

    const args = parseArgs();

    var my_scanner: scanner.Scanner = undefined;
    var scanner_inited = false;

    const needs_scanner = args.scan or args.scan_all or args.pid != null or args.lookup_mode != null;
    if (needs_scanner) {
        setupScanner(args, gpa, err_out, &my_scanner, &rules_based) catch return;
        scanner_inited = true;
    }
    defer if (scanner_inited) my_scanner.deinit();

    // SeDebugPrivilege must be enabled BEFORE any scan branch (including
    // --scan-all) otherwise PROCESS_VM_READ on protected processes fails.
    const priv_ok = privilege.enableDebugPrivilege();
    if (needs_scanner and !args.json_mode) {
        if (priv_ok) {
            err_out.write("[+] SeDebugPrivilege: ENABLED\n");
        } else {
            err_out.write("[!] SeDebugPrivilege: FAILED -- run from an elevated console if scanning protected processes\n");
        }
    }

    if (args.networking) |pid| {
        const conns = try netstat.listconnections(allocator, pid);
        defer allocator.free(conns);

        var rows: [512][4][]const u8 = undefined;
        var row_count: usize = 0;
        var buf_a: [24]u8 = undefined;
        var buf_b: [24]u8 = undefined;
        var buf_c: [24]u8 = undefined;
        // var buf_d: [24]u8 = undefined;

        //var line: [128]u8 = undefined;
        for (conns) |c| {
            const s: netstat.MIB_TCP_STATE = @enumFromInt(c.state);
            const val = s.tostr();

            const lbytes: [4]u8 = @bitCast(c.local_addr);
            const local = std.fmt.bufPrint(&buf_a, "{d}.{d}.{d}.{d}:{d}", .{
                lbytes[0],
                lbytes[1],
                lbytes[2],
                lbytes[3],
                @byteSwap(c.local_port),
            }) catch unreachable;

            const pid_str = std.fmt.bufPrint(&buf_c, "{d}", .{c.pid}) catch unreachable;

            const rbytes: [4]u8 = @bitCast(c.remote_addr);
            const remote = std.fmt.bufPrint(&buf_b, "{d}.{d}.{d}.{d}:{d}", .{
                rbytes[0],                rbytes[1], rbytes[2], rbytes[3],
                @byteSwap(c.remote_port),
            }) catch unreachable;

            rows[row_count] = .{ val, local, remote, pid_str };
            row_count += 1;

            //  err_out.print("  {s}\n", .{netstat.formatConnection(c, &line)});
        }
        err_out.print("[*] {d} network connections for PID {d}:\n", .{ conns.len, pid });

        var slices: [512][]const []const u8 = undefined;
        for (rows[0..row_count], 0..) |*r, j| {
            slices[j] = &r.*;
        }
        err_out.writeTable(
            &.{ "STATE", "LOCAL", "REMOTE", "PID" },
            slices[0..row_count],
        );
    }

    // memory dump section
    if (args.dump) |cfg| {
        if (cfg.pid == 0 or cfg.size == 0) {
            err_out.write("[!] --dump requires PID OFFSET SIZE\n");
            err_out.write("[*] OFFSET is hex (0x...), SIZE is decimal bytes (or hex with 0x prefix)\n");
            err_out.write("[*] Example: --dump 4820 0x7FFE1000 8192\n");
            err_out.write("[+] Tip: --verbose to retrieve accurate address\n");
            return;
        }

        const handle = w.OpenProcess(
            w.PROCESS_VM_READ | w.PROCESS_QUERY_INFORMATION,
            w.FALSE,
            cfg.pid,
        ) orelse {
            const err = w.GetLastError();
            err_out.print("[!] OpenProcess failed for PID:{d} (error {d})\n", .{ cfg.pid, err });
            return;
        };
        defer _ = w.CloseHandle(handle);

        if (!args.json_mode) {
            err_out.print("[*] Dumping 0x{X} ({d} bytes) from PID {d} (policy={s})...\n", .{
                cfg.start,                                            cfg.size, cfg.pid,
                if (cfg.pad_zero) "pad-zero" else "strict-committed",
            });
        }

        const policy: memory.DumpPolicy = if (cfg.pad_zero) .pad_zero else .strict_committed;
        const stats = memory.dumpMemRegion(
            io,
            handle,
            cfg.pid,
            cfg.start,
            cfg.size,
            policy,
            gpa,
        ) catch |err| {
            err_out.print("[!] Dump failed: {any}\n", .{err});
            return;
        };

        if (!args.json_mode) {
            err_out.print(
                "[+] Dump complete: {d} committed + {d} padded = {d}/{d} bytes " ++
                    "({d} regions visited, {d} gaps)\n",
                .{
                    stats.committed_bytes,
                    stats.padded_bytes,
                    stats.committed_bytes + stats.padded_bytes,
                    stats.requested_bytes,
                    stats.regions_visited,
                    stats.gaps,
                },
            );
            if (!stats.isComplete()) {
                err_out.print(
                    "[*] Output file is short ({d} bytes) - the request ran into " ++
                        "uncommitted memory. Re-run with --dump-pad-zero to get a " ++
                        "same-sized output with gaps zero-filled.\n",
                    .{stats.committed_bytes + stats.padded_bytes},
                );
            }
        }
    }
    //  return;
    // }

    if (args.readmem) |cfg| {
        const handle = w.OpenProcess(
            w.PROCESS_VM_READ | w.PROCESS_QUERY_INFORMATION,
            w.FALSE,
            cfg.pid,
        ) orelse {
            const err = w.GetLastError();
            err_out.print("[!] OpenProcess failed for PID:{d} (error {d})\n", .{ cfg.pid, err });
            return;
        };
        defer _ = w.CloseHandle(handle);

        if (!args.json_mode) {
            err_out.print("[*] Dumping 0x{X} ({d} bytes) from PID {d} )...\n", .{
                cfg.start, cfg.size, cfg.pid,
            });
        }

        //  const policy: memory.DumpPolicy = if (cfg.pad_zero) .pad_zero else .strict_committed;
        const stats = memory.readMemRegion(
            handle,
            cfg.start,
            cfg.size,
        ) catch |err| {
            err_out.print("[!] READ failed: {any}\n", .{err});
            return;
        };
        _ = stats;
    }

    if (args.hunt) |cfg| {
        err_out.print("[*] Monitoring PID {d} for beacon patterns (poll every {d}ms, duration {d}s)...\n", .{
            cfg.pid, cfg.sleep_ms, cfg.duration_s,
        });

        var monitor = netstat.ConnectionMonitor.init(allocator, cfg.pid);
        defer monitor.deinit();

        const deadline_ms: u64 = w.GetTickCount64() + @as(u64, cfg.duration_s) * 1000;
        while (w.GetTickCount64() < deadline_ms) {
            try monitor.poll();
            w.Sleep(cfg.sleep_ms);
        }

        try monitor.reporting(err_out);
    }
    if (args.help) {
        out.write(BANNER);
        out.write(USAGE);
        return;
    }

    if (args.scan_all) {
        out.write(BANNER);
        const pids = try findallpids(allocator, "--ALL");
        defer allocator.free(pids);
        for (pids) |pid| {
            const found = try scanProcess(&my_scanner, pid, args.json_mode, args.verbose, allocator, out, rules_based, err_out);
            if (!found and !args.json_mode) {
                //     err_out.print("[*] No significant findings for PID:{d}\n", .{pid});
            }
            //   return;
        }

        return;
    }

    if (args.lookup_mode) |target| {
        out.write(BANNER);
        const pids = try findallpids(allocator, target);
        defer allocator.free(pids);
        for (pids) |pid| {
            const found = try scanProcess(&my_scanner, pid, args.json_mode, args.verbose, allocator, out, rules_based, err_out);
            if (!found and !args.json_mode) {
                //  err_out.print("[*] No significant findings for PID:{d}\n", .{pid});
            }
            //   return;
        }

        if (pids.len == 0) {
            if (args.json_mode) {
                out.write("{\"_pids\":[]}\n");
            } else {
                err_out.write("[*] No processes found.\n");
            }
            return;
        }

        if (args.json_mode) {
            out.write("{\"_pids\":[");
            for (pids, 0..) |pid, i| {
                if (i > 0) out.write(",");
                out.print("{d}", .{pid});
            }
            out.write("]}\n");
        } else {
            err_out.print("[*] Found {d} process(es):\n", .{pids.len});
            for (pids) |pid| {
                err_out.print("    PID: {d}\n", .{pid});
            }
        }
        return;
    }

    if (args.pid) |pid| {
        out.write(BANNER);

        const found = try scanProcess(&my_scanner, pid, args.json_mode, args.verbose, allocator, out, rules_based, err_out);
        if (!found and !args.json_mode) {
            //  err_out.print("[*] No significant findings for PID:{d}\n", .{pid});
        }
        return;
    }
}
