//! ============================================================================
//! File: memory_m.zig
//! Author: Lawrence Amer (@zux0x3a - 0xsp.com)
//! year : 2026
//! Summary:
//! Provides the ability to detect a beaconing pattern from a process
//! leverage smart CoV scoring system and serveral verdict
//!
//! ============================================================================

const std = @import("std");
const api = @import("win32.zig");

const MIB_TCPROW_OWNER_PID = extern struct {
    dwstate: u32,
    dwLocalAddr: u32,
    dwLocalPort: u32,
    dwRemoteAddr: u32,
    dwRemotePort: u32,
    dwOwningPid: u32,
};

const MIB_TCPTABLE_OWNER_PID = extern struct {
    dwEntriles: api.DWORD,
    table: [1]MIB_TCPTABLE_OWNER_PID,
};

const TCP_TABLE_OWNER_PID_ALL: u32 = 5;
const NO_ERROR: u32 = 0;
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;

pub const MIB_TCP_STATE = enum(u32) {
    closed = 1,
    listen = 2,
    syn_sent = 3,
    syn_rcvd = 4,
    established = 5,
    fin_wait1 = 6,
    fin_wait2 = 7,
    close_wait = 8,
    closing = 9,
    last_ack = 10,
    time_wait = 11,
    delete_tcb = 12,

    pub fn tostr(self: @This()) []const u8 {
        return switch (self) {
            .closed => "CLOSED",
            .listen => "LISTEN",
            .syn_sent => "SYN_SENT",
            .syn_rcvd => "SYN_RCVD",
            .established => "ESTABLISHED",
            .fin_wait1 => "FIN_WAIT1",
            .fin_wait2 => "FIN_WAIT2",
            .close_wait => "CLOSE_WAIT",
            .closing => "CLOSING",
            .last_ack => "LAST_ACK",
            .time_wait => "TIME_WAIT",
            .delete_tcb => "DELETE_TCB",
        };
    }
};

const MAX_EVENTS: usize = 64;

pub const HTTPConnection = struct {
    remote_ip: u32,
    remote_port: u32,
    is_https: bool,
    is_http: bool,
    first_seen_ms: u64,
    last_seen_ms: u64,
    hit_count: u32,
    is_active: bool,
    polls_present: u32 = 0,
    event_times: [MAX_EVENTS]u64 = [_]u64{0} ** MAX_EVENTS,
    event_count: u32 = 0,

    fn recordEvent(self: *HTTPConnection, ts: u64) void {
        if (self.event_count < MAX_EVENTS) {
            self.event_times[self.event_count] = ts;
            self.event_count += 1;
        }
    }
};

pub const BeaconVerdict = enum {
    high,
    medium,
    persistent,
    low,
    insufficient,

    pub fn label(self: BeaconVerdict) []const u8 {
        return switch (self) {
            .high => "HIGH",
            .medium => "MEDIUM",
            .persistent => "PERSIST",
            .low => "--",
            .insufficient => "?",
        };
    }
};

pub const BeaconScore = struct {
    mean_interval_ms: f64 = 0.0,
    stddev_ms: f64 = 0.0,
    cov: f64 = 0.0,
    intervals: u32 = 0,
    presence_ratio: f64 = 0.0,
    verdict: BeaconVerdict = .insufficient,
};

fn computeBeaconScore(conn: *const HTTPConnection, total_polls: u32) BeaconScore {
    // Path 1: periodic reconnection scoring (CoV analysis).
    // blogpost at 0xsp.com
    if (conn.event_count >= 3) {
        const n = conn.event_count;
        const interval_count = n - 1;

        var sum: f64 = 0.0;
        var intervals: [MAX_EVENTS]f64 = undefined;

        var i: u32 = 0;
        while (i < interval_count) : (i += 1) {
            const dt: f64 = @floatFromInt(conn.event_times[i + 1] -| conn.event_times[i]);
            intervals[i] = dt;
            sum += dt;
        }

        const mean = sum / @as(f64, @floatFromInt(interval_count));
        if (mean >= 1.0) {
            var var_sum: f64 = 0.0;
            i = 0;
            while (i < interval_count) : (i += 1) {
                const diff = intervals[i] - mean;
                var_sum += diff * diff;
            }
            const variance = var_sum / @as(f64, @floatFromInt(interval_count));
            const stddev = @sqrt(variance);
            const cov = stddev / mean;

            const verdict: BeaconVerdict = if (cov < 0.20)
                .high
            else if (cov < 0.40)
                .medium
            else
                .low;

            return .{
                .mean_interval_ms = mean,
                .stddev_ms = stddev,
                .cov = cov,
                .intervals = interval_count,
                .verdict = verdict,
            };
        }
    }

    // Path 2: persistent / keep-alive connection scoring.
    // A connection present in >50% of polls for at least 10 seconds
    // is a long-lived session -- typical of sleep-0 interactive beacons,
    // HTTP/2 C2 channels, and keep-alive callback loops.
    if (total_polls >= 5 and conn.polls_present > 0) {
        const pr = @as(f64, @floatFromInt(conn.polls_present)) / @as(f64, @floatFromInt(total_polls));
        const duration_ms = conn.last_seen_ms -| conn.first_seen_ms;
        if (pr >= 0.50 and duration_ms >= 10_000) {
            return .{
                .mean_interval_ms = @floatFromInt(duration_ms),
                .presence_ratio = pr,
                .intervals = conn.polls_present,
                .verdict = if (pr >= 0.80) .persistent else .medium,
            };
        }
    }

    return .{};
}

fn isFilteredEndpoint(ip: u32) bool {
    const bytes: [4]u8 = @bitCast(ip);
    if (bytes[0] == 127) return true; // loopback
    if (bytes[0] == 169 and bytes[1] == 254) return true; // link-local
    if (ip == 0) return true;
    return false;
}

pub const ConnectionMonitor = struct {
    allocator: std.mem.Allocator,
    pid: u32,
    known: std.AutoHashMap(u64, HTTPConnection),
    prev_conns: std.AutoHashMap(u64, void),
    poll_count: u32,
    start_ms: u64,

    fn connKey(local_port: u16, remote_addr: u32, remote_port: u16) u64 {
        return (@as(u64, remote_addr) << 32) | (@as(u64, local_port) << 16) | @as(u64, remote_port);
    }

    fn endpointKey(remote_addr: u32, remote_port: u16) u64 {
        return (@as(u64, remote_addr) << 32) | @as(u64, remote_port);
    }

    pub fn init(allocator: std.mem.Allocator, pid: u32) ConnectionMonitor {
        return .{
            .allocator = allocator,
            .pid = pid,
            .known = std.AutoHashMap(u64, HTTPConnection).init(allocator),
            .prev_conns = std.AutoHashMap(u64, void).init(allocator),
            .poll_count = 0,
            .start_ms = api.GetTickCount64(),
        };
    }

    pub fn deinit(self: *ConnectionMonitor) void {
        self.known.deinit();
        self.prev_conns.deinit();
    }

    pub fn poll(self: *ConnectionMonitor) !void {
        self.poll_count += 1;
        const now = api.GetTickCount64();

        const connections = try listconnections(self.allocator, self.pid);
        defer self.allocator.free(connections);

        var current_conns: std.AutoHashMap(u64, void) = .init(self.allocator);
        defer current_conns.deinit();

        var mark_it = self.known.iterator();
        while (mark_it.next()) |entry| {
            entry.value_ptr.*.is_active = false;
        }

        for (connections) |c| {
            if (c.state != 5 and c.state != 6 and c.state != 7 and
                c.state != 8 and c.state != 9 and c.state != 10) continue;

            if (c.remote_addr == 0 and c.remote_port == 0) continue;
            if (isFilteredEndpoint(c.remote_addr)) continue;

            const ck = connKey(c.local_port, c.remote_addr, c.remote_port);
            try current_conns.put(ck, {});

            const ek = endpointKey(c.remote_addr, c.remote_port);
            const is_https = c.remote_port == @byteSwap(@as(u16, 443));
            const is_http = c.remote_port == @byteSwap(@as(u16, 80));

            const gop = try self.known.getOrPut(ek);
            if (gop.found_existing) {
                gop.value_ptr.*.last_seen_ms = now;
                gop.value_ptr.*.hit_count += 1;
                gop.value_ptr.*.polls_present += 1;
                gop.value_ptr.*.is_active = (c.state == 5);

                if (!self.prev_conns.contains(ck)) {
                    gop.value_ptr.*.recordEvent(now);
                }
            } else {
                gop.value_ptr.* = .{
                    .remote_ip = c.remote_addr,
                    .remote_port = c.remote_port,
                    .is_https = is_https,
                    .is_http = is_http,
                    .first_seen_ms = now,
                    .last_seen_ms = now,
                    .hit_count = 1,
                    .is_active = (c.state == 5),
                    .polls_present = 1,
                };
                gop.value_ptr.*.recordEvent(now);
            }
        }

        self.prev_conns.clearRetainingCapacity();
        var ck_it = current_conns.iterator();
        while (ck_it.next()) |entry| {
            try self.prev_conns.put(entry.key_ptr.*, {});
        }
    }

    pub const ScoredEndpoint = struct {
        conn: HTTPConnection,
        score: BeaconScore,
    };

    pub fn huntBeacons(self: *ConnectionMonitor) ![]ScoredEndpoint {
        var result: std.ArrayList(ScoredEndpoint) = .empty;
        defer result.deinit(self.allocator);

        var it = self.known.iterator();
        while (it.next()) |entry| {
            const conn = entry.value_ptr.*;
            const score = computeBeaconScore(&conn, self.poll_count);
            if (score.verdict != .insufficient and score.verdict != .low) {
                try result.append(self.allocator, .{
                    .conn = conn,
                    .score = score,
                });
            }
        }

        const owned = try result.toOwnedSlice(self.allocator);

        std.mem.sort(ScoredEndpoint, owned, {}, struct {
            fn lessThan(_: void, a: ScoredEndpoint, b: ScoredEndpoint) bool {
                const ord_a = verdictOrd(a.score.verdict);
                const ord_b = verdictOrd(b.score.verdict);
                if (ord_a != ord_b) return ord_a < ord_b;
                return a.score.cov < b.score.cov;
            }
            fn verdictOrd(v: BeaconVerdict) u8 {
                return switch (v) {
                    .high => 0,
                    .persistent => 1,
                    .medium => 2,
                    .low => 3,
                    .insufficient => 4,
                };
            }
        }.lessThan);

        return owned;
    }

    pub fn reporting(self: *ConnectionMonitor, writer: anytype) !void {
        const elapsed_s = (api.GetTickCount64() - self.start_ms) / 1000;
        writer.print("\n  Beacon Analysis for PID {d} ({d} polls over {d}s):\n\n", .{
            self.pid, self.poll_count, elapsed_s,
        });

        const scored = try self.huntBeacons();
        defer self.allocator.free(scored);

        if (scored.len == 0) {
            writer.write("  No repeated connection patterns observed.\n\n");
            return;
        }

        var row_buf: [64][6][]const u8 = undefined;
        var row_count: usize = 0;

        var ip_bufs: [64][24]u8 = undefined;
        var conns_bufs: [64][8]u8 = undefined;
        var mean_bufs: [64][16]u8 = undefined;
        var cov_bufs: [64][12]u8 = undefined;

        for (scored) |s| {
            if (row_count >= 64) break;

            const c = s.conn;
            const bytes: [4]u8 = @bitCast(c.remote_ip);
            const ip_str = std.fmt.bufPrint(&ip_bufs[row_count], "{d}.{d}.{d}.{d}:{d}", .{
                bytes[0],                                      bytes[1], bytes[2], bytes[3],
                @byteSwap(@as(u16, @truncate(c.remote_port))),
            }) catch unreachable;

            const conns_str = std.fmt.bufPrint(&conns_bufs[row_count], "{d}", .{c.hit_count}) catch unreachable;
            const proto = if (c.is_https) "HTTPS" else if (c.is_http) "HTTP" else "TCP";

            const is_persistent = (s.score.verdict == .persistent);
            const mean_str = if (is_persistent)
                std.fmt.bufPrint(&mean_bufs[row_count], "{d:.0}s", .{s.score.mean_interval_ms / 1000.0}) catch unreachable
            else
                std.fmt.bufPrint(&mean_bufs[row_count], "{d:.1}s", .{s.score.mean_interval_ms / 1000.0}) catch unreachable;

            const cov_str = if (is_persistent)
                std.fmt.bufPrint(&cov_bufs[row_count], "{d:.0}%", .{s.score.presence_ratio * 100.0}) catch unreachable
            else
                std.fmt.bufPrint(&cov_bufs[row_count], "{d:.2}", .{s.score.cov}) catch unreachable;

            row_buf[row_count] = .{
                s.score.verdict.label(),
                ip_str,
                conns_str,
                proto,
                mean_str,
                if (is_persistent) cov_str else cov_str,
            };
            row_count += 1;
        }

        var row_slices: [64][]const []const u8 = undefined;
        for (row_buf[0..row_count], 0..) |*row, j| {
            row_slices[j] = &row.*;
        }

        writer.writeTable(
            &.{ "VERDICT", "ENDPOINT", "HITS", "PROTO", "MEAN/DUR", "COV/PRES" },
            row_slices[0..row_count],
        );

        writer.write("\n");
        for (scored) |s| {
            if (s.score.verdict == .high or s.score.verdict == .medium or s.score.verdict == .persistent) {
                const c = s.conn;
                const bytes: [4]u8 = @bitCast(c.remote_ip);
                var alert_ip: [24]u8 = undefined;
                const ip_str = std.fmt.bufPrint(&alert_ip, "{d}.{d}.{d}.{d}:{d}", .{
                    bytes[0],                                      bytes[1], bytes[2], bytes[3],
                    @byteSwap(@as(u16, @truncate(c.remote_port))),
                }) catch unreachable;

                if (s.score.verdict == .persistent) {
                    writer.print("  \x1b[95m[PERSIST]\x1b[0m {s} -- long-lived session {d:.0}s, present {d:.0}% of polls\n", .{
                        ip_str, s.score.mean_interval_ms / 1000.0, s.score.presence_ratio * 100.0,
                    });
                } else {
                    const mean_s = s.score.mean_interval_ms / 1000.0;
                    const sev = if (s.score.verdict == .high) "\x1b[91m[HIGH]\x1b[0m" else "\x1b[93m[MEDIUM]\x1b[0m";
                    writer.print("  {s} {s} -- {d} reconnections, mean interval {d:.1}s, CoV {d:.2}\n", .{
                        sev, ip_str, s.score.intervals, mean_s, s.score.cov,
                    });
                }
            }
        }
        writer.write("\n");
    }
};

pub const TcpConnection = struct {
    state: u32,
    local_addr: u32,
    local_port: u16,
    remote_addr: u32,
    remote_port: u16,
    pid: u32,
};

//pub extern "kernel32" fn QueryPerformanceFrequency(lpFrequency: *i64) callconv(.c) i32;

fn fmtIp(addr: u32, buf: []u8) []const u8 {
    const bytes: [4]u8 = @bitCast(addr);
    return std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{
        bytes[0], bytes[1], bytes[2], bytes[3],
    }) catch unreachable;
}

pub fn formatConnection(conn: TcpConnection, buf: []u8) []const u8 {
    const state: MIB_TCP_STATE = @enumFromInt(conn.state);
    var ip_buf: [16]u8 = undefined;

    const local_ip = fmtIp(conn.local_addr, &ip_buf);
    const remote_ip = fmtIp(conn.remote_addr, &ip_buf);
    const lport = @byteSwap(conn.local_port);
    const rport = @byteSwap(conn.remote_port);

    return std.fmt.bufPrint(buf, "{s:12} {s}:{d} -> {s}:{d}", .{
        state.tostr(),
        local_ip,
        lport,
        remote_ip,
        rport,
    }) catch unreachable;
}

pub fn listconnections(allocator: std.mem.Allocator, pid: u32) ![]TcpConnection {
    var buf_size: u32 = 0;
    const rc = api.GetExtendedTcpTable(null, &buf_size, api.FALSE, 2, TCP_TABLE_OWNER_PID_ALL, 0);
    if (rc != ERROR_INSUFFICIENT_BUFFER) {
        if (rc == NO_ERROR) return &.{};
        return error.Win32ApiError;
    }

    const table_buf = try allocator.alloc(u8, buf_size);
    defer allocator.free(table_buf);

    const rc2 = api.GetExtendedTcpTable(
        @ptrCast(table_buf.ptr),
        &buf_size,
        api.FALSE,
        2,
        TCP_TABLE_OWNER_PID_ALL,
        0,
    );
    if (rc2 != NO_ERROR) return error.Win32ApiError;

    const num_entries = @as(*u32, @ptrCast(@alignCast(table_buf.ptr))).*;
    if (num_entries == 0) return &.{};

    const rows_start = @as([*]u8, table_buf.ptr) + 4;
    const rows: [*]MIB_TCPROW_OWNER_PID = @ptrCast(@alignCast(rows_start));
    const row_count: usize = @intCast(num_entries);

    var match_count: usize = 0;
    var i: usize = 0;
    while (i < row_count) : (i += 1) {
        if (rows[i].dwOwningPid == pid) match_count += 1;
    }

    var result = try allocator.alloc(TcpConnection, match_count);
    var idx: usize = 0;
    i = 0;
    while (i < row_count) : (i += 1) {
        if (rows[i].dwOwningPid != pid) continue;
        result[idx] = .{
            .state = rows[i].dwstate,
            .local_addr = rows[i].dwLocalAddr,
            .local_port = @truncate(rows[i].dwLocalPort),
            .remote_addr = rows[i].dwRemoteAddr,
            .remote_port = @truncate(rows[i].dwRemotePort),
            .pid = rows[i].dwOwningPid,
        };
        idx += 1;
    }

    return result;
}
