// This module need to be updated to support Zig 0.16 Io
// will be updated in the future release.

const std = @import("std");

const HANDLE = *anyopaque;
const BOOL = i32;
const DWORD = u32;

extern "kernel32" fn GetStdHandle(nStdHandle: DWORD) callconv(.c) ?HANDLE;
extern "kernel32" fn WriteFile(hFile: HANDLE, lpBuffer: [*]const u8, nNumberOfBytesToWrite: DWORD, lpNumberOfBytesWritten: ?*DWORD, lpOverlapped: ?*anyopaque) callconv(.c) BOOL;
extern "kernel32" fn GetConsoleMode(hConsoleHandle: HANDLE, lpMode: *DWORD) callconv(.c) BOOL;
extern "kernel32" fn SetConsoleMode(hConsoleHandle: HANDLE, dwMode: DWORD) callconv(.c) BOOL;
extern "kernel32" fn SetConsoleOutputCP(wCodePageID: u32) callconv(.c) i32;
const CP_UTF8: u32 = 65001;

const STD_INPUT_HANDLE: DWORD = @as(DWORD, @bitCast(@as(i32, -10)));
const STD_OUTPUT_HANDLE: DWORD = @as(DWORD, @bitCast(@as(i32, -11)));
const STD_ERROR_HANDLE: DWORD = @as(DWORD, @bitCast(@as(i32, -12)));

const ENABLE_QUICK_EDIT_MODE: DWORD = 0x0040;
const ENABLE_EXTENDED_FLAGS: DWORD = 0x0080;
const ENABLE_MOUSE_INPUT: DWORD = 0x0010;

// TEMP FUNCTIONS
//
//
//
//

pub fn disableQuickEdit() void {
    const h = GetStdHandle(STD_INPUT_HANDLE) orelse return;
    var mode: DWORD = 0;
    if (GetConsoleMode(h, &mode) == 0) return;
    mode &= ~ENABLE_QUICK_EDIT_MODE;
    mode &= ~ENABLE_MOUSE_INPUT;
    mode |= ENABLE_EXTENDED_FLAGS;
    _ = SetConsoleMode(h, mode);
}

pub fn enableUtf8() void {
    _ = SetConsoleOutputCP(CP_UTF8);
}
pub const Writer = struct {
    handle: HANDLE,

    pub fn write(self: Writer, bytes: []const u8) void {
        var remaining = bytes;
        while (remaining.len > 0) {
            const chunk: DWORD = @intCast(@min(remaining.len, 0x7FFFFFFF));
            var written: DWORD = 0;
            _ = WriteFile(self.handle, remaining.ptr, chunk, &written, null);
            if (written == 0) break;
            remaining = remaining[@intCast(written)..];
        }
    }

    pub fn print(self: Writer, comptime fmt: []const u8, args: anytype) void {
        var buf: [8192]u8 = undefined;
        const slice = std.fmt.bufPrint(&buf, fmt, args) catch {
            self.write("(format error)\n");
            return;
        };
        self.write(slice);
    }

    pub fn writeAll(self: Writer, bytes: []const u8) void {
        self.write(bytes);
    }

    pub fn writeByte(self: Writer, byte: u8) void {
        const b = [1]u8{byte};
        self.write(&b);
    }

    pub fn writeTable(self: Writer, headers: []const []const u8, rows: []const []const []const u8) void {
        const cols = headers.len;
        if (cols == 0) return;

        var width: [16]usize = [_]usize{0} ** 16;

        for (headers, 0..) |h, c| {
            width[c] = h.len;
        }
        for (rows) |row| {
            for (row, 0..) |cell, c| {
                if (cell.len > width[c]) width[c] = cell.len;
            }
        }
        const w = width[0..cols];

        self.write("  ");
        self.tableBorder(w, "┌", "┬", "┐");

        // Header
        self.write("  ");
        self.tableRow(w, headers);

        // Separator
        self.write("  ");
        self.tableBorder(w, "├", "┼", "┤");

        // Data rows
        for (rows) |row| {
            self.write("  ");
            self.tableRow(w, row);
        }

        // Bottom border
        self.write("  ");
        self.tableBorder(w, "└", "┴", "┘");
    }
    fn tableBorder(self: Writer, widths: []const usize, left: []const u8, mid: []const u8, right: []const u8) void {
        self.write(left);
        for (widths[0 .. widths.len - 1]) |cw| {
            self.repeat("─", cw + 2);
            self.write(mid);
        }
        self.repeat("─", widths[widths.len - 1] + 2);
        self.write(right);
        self.write("\n");
    }

    fn tableRow(self: Writer, widths: []const usize, cells: []const []const u8) void {
        self.write("│");
        for (cells, 0..) |cell, c| {
            self.write(" ");
            self.write(cell);
            self.repeat(" ", widths[c] - cell.len + 1);
            self.write("│");
        }
        self.write("\n");
    }

    fn repeat(self: Writer, ch: []const u8, count: usize) void {
        var n = count;
        while (n > 0) : (n -= 1) {
            self.write(ch);
        }
    }
};

pub fn stdout() Writer {
    return .{ .handle = GetStdHandle(STD_OUTPUT_HANDLE) orelse unreachable };
}

pub fn stderr() Writer {
    return .{ .handle = GetStdHandle(STD_ERROR_HANDLE) orelse unreachable };
}
