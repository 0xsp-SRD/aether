//! ============================================================================
//! File: privilege.zig
//! Author: Lawrence Amer (@zux0x3a - 0xsp.com)
//!
//! Summary:
//! Provides utility functions to enable SeDebugPrivilege. This allows the
//! current process token to inspect, interact with, and read/write the
//! memory of high-privilege running processes.
//! ============================================================================

const w = @import("win32.zig");

// "SeDebugPrivilege" as UTF-16LE, blame windows not myself.
const SE_DEBUG_NAME = [_:0]u16{ 'S', 'e', 'D', 'e', 'b', 'u', 'g', 'P', 'r', 'i', 'v', 'i', 'l', 'e', 'g', 'e' };

pub fn enableDebugPrivilege() bool {
    var token: ?w.HANDLE = null;

    if (w.OpenProcessToken(w.GetCurrentProcess(), w.TOKEN_ADJUST_PRIVILEGES | w.TOKEN_QUERY, &token) == w.FALSE) {
        return false;
    }

    const h = token orelse return false;
    defer _ = w.CloseHandle(h);

    var luid: w.LUID = undefined;
    if (w.LookupPrivilegeValueW(null, &SE_DEBUG_NAME, &luid) == w.FALSE) {
        return false;
    }

    var tp = w.TOKEN_PRIVILEGES{
        .PrivilegeCount = 1,
        .Privileges = .{.{
            .Luid = luid,
            .Attributes = w.SE_PRIVILEGE_ENABLED,
        }},
    };

    _ = w.AdjustTokenPrivileges(h, w.FALSE, &tp, @sizeOf(w.TOKEN_PRIVILEGES), null, null);
    return w.GetLastError() == 0;
}
