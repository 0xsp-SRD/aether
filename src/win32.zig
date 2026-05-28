// Win32 API declarations for process memory inspection.
// Using manual declarations instead of @cImport for cross-compilation compatibility.

pub const HANDLE = *anyopaque;
pub const BOOL = i32;
pub const DWORD = u32;
pub const WORD = u16;
pub const BYTE = u8;
pub const LONG = i32;
pub const ULONG_PTR = usize;
pub const SIZE_T = usize;
pub const LPCSTR = [*:0]const u8;
pub const LPCWSTR = [*:0]const u16;
pub const PVOID = *anyopaque;
pub const LPVOID = *anyopaque;

pub const FALSE: BOOL = 0;
pub const TRUE: BOOL = 1;
pub const INVALID_HANDLE_VALUE: HANDLE = @ptrFromInt(~@as(usize, 0));

// Process access rights
pub const PROCESS_VM_READ: DWORD = 0x0010;
pub const PROCESS_QUERY_INFORMATION: DWORD = 0x0400;
pub const PROCESS_QUERY_LIMITED_INFORMATION: DWORD = 0x1000;

// Memory region constants
pub const MEM_COMMIT: DWORD = 0x1000;
pub const MEM_FREE: DWORD = 0x10000;
pub const MEM_RESERVE: DWORD = 0x2000;
pub const MEM_IMAGE: DWORD = 0x1000000;
pub const MEM_MAPPED: DWORD = 0x40000;
pub const MEM_PRIVATE: DWORD = 0x20000;

// Page protections
pub const PAGE_NOACCESS: DWORD = 0x01;
pub const PAGE_GUARD: DWORD = 0x100;
pub const PAGE_EXECUTE: DWORD = 0x10;
pub const PAGE_EXECUTE_READ: DWORD = 0x20;
pub const PAGE_EXECUTE_READWRITE: DWORD = 0x40;
pub const PAGE_EXECUTE_WRITECOPY: DWORD = 0x80;
pub const PAGE_READONLY: DWORD = 0x02;
pub const PAGE_READWRITE: DWORD = 0x04;
pub const PAGE_WRITECOPY: DWORD = 0x08;

// Token
pub const TOKEN_ADJUST_PRIVILEGES: DWORD = 0x0020;
pub const TOKEN_QUERY: DWORD = 0x0008;
pub const SE_PRIVILEGE_ENABLED: DWORD = 0x00000002;

// Snapshot
pub const TH32CS_SNAPPROCESS: DWORD = 0x00000002;
pub const TH32CS_SNAPMODULE: DWORD = 0x00000008;
pub const TH32CS_SNAPMODULE32: DWORD = 0x00000010;
pub const MAX_PATH = 260;
pub const MAX_MODULE_NAME32 = 255;
pub const STATUS_SUCCESS: u32 = 0;
pub const STATUS_ACCESS_DENIED: u32 = 0xc0000022;
pub const UNICODE_STRING = extern struct {
    Length: u16,
    MaximumLength: u16,
    Buffer: ?[*]u16,
};

//  Thread types

pub const TH32CS_SNAPTHREAD: DWORD = 0x00000004;
pub const THREAD_QUERY_INFORMATION: DWORD = 0x0040;
pub const THREAD_QUERY_LIMITED_INFORMATION: DWORD = 0x0800;
pub const THREAD_GET_CONTEXT: DWORD = 0x0008;
pub const THREAD_SUSPEND_RESUME: DWORD = 0x0002;

// x64 CONTEXT is 1232 bytes, 16-byte aligned. Rip lives at fixed offset 0xF8
// (winnt.h). We treat it as an opaque aligned byte buffer to avoid declaring
// the entire alignment-sensitive layout (XMM_SAVE_AREA32 union, FloatSave,
// VectorRegister[26], etc.). Same approach used by PE-Sieve / Moneta.
pub const CONTEXT_AMD64_SIZE: usize = 1232;
pub const CONTEXT_AMD64_RIP_OFFSET: usize = 0xF8;
pub const CONTEXT_AMD64_CONTEXT_FLAGS_OFFSET: usize = 0x30;

// CONTEXT_CONTROL on AMD64 = CONTEXT_AMD64 | 0x1. Enough to retrieve Rip.
pub const CONTEXT_AMD64: u32 = 0x00100000;
pub const CONTEXT_CONTROL_AMD64: u32 = CONTEXT_AMD64 | 0x00000001;

pub const ContextAmd64Buf = extern struct {
    bytes: [CONTEXT_AMD64_SIZE]u8 align(16),
};

// WOW64_CONTEXT is documented per winnt.h: ContextFlags at offset 0, then a
// fixed sequence of DWORDs leading to Eip at offset 0xB8 (decimal 184).
// Layout: ContextFlags, Dr0..Dr3, Dr6, Dr7 (7 DWORDs = 28 bytes), then
// WOW64_FLOATING_SAVE_AREA (112 bytes), then SegGs..Ebp (10 DWORDs = 40 bytes,
// ending at 28+112+40 = 180), then Eip at 184.
pub const WOW64_CONTEXT_EIP_OFFSET: usize = 0xB8;
pub const WOW64_CONTEXT_CONTROL: u32 = 0x00010001;
// Total size: 4 (header) + 7*4 (Dr) + 112 (FloatSave) + 10*4 (segs/regs) +
// 4 (Eip) + 5*4 (SegCs, EFlags, Esp, SegSs, +1 align) + 512 (ExtendedRegisters)
// = 716. Round up for safety.
pub const WOW64_CONTEXT_SIZE: usize = 716;
pub const Wow64ContextBuf = extern struct {
    bytes: [WOW64_CONTEXT_SIZE]u8 align(16),
};

pub const THREADENTRY32 = extern struct {
    dwSize: DWORD,
    cntUsage: DWORD,
    th32ThreadID: DWORD,
    th32OwnerProcessID: DWORD,
    tpBasePri: LONG,
    tpDeltaPri: LONG,
    dwFlags: DWORD,
};

const THREADINFOCLASS = enum(u32) {
    ThreadBasicInformation = 0,
    ThreadTimes = 1,
    ThreadPriority = 2,
    ThreadBasePriority = 3,
    ThreadAffinityMask = 4,
    ThreadImpersonationToken = 5,
    ThreadDescriptorTableEntry = 6,
    ThreadEnableAlignmentFaultFixup = 7,
    ThreadEventPair = 8,
    ThreadQuerySetWin32StartAddress = 9,
    ThreadZeroTlsCell = 10,
    ThreadPerformanceCount = 11,
    ThreadAmILastThread = 12,
    ThreadIdealProcessor = 13,
    ThreadPriorityBoost = 14,
    ThreadSetTlsArrayAddress = 15,
    ThreadIsIoPending = 16,
    ThreadHideFromDebugger = 17,
    ThreadBreakOnTermination = 18,
};

pub const OBJECT_ATTRIBUTES = extern struct {
    Length: u32,
    RootDirectory: ?HANDLE,
    ObjectName: ?*UNICODE_STRING,
    Attributes: u32,
    SecurityDescriptor: ?*anyopaque,
    SecurityQualityOfService: ?*anyopaque,
};

pub const PSAPI_WORKING_SET_EX_INFORMATION = extern struct {
    VirtualAddress: usize,
    VirtualAttributes: packed struct(u64) {
        Valid: u1 = 0,
        ShareCount: u3 = 0,
        Win32Protection: u11 = 0,
        Shared: u1 = 0,
        Node: u6 = 0,
        Locked: u1 = 0,
        LargePage: u1 = 0,
        _reserved: u40 = 0,
    },
};
pub const MEMORY_BASIC_INFORMATION = extern struct {
    BaseAddress: usize,
    AllocationBase: usize,
    AllocationProtect: DWORD,
    PartitionId: WORD,
    RegionSize: SIZE_T,
    State: DWORD,
    Protect: DWORD,
    Type: DWORD,
};

pub const PROCESSENTRY32W = extern struct {
    dwSize: DWORD,
    cntUsage: DWORD,
    th32ProcessID: DWORD,
    th32DefaultHeapID: ULONG_PTR,
    th32ModuleID: DWORD,
    cntThreads: DWORD,
    th32ParentProcessID: DWORD,
    pcPriClassBase: LONG,
    dwFlags: DWORD,
    szExeFile: [MAX_PATH]u16,
};

pub const MODULEENTRY32W = extern struct {
    dwSize: DWORD,
    th32ModuleID: DWORD,
    th32ProcessID: DWORD,
    GlblcntUsage: DWORD,
    ProccntUsage: DWORD,
    modBaseAddr: usize,
    modBaseSize: DWORD,
    hModule: ?HANDLE,
    szModule: [MAX_MODULE_NAME32 + 1]u16,
    szExePath: [MAX_PATH]u16,
};

pub const LUID = extern struct {
    LowPart: DWORD,
    HighPart: LONG,
};

pub const LUID_AND_ATTRIBUTES = extern struct {
    Luid: LUID,
    Attributes: DWORD,
};

pub const TOKEN_PRIVILEGES = extern struct {
    PrivilegeCount: DWORD,
    Privileges: [1]LUID_AND_ATTRIBUTES,
};

pub extern "ntdll" fn RtlInitUnicodeString(
    DestinationString: *UNICODE_STRING,
    SourceString: [*:0]const u16,
) callconv(.c) void;

pub extern "ntdll" fn NtOpenSection(
    SectionHandle: *?HANDLE,
    DesiredAccess: u32,
    ObjectAttributes: *OBJECT_ATTRIBUTES,
) callconv(.c) u32;

pub extern "ntdll" fn NtClose(Handle: HANDLE) callconv(.c) u32;
// kernel32
pub extern "kernel32" fn OpenProcess(dwDesiredAccess: DWORD, bInheritHandle: BOOL, dwProcessId: DWORD) callconv(.c) ?HANDLE;
pub extern "kernel32" fn CloseHandle(hObject: HANDLE) callconv(.c) BOOL;
pub extern "kernel32" fn GetCurrentProcess() callconv(.c) HANDLE;
pub extern "kernel32" fn GetLastError() callconv(.c) DWORD;

pub extern "kernel32" fn VirtualQueryEx(hProcess: HANDLE, lpAddress: usize, lpBuffer: *MEMORY_BASIC_INFORMATION, dwLength: SIZE_T) callconv(.c) SIZE_T;
pub extern "kernel32" fn ReadProcessMemory(hProcess: HANDLE, lpBaseAddress: usize, lpBuffer: [*]u8, nSize: SIZE_T, lpNumberOfBytesRead: *SIZE_T) callconv(.c) BOOL;

pub extern "kernel32" fn CreateToolhelp32Snapshot(dwFlags: DWORD, th32ProcessID: DWORD) callconv(.c) ?HANDLE;
pub extern "kernel32" fn Process32FirstW(hSnapshot: HANDLE, lppe: *PROCESSENTRY32W) callconv(.c) BOOL;
pub extern "kernel32" fn Process32NextW(hSnapshot: HANDLE, lppe: *PROCESSENTRY32W) callconv(.c) BOOL;
pub extern "kernel32" fn Module32FirstW(hSnapshot: HANDLE, lpme: *MODULEENTRY32W) callconv(.c) BOOL;
pub extern "kernel32" fn Module32NextW(hSnapshot: HANDLE, lpme: *MODULEENTRY32W) callconv(.c) BOOL;

pub extern "kernel32" fn GetModuleFileNameExW(hProcess: HANDLE, hModule: ?HANDLE, lpFilename: [*]u16, nSize: DWORD) callconv(.c) DWORD;
pub extern "kernel32" fn GetTickCount64() callconv(.c) u64;

pub extern "kernel32" fn GetCommandLineW() callconv(.c) [*:0]const u16;
pub extern "shell32" fn CommandLineToArgvW(lpCmdLine: [*:0]const u16, pNumArgs: *i32) callconv(.c) ?[*]const [*:0]const u16;
pub extern "kernel32" fn LocalFree(hMem: ?*anyopaque) callconv(.c) ?*anyopaque;

pub extern "kernel32" fn Thread32First(hSnapshot: HANDLE, lpte: *THREADENTRY32) callconv(.c) BOOL;
pub extern "kernel32" fn Thread32Next(hSnapshot: HANDLE, lpte: *THREADENTRY32) callconv(.c) BOOL;
pub extern "kernel32" fn OpenThread(dwDesiredAccess: DWORD, bInheritHandle: BOOL, dwThreadId: DWORD) callconv(.c) ?HANDLE;

pub extern "kernel32" fn GetThreadContext(hThread: HANDLE, lpContext: *anyopaque) callconv(.c) BOOL;
pub extern "kernel32" fn Wow64GetThreadContext(hThread: HANDLE, lpContext: *anyopaque) callconv(.c) BOOL;
pub extern "kernel32" fn IsWow64Process(hProcess: HANDLE, Wow64Process: *BOOL) callconv(.c) BOOL;

pub extern "kernel32" fn GetProcAddress(hModule: HANDLE, lpProcName: LPCSTR) callconv(.c) ?*anyopaque;
pub extern "kernel32" fn GetModuleHandleA(lpModuleName: ?LPCSTR) callconv(.c) ?HANDLE;

pub extern "ntdll" fn NtQueryInformationThread(
    ThreadHandle: HANDLE,
    ThreadInformationClass: THREADINFOCLASS,
    ThreadInformation: ?*anyopaque,
    ThreadInformationLength: u32,
    ReturnLength: ?*u32,
) callconv(.c) u32;

pub extern "kernel32" fn K32QueryWorkingSetEx(
    hProcess: HANDLE,
    pv: [*]PSAPI_WORKING_SET_EX_INFORMATION,
    cb: u32,
) callconv(.c) BOOL;

// File mapping (used for on-disk PE diff against in-memory IMAGE)
pub const FILE_SHARE_READ: DWORD = 0x00000001;
pub const FILE_ATTRIBUTE_NORMAL: DWORD = 0x80;
pub const OPEN_EXISTING: DWORD = 3;
pub const GENERIC_READ: DWORD = 0x80000000;
pub const PAGE_READONLY_FLAG: DWORD = 0x02;
pub const SEC_IMAGE: DWORD = 0x1000000;
pub const SEC_IMAGE_NO_EXECUTE: DWORD = 0x11000000;
pub const FILE_MAP_READ: DWORD = 0x0004;

pub extern "kernel32" fn CreateFileW(
    lpFileName: LPCWSTR,
    dwDesiredAccess: DWORD,
    dwShareMode: DWORD,
    lpSecurityAttributes: ?*anyopaque,
    dwCreationDisposition: DWORD,
    dwFlagsAndAttributes: DWORD,
    hTemplateFile: ?HANDLE,
) callconv(.c) ?HANDLE;

pub extern "kernel32" fn CreateFileMappingW(
    hFile: HANDLE,
    lpFileMappingAttributes: ?*anyopaque,
    flProtect: DWORD,
    dwMaximumSizeHigh: DWORD,
    dwMaximumSizeLow: DWORD,
    lpName: ?LPCWSTR,
) callconv(.c) ?HANDLE;

pub extern "kernel32" fn MapViewOfFile(
    hFileMappingObject: HANDLE,
    dwDesiredAccess: DWORD,
    dwFileOffsetHigh: DWORD,
    dwFileOffsetLow: DWORD,
    dwNumberOfBytesToMap: SIZE_T,
) callconv(.c) ?*anyopaque;

pub extern "kernel32" fn UnmapViewOfFile(lpBaseAddress: *const anyopaque) callconv(.c) BOOL;

//https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedtcptable
//
pub extern "iphlpapi" fn GetExtendedTcpTable(
    pTcpTable: ?*anyopaque,
    pdwSize: *u32,
    bOrder: i32,
    lAf: u32,
    TableClass: u32,
    Reserved: u32,
) callconv(.c) u32;

// Add at the top of network_m.zig:
pub extern "kernel32" fn Sleep(dwMilliseconds: u32) callconv(.c) void;

// advapi32
pub extern "advapi32" fn OpenProcessToken(ProcessHandle: HANDLE, DesiredAccess: DWORD, TokenHandle: *?HANDLE) callconv(.c) BOOL;
pub extern "advapi32" fn LookupPrivilegeValueW(lpSystemName: ?LPCWSTR, lpName: LPCWSTR, lpLuid: *LUID) callconv(.c) BOOL;
pub extern "advapi32" fn AdjustTokenPrivileges(TokenHandle: HANDLE, DisableAllPrivileges: BOOL, NewState: *TOKEN_PRIVILEGES, BufferLength: DWORD, PreviousState: ?*TOKEN_PRIVILEGES, ReturnLength: ?*DWORD) callconv(.c) BOOL;

pub fn isReadable(protect: DWORD) bool {
    const readable = PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
        PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    if (protect & PAGE_NOACCESS != 0) return false;
    if (protect & PAGE_GUARD != 0) return false;
    return (protect & readable) != 0;
}

pub fn isExecutable(protect: DWORD) bool {
    const executable = PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    return (protect & executable) != 0;
}

pub fn isWritableNotExecutable(protect: DWORD) bool {
    if (protect & PAGE_GUARD != 0) return false;
    if (protect & PAGE_NOACCESS != 0) return false;
    if (isExecutable(protect)) return false;
    const writable = PAGE_READWRITE | PAGE_WRITECOPY;
    return (protect & writable) != 0;
}

pub fn wideToSlice(wide: []const u16) []const u16 {
    for (wide, 0..) |c, i| {
        if (c == 0) return wide[0..i];
    }
    return wide;
}
