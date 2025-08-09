#include <windows.h>
#include <stdio.h>

// 讀檔函數：讀取 .bin 檔案到記憶體
unsigned char* read_shellcode(const char* filename, DWORD* size) {
    HANDLE hFile = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, NULL,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to open file: %s\n", filename);
        return NULL;
    }

    *size = GetFileSize(hFile, NULL);
    if (*size == INVALID_FILE_SIZE) {
        printf("[-] Failed to get file size\n");
        CloseHandle(hFile);
        return NULL;
    }

    unsigned char* buffer = (unsigned char*)malloc(*size);
    if (!buffer) {
        printf("[-] Memory allocation failed\n");
        CloseHandle(hFile);
        return NULL;
    }

    DWORD bytesRead;
    if (!ReadFile(hFile, buffer, *size, &bytesRead, NULL)) {
        printf("[-] Failed to read file\n");
        free(buffer);
        CloseHandle(hFile);
        return NULL;
    }

    CloseHandle(hFile);
    return buffer;
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        printf("Usage: %s <shellcode.bin>\n", argv[0]);
        return -1;
    }

    DWORD shellcodeSize;
    unsigned char* shellcode = read_shellcode(argv[1], &shellcodeSize);
    if (!shellcode) {
        return -1;
    }

    printf("[+] Read %lu bytes of shellcode from %s\n", shellcodeSize, argv[1]);

    // 分配可執行記憶體
    void* exec_mem = VirtualAlloc(
        NULL,
        shellcodeSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    if (!exec_mem) {
        printf("[-] VirtualAlloc failed\n");
        free(shellcode);
        return -1;
    }

    // 複製 shellcode
    memcpy(exec_mem, shellcode, shellcodeSize);
    free(shellcode);

    printf("[+] Shellcode written to memory at %p\n", exec_mem);

    // 執行 shellcode
    HANDLE hThread = CreateThread(
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)exec_mem,
        NULL,
        0,
        NULL
    );

    if (!hThread) {
        printf("[-] CreateThread failed\n");
        return -1;
    }

    printf("[+] Shellcode thread started, waiting...\n");
    WaitForSingleObject(hThread, INFINITE);

    return 0;
}

