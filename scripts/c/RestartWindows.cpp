#include <windows.h>
#include <iostream>

void RestartWindows() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tkp;

    // Get a token for this process.
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        std::cerr << "OpenProcessToken failed." << std::endl;
        return;
    }

    // Get the LUID for the shutdown privilege.
    if (!LookupPrivilegeValue(NULL, SE_SHUTDOWN_NAME, &tkp.Privileges[0].Luid)) {
        std::cerr << "LookupPrivilegeValue failed." << std::endl;
        CloseHandle(hToken);
        return;
    }

    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    // Enable the shutdown privilege.
    if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, (PTOKEN_PRIVILEGES)NULL, 0)) {
        std::cerr << "AdjustTokenPrivileges failed." << std::endl;
        CloseHandle(hToken);
        return;
    }

    // Call ExitWindowsEx to reboot the system.
    if (!ExitWindowsEx(EWX_REBOOT | EWX_FORCE, SHTDN_REASON_MAJOR_OPERATINGSYSTEM | SHTDN_REASON_MINOR_RECONFIG | SHTDN_REASON_FLAG_PLANNED)) {
        std::cerr << "ExitWindowsEx failed." << std::endl;
    }

    CloseHandle(hToken);
}

int main() {
    std::cout << "Attempting to restart Windows..." << std::endl;
    RestartWindows();
    return 0;
}