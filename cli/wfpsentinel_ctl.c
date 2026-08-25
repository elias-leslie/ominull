#include <windows.h>
#include <winioctl.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>
#include "../driver/include/wfpsentinel_ioctl.h"

#pragma comment(lib, "ws2_32.lib")

static HANDLE OpenDriverHandle(void) {
    HANDLE hDevice = CreateFileA(
        WFPSENTINEL_USERMODE_PATH,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hDevice == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        printf("[-] Failed to open device %s (Error %lu)\n", WFPSENTINEL_USERMODE_PATH, err);
    }
    return hDevice;
}

static void PrintUsage(const char* prog) {
    printf("WfpSentinel Policy Controller v1.0\n");
    printf("Usage:\n");
    printf("  %s block <ip> [port] [proto: tcp|udp] [pid]\n", prog);
    printf("  %s clear\n", prog);
    printf("  %s stats\n", prog);
    printf("Examples:\n");
    printf("  %s block 10.0.0.57 9998 tcp\n", prog);
    printf("  %s block 10.0.0.57 0\n", prog);
    printf("  %s stats\n", prog);
    printf("  %s clear\n", prog);
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        PrintUsage(argv[0]);
        return 1;
    }

    HANDLE hDevice = OpenDriverHandle();
    if (hDevice == INVALID_HANDLE_VALUE) {
        return 1;
    }

    if (_stricmp(argv[1], "block") == 0) {
        if (argc < 3) {
            printf("[-] Missing IP address to block\n");
            CloseHandle(hDevice);
            return 1;
        }

        WFPSENTINEL_BLOCK_RULE rule;
        ZeroMemory(&rule, sizeof(rule));

        // Parse IP
        struct in_addr addr;
        if (inet_pton(AF_INET, argv[2], &addr) != 1) {
            printf("[-] Invalid IPv4 address: %s\n", argv[2]);
            CloseHandle(hDevice);
            return 1;
        }
        rule.RemoteIpV4 = ntohl(addr.s_addr);
        rule.RemoteIpMask = 0xFFFFFFFF; // Exact host match

        // Parse Port
        if (argc >= 4) {
            rule.RemotePort = (UINT16)atoi(argv[3]);
        }

        // Parse Protocol
        if (argc >= 5) {
            if (_stricmp(argv[4], "tcp") == 0) {
                rule.Protocol = 6;
            } else if (_stricmp(argv[4], "udp") == 0) {
                rule.Protocol = 17;
            } else {
                rule.Protocol = (UINT8)atoi(argv[4]);
            }
        }

        // Parse PID
        if (argc >= 6) {
            rule.ProcessId = (UINT64)_strtoui64(argv[5], NULL, 10);
        }

        DWORD bytesReturned = 0;
        BOOL ok = DeviceIoControl(
            hDevice,
            IOCTL_WFPSENTINEL_ADD_BLOCK_RULE,
            &rule,
            sizeof(rule),
            NULL,
            0,
            &bytesReturned,
            NULL
        );

        if (ok) {
            printf("[+] Successfully added block rule in kernel:\n");
            printf("    Remote IP:   %s\n", argv[2]);
            printf("    Remote Port: %u (%s)\n", rule.RemotePort, rule.RemotePort ? "exact" : "any");
            printf("    Protocol:    %u (%s)\n", rule.Protocol, rule.Protocol == 6 ? "TCP" : rule.Protocol == 17 ? "UDP" : "any");
            printf("    PID:         %llu (%s)\n", rule.ProcessId, rule.ProcessId ? "exact" : "any");
        } else {
            printf("[-] DeviceIoControl failed: %lu\n", GetLastError());
        }

    } else if (_stricmp(argv[1], "clear") == 0) {
        DWORD bytesReturned = 0;
        BOOL ok = DeviceIoControl(
            hDevice,
            IOCTL_WFPSENTINEL_CLEAR_BLOCK_RULES,
            NULL,
            0,
            NULL,
            0,
            &bytesReturned,
            NULL
        );

        if (ok) {
            printf("[+] Successfully cleared all kernel block rules\n");
        } else {
            printf("[-] DeviceIoControl failed: %lu\n", GetLastError());
        }

    } else if (_stricmp(argv[1], "stats") == 0) {
        WFPSENTINEL_STATS stats;
        ZeroMemory(&stats, sizeof(stats));
        DWORD bytesReturned = 0;

        BOOL ok = DeviceIoControl(
            hDevice,
            IOCTL_WFPSENTINEL_GET_STATS,
            NULL,
            0,
            &stats,
            sizeof(stats),
            &bytesReturned,
            NULL
        );

        if (ok) {
            printf("=== WFPSENTINEL KERNEL STATISTICS ===\n");
            printf("  Active Block Rules:         %u\n", stats.ActiveRuleCount);
            printf("  Total Connections Classified: %llu\n", stats.TotalClassified);
            printf("  Total Permitted:            %llu\n", stats.TotalPermitted);
            printf("  Total Blocked:              %llu\n", stats.TotalBlocked);
        } else {
            printf("[-] DeviceIoControl failed: %lu\n", GetLastError());
        }

    } else {
        PrintUsage(argv[0]);
    }

    CloseHandle(hDevice);
    return 0;
}
