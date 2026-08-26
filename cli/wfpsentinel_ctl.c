#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include "../driver/include/wfpsentinel_ioctl.h"

#pragma comment(lib, "ws2_32.lib")

static volatile BOOL g_Running = TRUE;
static HANDLE g_hDevice = INVALID_HANDLE_VALUE;

static void SignalHandler(int signum) {
    (void)signum;
    g_Running = FALSE;
    if (g_hDevice != INVALID_HANDLE_VALUE) {
        CancelIo(g_hDevice);
    }
}

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

static void FormatIpv4(UINT32 ip, char* out, size_t outSize) {
    snprintf(out, outSize, "%u.%u.%u.%u",
        (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF);
}

static void FormatIpv6(const UINT8* ip6, char* out, size_t outSize) {
    struct in6_addr in6;
    memcpy(&in6, ip6, 16);
    if (!inet_ntop(AF_INET6, &in6, out, (socklen_t)outSize)) {
        snprintf(out, outSize, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
            ip6[0], ip6[1], ip6[2], ip6[3], ip6[4], ip6[5], ip6[6], ip6[7],
            ip6[8], ip6[9], ip6[10], ip6[11], ip6[12], ip6[13], ip6[14], ip6[15]);
    }
}

static const char* ProtocolName(UINT8 proto) {
    switch (proto) {
    case 6: return "TCP";
    case 17: return "UDP";
    case 1: return "ICMP";
    case 58: return "ICMPv6";
    case 0: return "ANY";
    default: return "OTHER";
    }
}

static const char* DirectionName(UINT8 dir) {
    switch (dir) {
    case WFPSENTINEL_DIR_OUTBOUND: return "OUTBOUND";
    case WFPSENTINEL_DIR_INBOUND:  return "INBOUND";
    default: return "ANY";
    }
}

static const char* EventTypeName(UINT32 evtType) {
    switch (evtType) {
    case WFPSENTINEL_EVENT_CONNECT_V4:          return "CONNECT_V4";
    case WFPSENTINEL_EVENT_CONNECT_V6:          return "CONNECT_V6";
    case WFPSENTINEL_EVENT_RECV_ACCEPT_V4:      return "RECV_ACCEPT_V4";
    case WFPSENTINEL_EVENT_RECV_ACCEPT_V6:      return "RECV_ACCEPT_V6";
    case WFPSENTINEL_EVENT_FLOW_ESTABLISHED_V4: return "FLOW_EST_V4";
    case WFPSENTINEL_EVENT_FLOW_ESTABLISHED_V6: return "FLOW_EST_V6";
    case WFPSENTINEL_EVENT_FLOW_CLOSED:         return "FLOW_CLOSED";
    case WFPSENTINEL_EVENT_BLOCKED:             return "BLOCKED";
    default: return "UNKNOWN";
    }
}

static void PrintUsage(const char* prog) {
    printf("===============================================================================\n");
    printf("   WfpSentinel Policy Controller & Telemetry Streaming Utility (Dual-Stack)\n");
    printf("===============================================================================\n");
    printf("Usage:\n");
    printf("  %s block <ip[/cidr]> [port] [proto] [pid] [app] [--dir in|out]\n", prog);
    printf("  %s allow <ip[/cidr]> [port] [proto] [pid] [app] [--dir in|out]\n", prog);
    printf("  %s block-app <path_substring>\n", prog);
    printf("  %s allow-app <path_substring>\n", prog);
    printf("  %s rules\n", prog);
    printf("  %s delete <rule_id>\n", prog);
    printf("  %s clear\n", prog);
    printf("  %s stats\n", prog);
    printf("  %s monitor\n", prog);
    printf("  %s stream\n", prog);
    printf("\nExamples:\n");
    printf("  %s block 10.0.0.57 9998 tcp\n", prog);
    printf("  %s block 10.0.0.0/8 443 tcp\n", prog);
    printf("  %s block 2001:db8::/32 80 tcp\n", prog);
    printf("  %s block ::1 0\n", prog);
    printf("  %s block-app curl.exe\n", prog);
    printf("  %s allow 10.0.0.1 53 udp\n", prog);
    printf("  %s monitor\n", prog);
    printf("  %s stats\n", prog);
    printf("  %s rules\n", prog);
    printf("  %s delete 1\n", prog);
    printf("  %s clear\n", prog);
    printf("===============================================================================\n");
}

static int ParseRuleFromArgs(int argc, char* argv[], UINT8 action, PWFPSENTINEL_RULE outRule) {
    ZeroMemory(outRule, sizeof(WFPSENTINEL_RULE));
    outRule->Action = action;
    outRule->Direction = WFPSENTINEL_DIR_ANY;

    if (argc < 3) {
        printf("[-] Missing IP / CIDR argument\n");
        return 0;
    }

    char ipStr[128];
    strncpy(ipStr, argv[2], sizeof(ipStr) - 1);
    ipStr[sizeof(ipStr) - 1] = '\0';

    char* slash = strchr(ipStr, '/');
    int prefixLen = -1;
    if (slash) {
        *slash = '\0';
        prefixLen = atoi(slash + 1);
    }

    // Try IPv4 first
    struct in_addr addr4;
    if (inet_pton(AF_INET, ipStr, &addr4) == 1) {
        outRule->IpVersion = 4;
        outRule->RemoteIpV4 = ntohl(addr4.s_addr);
        if (prefixLen < 0) {
            outRule->RemoteIpV4Mask = 0xFFFFFFFF;
        } else if (prefixLen == 0) {
            outRule->RemoteIpV4Mask = 0;
        } else if (prefixLen > 32) {
            prefixLen = 32;
            outRule->RemoteIpV4Mask = 0xFFFFFFFF;
        } else {
            outRule->RemoteIpV4Mask = (UINT32)(0xFFFFFFFFULL << (32 - prefixLen));
        }
    } else {
        // Try IPv6
        struct in6_addr addr6;
        if (inet_pton(AF_INET6, ipStr, &addr6) == 1) {
            outRule->IpVersion = 6;
            memcpy(outRule->RemoteIpV6, &addr6, 16);
            if (prefixLen < 0) {
                outRule->RemoteIpV6PrefixLen = 128;
            } else if (prefixLen > 128) {
                outRule->RemoteIpV6PrefixLen = 128;
            } else {
                outRule->RemoteIpV6PrefixLen = (UINT8)prefixLen;
            }
        } else {
            printf("[-] Invalid IP address format: %s\n", argv[2]);
            return 0;
        }
    }

    // Parse optional positional parameters
    for (int i = 3; i < argc; i++) {
        if (_stricmp(argv[i], "--dir") == 0 && i + 1 < argc) {
            i++;
            if (_stricmp(argv[i], "in") == 0 || _stricmp(argv[i], "inbound") == 0) {
                outRule->Direction = WFPSENTINEL_DIR_INBOUND;
            } else if (_stricmp(argv[i], "out") == 0 || _stricmp(argv[i], "outbound") == 0) {
                outRule->Direction = WFPSENTINEL_DIR_OUTBOUND;
            }
        } else if (i == 3) {
            outRule->RemotePort = (UINT16)atoi(argv[3]);
        } else if (i == 4) {
            if (_stricmp(argv[4], "tcp") == 0) {
                outRule->Protocol = 6;
            } else if (_stricmp(argv[4], "udp") == 0) {
                outRule->Protocol = 17;
            } else if (_stricmp(argv[4], "icmp") == 0) {
                outRule->Protocol = (outRule->IpVersion == 6) ? 58 : 1;
            } else {
                outRule->Protocol = (UINT8)atoi(argv[4]);
            }
        } else if (i == 5) {
            outRule->ProcessId = (UINT64)_strtoui64(argv[5], NULL, 10);
        } else if (i == 6) {
            int len = MultiByteToWideChar(CP_UTF8, 0, argv[6], -1, outRule->ProcessPath, WFPSENTINEL_MAX_PATH - 1);
            if (len > 0) {
                outRule->ProcessPathLen = (UINT16)(len - 1);
            }
        }
    }

    return 1;
}

static void RunStreamMonitor(HANDLE hDevice) {
    printf("[*] Starting Real-Time Telemetry Stream (Inverted Call IOCTL)...\n");
    printf("[*] Press Ctrl+C to stop monitoring.\n\n");
    printf("%-20s %-16s %-8s %-6s %-32s -> %-32s %-8s %-6s %s\n",
        "TIMESTAMP", "EVENT", "ACTION", "DIR", "LOCAL ENDPOINT", "REMOTE ENDPOINT", "PROTO", "PID", "IMAGE PATH");
    printf("----------------------------------------------------------------------------------------------------------------------------------------------------\n");

    signal(SIGINT, SignalHandler);

    while (g_Running) {
        WFPSENTINEL_EVENT ev;
        ZeroMemory(&ev, sizeof(ev));
        DWORD bytesReturned = 0;

        BOOL ok = DeviceIoControl(
            hDevice,
            IOCTL_WFPSENTINEL_STREAM_EVENT,
            NULL,
            0,
            &ev,
            sizeof(ev),
            &bytesReturned,
            NULL
        );

        if (!ok) {
            DWORD err = GetLastError();
            if (err == ERROR_OPERATION_ABORTED || !g_Running) {
                break;
            }
            printf("[-] Stream IOCTL failed (Error %lu)\n", err);
            Sleep(100);
            continue;
        }

        if (bytesReturned < sizeof(WFPSENTINEL_EVENT)) {
            continue;
        }

        // Format time
        FILETIME ft;
        ft.dwLowDateTime = (DWORD)(ev.Timestamp & 0xFFFFFFFF);
        ft.dwHighDateTime = (DWORD)(ev.Timestamp >> 32);
        SYSTEMTIME st;
        FileTimeToSystemTime(&ft, &st);

        char timeBuf[32];
        snprintf(timeBuf, sizeof(timeBuf), "%02u:%02u:%02u.%03u",
            st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

        char localStr[64];
        char remoteStr[64];

        if (ev.IpVersion == 4) {
            char ip1[32], ip2[32];
            FormatIpv4(ev.Addr.Ipv4.LocalIp, ip1, sizeof(ip1));
            FormatIpv4(ev.Addr.Ipv4.RemoteIp, ip2, sizeof(ip2));
            snprintf(localStr, sizeof(localStr), "%s:%u", ip1, ev.LocalPort);
            snprintf(remoteStr, sizeof(remoteStr), "%s:%u", ip2, ev.RemotePort);
        } else {
            char ip1[64], ip2[64];
            FormatIpv6(ev.Addr.Ipv6.LocalIp, ip1, sizeof(ip1));
            FormatIpv6(ev.Addr.Ipv6.RemoteIp, ip2, sizeof(ip2));
            snprintf(localStr, sizeof(localStr), "[%s]:%u", ip1, ev.LocalPort);
            snprintf(remoteStr, sizeof(remoteStr), "[%s]:%u", ip2, ev.RemotePort);
        }

        char pathBuf[260];
        WideCharToMultiByte(CP_UTF8, 0, ev.ProcessPath, -1, pathBuf, sizeof(pathBuf), NULL, NULL);

        const char* actionStr = (ev.Action == 1) ? "BLOCKED" : "PERMIT";
        const char* dirStr = DirectionName(ev.Direction);
        const char* protoStr = ProtocolName(ev.Protocol);
        const char* typeStr = EventTypeName(ev.EventType);

        printf("%-20s %-16s %-8s %-6s %-32s -> %-32s %-8s %-6llu %s\n",
            timeBuf, typeStr, actionStr, dirStr, localStr, remoteStr, protoStr, ev.ProcessId, pathBuf);
    }

    printf("\n[*] Telemetry stream closed cleanly.\n");
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        PrintUsage(argv[0]);
        return 1;
    }

    // Initialize Winsock
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("[-] WSAStartup failed\n");
        return 1;
    }

    HANDLE hDevice = OpenDriverHandle();
    if (hDevice == INVALID_HANDLE_VALUE) {
        WSACleanup();
        return 1;
    }
    g_hDevice = hDevice;

    if (_stricmp(argv[1], "block") == 0 || _stricmp(argv[1], "allow") == 0) {
        UINT8 action = (_stricmp(argv[1], "block") == 0) ? WFPSENTINEL_ACTION_BLOCK : WFPSENTINEL_ACTION_ALLOW;
        WFPSENTINEL_RULE rule;
        if (!ParseRuleFromArgs(argc, argv, action, &rule)) {
            CloseHandle(hDevice);
            WSACleanup();
            return 1;
        }

        UINT32 assignedId = 0;
        DWORD bytesReturned = 0;
        BOOL ok = DeviceIoControl(
            hDevice,
            IOCTL_WFPSENTINEL_ADD_RULE,
            &rule,
            sizeof(rule),
            &assignedId,
            sizeof(assignedId),
            &bytesReturned,
            NULL
        );

        if (ok) {
            char ipBuf[64] = { 0 };
            if (rule.IpVersion == 4) {
                FormatIpv4(rule.RemoteIpV4, ipBuf, sizeof(ipBuf));
                if (rule.RemoteIpV4Mask != 0xFFFFFFFF) {
                    char maskBuf[16];
                    snprintf(maskBuf, sizeof(maskBuf), "/mask:0x%08X", rule.RemoteIpV4Mask);
                    strncat(ipBuf, maskBuf, sizeof(ipBuf) - strlen(ipBuf) - 1);
                }
            } else if (rule.IpVersion == 6) {
                FormatIpv6(rule.RemoteIpV6, ipBuf, sizeof(ipBuf));
                char prefixBuf[16];
                snprintf(prefixBuf, sizeof(prefixBuf), "/%u", rule.RemoteIpV6PrefixLen);
                strncat(ipBuf, prefixBuf, sizeof(ipBuf) - strlen(ipBuf) - 1);
            }

            char pathBuf[260] = { 0 };
            WideCharToMultiByte(CP_UTF8, 0, rule.ProcessPath, -1, pathBuf, sizeof(pathBuf), NULL, NULL);

            printf("[+] Successfully added %s rule in kernel (Rule ID: %u):\n",
                (action == WFPSENTINEL_ACTION_BLOCK) ? "BLOCK" : "ALLOW", assignedId);
            printf("    Direction:   %s\n", DirectionName(rule.Direction));
            printf("    IP Version:  IPv%u\n", rule.IpVersion);
            printf("    Remote IP:   %s\n", ipBuf);
            printf("    Remote Port: %u (%s)\n", rule.RemotePort, rule.RemotePort ? "exact" : "any");
            printf("    Protocol:    %u (%s)\n", rule.Protocol, ProtocolName(rule.Protocol));
            printf("    PID:         %llu (%s)\n", rule.ProcessId, rule.ProcessId ? "exact" : "any");
            if (rule.ProcessPathLen > 0) {
                printf("    App Path:    %s\n", pathBuf);
            }
        } else {
            printf("[-] DeviceIoControl IOCTL_WFPSENTINEL_ADD_RULE failed: %lu\n", GetLastError());
        }

    } else if (_stricmp(argv[1], "block-app") == 0 || _stricmp(argv[1], "allow-app") == 0) {
        if (argc < 3) {
            printf("[-] Missing image path pattern (e.g. curl.exe)\n");
            CloseHandle(hDevice);
            WSACleanup();
            return 1;
        }

        UINT8 action = (_stricmp(argv[1], "block-app") == 0) ? WFPSENTINEL_ACTION_BLOCK : WFPSENTINEL_ACTION_ALLOW;
        WFPSENTINEL_RULE rule;
        ZeroMemory(&rule, sizeof(rule));
        rule.Action = action;
        rule.Direction = WFPSENTINEL_DIR_ANY;

        int len = MultiByteToWideChar(CP_UTF8, 0, argv[2], -1, rule.ProcessPath, WFPSENTINEL_MAX_PATH - 1);
        if (len > 0) {
            rule.ProcessPathLen = (UINT16)(len - 1);
        }

        UINT32 assignedId = 0;
        DWORD bytesReturned = 0;
        BOOL ok = DeviceIoControl(
            hDevice,
            IOCTL_WFPSENTINEL_ADD_RULE,
            &rule,
            sizeof(rule),
            &assignedId,
            sizeof(assignedId),
            &bytesReturned,
            NULL
        );

        if (ok) {
            printf("[+] Successfully added %s rule for process path: '%s' (Rule ID: %u)\n",
                (action == WFPSENTINEL_ACTION_BLOCK) ? "BLOCK" : "ALLOW", argv[2], assignedId);
        } else {
            printf("[-] Failed to add rule: %lu\n", GetLastError());
        }

    } else if (_stricmp(argv[1], "rules") == 0) {
        WFPSENTINEL_RULES_LIST list;
        ZeroMemory(&list, sizeof(list));
        DWORD bytesReturned = 0;

        BOOL ok = DeviceIoControl(
            hDevice,
            IOCTL_WFPSENTINEL_GET_RULES,
            NULL,
            0,
            &list,
            sizeof(list),
            &bytesReturned,
            NULL
        );

        if (ok) {
            printf("=== ACTIVE KERNEL FILTERING RULES (%u rules) ===\n", list.RuleCount);
            printf("%-4s %-7s %-8s %-5s %-32s %-6s %-6s %-6s %s\n",
                "ID", "ACTION", "DIR", "VER", "REMOTE TARGET", "PORT", "PROTO", "PID", "APP PATH");
            printf("----------------------------------------------------------------------------------------------------\n");

            for (UINT32 i = 0; i < list.RuleCount; i++) {
                PWFPSENTINEL_RULE r = &list.Rules[i];
                char ipBuf[64] = "*";
                if (r->IpVersion == 4 && r->RemoteIpV4 != 0) {
                    char ip4[32];
                    FormatIpv4(r->RemoteIpV4, ip4, sizeof(ip4));
                    if (r->RemoteIpV4Mask == 0xFFFFFFFF) {
                        snprintf(ipBuf, sizeof(ipBuf), "%s", ip4);
                    } else {
                        snprintf(ipBuf, sizeof(ipBuf), "%s/0x%08X", ip4, r->RemoteIpV4Mask);
                    }
                } else if (r->IpVersion == 6 && r->RemoteIpV6PrefixLen > 0) {
                    char ip6[64];
                    FormatIpv6(r->RemoteIpV6, ip6, sizeof(ip6));
                    snprintf(ipBuf, sizeof(ipBuf), "%s/%u", ip6, r->RemoteIpV6PrefixLen);
                }

                char portBuf[16] = "*";
                if (r->RemotePort != 0) snprintf(portBuf, sizeof(portBuf), "%u", r->RemotePort);

                char pidBuf[16] = "*";
                if (r->ProcessId != 0) snprintf(pidBuf, sizeof(pidBuf), "%llu", r->ProcessId);

                char pathBuf[260] = "*";
                if (r->ProcessPathLen > 0) {
                    WideCharToMultiByte(CP_UTF8, 0, r->ProcessPath, -1, pathBuf, sizeof(pathBuf), NULL, NULL);
                }

                char verBuf[8] = "ANY";
                if (r->IpVersion == 4) strcpy(verBuf, "IPv4");
                else if (r->IpVersion == 6) strcpy(verBuf, "IPv6");

                printf("%-4u %-7s %-8s %-5s %-32s %-6s %-6s %-6s %s\n",
                    r->RuleId,
                    (r->Action == WFPSENTINEL_ACTION_BLOCK) ? "BLOCK" : "ALLOW",
                    DirectionName(r->Direction),
                    verBuf,
                    ipBuf,
                    portBuf,
                    ProtocolName(r->Protocol),
                    pidBuf,
                    pathBuf);
            }
        } else {
            printf("[-] DeviceIoControl IOCTL_WFPSENTINEL_GET_RULES failed: %lu\n", GetLastError());
        }

    } else if (_stricmp(argv[1], "delete") == 0) {
        if (argc < 3) {
            printf("[-] Missing Rule ID to delete\n");
            CloseHandle(hDevice);
            WSACleanup();
            return 1;
        }

        UINT32 targetId = (UINT32)atoi(argv[2]);
        DWORD bytesReturned = 0;

        BOOL ok = DeviceIoControl(
            hDevice,
            IOCTL_WFPSENTINEL_DELETE_RULE,
            &targetId,
            sizeof(targetId),
            NULL,
            0,
            &bytesReturned,
            NULL
        );

        if (ok) {
            printf("[+] Successfully deleted kernel rule ID %u\n", targetId);
        } else {
            printf("[-] Failed to delete rule ID %u (Error %lu)\n", targetId, GetLastError());
        }

    } else if (_stricmp(argv[1], "clear") == 0) {
        DWORD bytesReturned = 0;
        BOOL ok = DeviceIoControl(
            hDevice,
            IOCTL_WFPSENTINEL_CLEAR_RULES,
            NULL,
            0,
            NULL,
            0,
            &bytesReturned,
            NULL
        );

        if (ok) {
            printf("[+] Successfully cleared all kernel rules\n");
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
            printf("===============================================================================\n");
            printf("                     WFPSENTINEL KERNEL STATISTICS\n");
            printf("===============================================================================\n");
            printf("  Policy Engine:\n");
            printf("    Active Dynamic Rules:             %u\n", stats.ActiveRuleCount);
            printf("  Classification & Enforcement:\n");
            printf("    Total Connections Classified:     %llu\n", stats.TotalClassified);
            printf("    Total Permitted Connections:      %llu\n", stats.TotalPermitted);
            printf("    Total Blocked Connections:        %llu\n", stats.TotalBlocked);
            printf("  Dual-Stack Parity:\n");
            printf("    IPv4 Connections:                 %llu\n", stats.TotalV4Connections);
            printf("    IPv6 Connections:                 %llu\n", stats.TotalV6Connections);
            printf("  Traffic Directions:\n");
            printf("    Outbound Connections:             %llu\n", stats.TotalOutboundConnections);
            printf("    Inbound Connections:              %llu\n", stats.TotalInboundConnections);
            printf("  Flow Context Engine:\n");
            printf("    Total Flows Established:          %llu\n", stats.TotalFlowsEstablished);
            printf("    Currently Active Flows:           %llu\n", stats.TotalFlowsActive);
            printf("  Real-Time Telemetry Streaming:\n");
            printf("    Total Events Streamed:            %llu\n", stats.TotalEventsStreamed);
            printf("    Pending Streaming IRPs:           %u\n", stats.PendingIrpCount);
            printf("===============================================================================\n");
        } else {
            printf("[-] DeviceIoControl failed: %lu\n", GetLastError());
        }

    } else if (_stricmp(argv[1], "monitor") == 0 || _stricmp(argv[1], "stream") == 0) {
        RunStreamMonitor(hDevice);

    } else {
        PrintUsage(argv[0]);
    }

    CloseHandle(hDevice);
    WSACleanup();
    return 0;
}
