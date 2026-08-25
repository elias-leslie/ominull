#ifndef WFPSENTINEL_IOCTL_H
#define WFPSENTINEL_IOCTL_H

#define WFPSENTINEL_DEVICE_TYPE     FILE_DEVICE_NETWORK
#define WFPSENTINEL_DEVICE_NAME     L"\\Device\\WfpSentinel"
#define WFPSENTINEL_SYMBOLIC_NAME   L"\\DosDevices\\WfpSentinel"
#define WFPSENTINEL_USERMODE_PATH   "\\\\.\\WfpSentinel"

#ifndef CTL_CODE
#define CTL_CODE( DeviceType, Function, Method, Access ) ( \
    ((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method) \
)
#define METHOD_BUFFERED 0
#define FILE_ANY_ACCESS 0
#define FILE_DEVICE_NETWORK 0x00000012
#endif

// IOCTL Definitions
#define IOCTL_WFPSENTINEL_ADD_BLOCK_RULE    CTL_CODE(WFPSENTINEL_DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WFPSENTINEL_CLEAR_BLOCK_RULES CTL_CODE(WFPSENTINEL_DEVICE_TYPE, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WFPSENTINEL_GET_STATS         CTL_CODE(WFPSENTINEL_DEVICE_TYPE, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define WFPSENTINEL_MAX_RULES 64

#pragma pack(push, 1)

// Block Rule Definition
typedef struct _WFPSENTINEL_BLOCK_RULE {
    UINT32 RemoteIpV4;       // IPv4 in network byte order (e.g. 10.0.0.57 = 0x0A000039)
    UINT32 RemoteIpMask;     // Mask (0xFFFFFFFF = exact host, 0 = any)
    UINT16 RemotePort;       // Host byte order (0 = any)
    UINT8  Protocol;         // IPPROTO_TCP (6), IPPROTO_UDP (17), or 0 for any
    UINT8  Reserved;
    UINT64 ProcessId;        // PID to block (0 = any process)
} WFPSENTINEL_BLOCK_RULE, *PWFPSENTINEL_BLOCK_RULE;

// Runtime Statistics
typedef struct _WFPSENTINEL_STATS {
    UINT64 TotalClassified;
    UINT64 TotalPermitted;
    UINT64 TotalBlocked;
    UINT32 ActiveRuleCount;
} WFPSENTINEL_STATS, *PWFPSENTINEL_STATS;

#pragma pack(pop)

#endif // WFPSENTINEL_IOCTL_H
