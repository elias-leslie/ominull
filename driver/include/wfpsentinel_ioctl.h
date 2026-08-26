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

// Legacy IOCTL Definitions (Milestone 2 backwards compatibility)
#define IOCTL_WFPSENTINEL_ADD_BLOCK_RULE    CTL_CODE(WFPSENTINEL_DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WFPSENTINEL_CLEAR_BLOCK_RULES CTL_CODE(WFPSENTINEL_DEVICE_TYPE, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WFPSENTINEL_GET_STATS         CTL_CODE(WFPSENTINEL_DEVICE_TYPE, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Advanced Dynamic Policy & Streaming IOCTL Definitions
#define IOCTL_WFPSENTINEL_ADD_RULE          CTL_CODE(WFPSENTINEL_DEVICE_TYPE, 0x810, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WFPSENTINEL_DELETE_RULE       CTL_CODE(WFPSENTINEL_DEVICE_TYPE, 0x811, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WFPSENTINEL_CLEAR_RULES       CTL_CODE(WFPSENTINEL_DEVICE_TYPE, 0x812, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WFPSENTINEL_GET_RULES         CTL_CODE(WFPSENTINEL_DEVICE_TYPE, 0x813, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WFPSENTINEL_STREAM_EVENT      CTL_CODE(WFPSENTINEL_DEVICE_TYPE, 0x820, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define WFPSENTINEL_MAX_RULES 128
#define WFPSENTINEL_MAX_PATH  260

#pragma pack(push, 1)

// Legacy IPv4 Block Rule Definition
typedef struct _WFPSENTINEL_BLOCK_RULE {
    UINT32 RemoteIpV4;       // IPv4 in host byte order
    UINT32 RemoteIpMask;     // Mask (0xFFFFFFFF = exact host, 0 = any)
    UINT16 RemotePort;       // Host byte order (0 = any)
    UINT8  Protocol;         // IPPROTO_TCP (6), IPPROTO_UDP (17), or 0 for any
    UINT8  Reserved;
    UINT64 ProcessId;        // PID to block (0 = any process)
} WFPSENTINEL_BLOCK_RULE, *PWFPSENTINEL_BLOCK_RULE;

// Rule Actions
#define WFPSENTINEL_ACTION_BLOCK  1
#define WFPSENTINEL_ACTION_ALLOW  2

// Rule Directions
#define WFPSENTINEL_DIR_ANY       0
#define WFPSENTINEL_DIR_OUTBOUND  1
#define WFPSENTINEL_DIR_INBOUND   2

// Advanced Dynamic Filter Rule (Dual-Stack IPv4 / IPv6, CIDR, Port, Protocol, PID, Image Path)
typedef struct _WFPSENTINEL_RULE {
    UINT32 RuleId;                   // Unique rule ID (assigned by driver on add)
    UINT8  Action;                   // WFPSENTINEL_ACTION_BLOCK (1) or WFPSENTINEL_ACTION_ALLOW (2)
    UINT8  Direction;                // WFPSENTINEL_DIR_ANY (0), OUTBOUND (1), INBOUND (2)
    UINT8  IpVersion;                // 0 = Any, 4 = IPv4, 6 = IPv6
    UINT8  Protocol;                 // IPPROTO_TCP (6), IPPROTO_UDP (17), or 0 for Any
    UINT16 LocalPort;                // 0 = Any
    UINT16 RemotePort;               // 0 = Any
    UINT64 ProcessId;                // 0 = Any PID

    // IPv4 Addressing (Host byte order)
    UINT32 RemoteIpV4;               // e.g. 0x0A000039 (10.0.0.57)
    UINT32 RemoteIpV4Mask;           // e.g. 0xFFFFFFFF for /32, 0xFFFFFF00 for /24

    // IPv6 Addressing (16-byte network order)
    UINT8  RemoteIpV6[16];           // 16-byte IPv6 address
    UINT8  RemoteIpV6PrefixLen;      // 0 to 128 (0 = any, 128 = exact host)

    // Process Image Path Filtering
    WCHAR  ProcessPath[WFPSENTINEL_MAX_PATH]; // Case-insensitive substring/path match
    UINT16 ProcessPathLen;           // Character length of ProcessPath (0 if no path filter)
} WFPSENTINEL_RULE, *PWFPSENTINEL_RULE;

// Request/Response for GET_RULES
typedef struct _WFPSENTINEL_RULES_LIST {
    UINT32           RuleCount;
    WFPSENTINEL_RULE Rules[WFPSENTINEL_MAX_RULES];
} WFPSENTINEL_RULES_LIST, *PWFPSENTINEL_RULES_LIST;

// Event Types for Real-Time Streaming Telemetry
#define WFPSENTINEL_EVENT_CONNECT_V4          1
#define WFPSENTINEL_EVENT_CONNECT_V6          2
#define WFPSENTINEL_EVENT_RECV_ACCEPT_V4      3
#define WFPSENTINEL_EVENT_RECV_ACCEPT_V6      4
#define WFPSENTINEL_EVENT_FLOW_ESTABLISHED_V4 5
#define WFPSENTINEL_EVENT_FLOW_ESTABLISHED_V6 6
#define WFPSENTINEL_EVENT_FLOW_CLOSED         7
#define WFPSENTINEL_EVENT_BLOCKED             8

// Real-Time Telemetry Event
typedef struct _WFPSENTINEL_EVENT {
    UINT64 Timestamp;                // System timestamp (100-ns intervals since Jan 1 1601)
    UINT32 EventType;                // WFPSENTINEL_EVENT_*
    UINT32 Action;                   // 0 = Permit/Continue, 1 = Blocked
    UINT64 ProcessId;                // PID
    UINT8  IpVersion;                // 4 or 6
    UINT8  Protocol;                 // IPPROTO_TCP (6), IPPROTO_UDP (17), etc.
    UINT8  Direction;                // 1 = Outbound, 2 = Inbound
    UINT8  Reserved;
    UINT16 LocalPort;                // Host byte order
    UINT16 RemotePort;               // Host byte order
    union {
        struct {
            UINT32 LocalIp;          // Host byte order
            UINT32 RemoteIp;         // Host byte order
        } Ipv4;
        struct {
            UINT8  LocalIp[16];
            UINT8  RemoteIp[16];
        } Ipv6;
    } Addr;
    UINT64 FlowId;                   // WFP flow handle / ID
    WCHAR  ProcessPath[WFPSENTINEL_MAX_PATH];
} WFPSENTINEL_EVENT, *PWFPSENTINEL_EVENT;

// Runtime Statistics
typedef struct _WFPSENTINEL_STATS {
    UINT64 TotalClassified;
    UINT64 TotalPermitted;
    UINT64 TotalBlocked;
    UINT64 TotalV4Connections;
    UINT64 TotalV6Connections;
    UINT64 TotalInboundConnections;
    UINT64 TotalOutboundConnections;
    UINT64 TotalFlowsActive;
    UINT64 TotalFlowsEstablished;
    UINT64 TotalEventsStreamed;
    UINT32 ActiveRuleCount;
    UINT32 PendingIrpCount;
} WFPSENTINEL_STATS, *PWFPSENTINEL_STATS;

#pragma pack(pop)

#endif // WFPSENTINEL_IOCTL_H
