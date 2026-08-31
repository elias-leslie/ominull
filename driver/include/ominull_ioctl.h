#ifndef OMINULL_IOCTL_H
#define OMINULL_IOCTL_H

#define OMINULL_DEVICE_TYPE     FILE_DEVICE_NETWORK
#define OMINULL_DEVICE_NAME     L"\\Device\\Ominull"
#define OMINULL_SYMBOLIC_NAME   L"\\DosDevices\\Ominull"
#define OMINULL_USERMODE_PATH   "\\\\.\\Ominull"

#ifndef CTL_CODE
#define CTL_CODE( DeviceType, Function, Method, Access ) ( \
    ((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method) \
)
#define METHOD_BUFFERED 0
#define FILE_ANY_ACCESS 0
#define FILE_DEVICE_NETWORK 0x00000012
#endif

// Legacy IOCTL Definitions (Backwards compatibility)
#define IOCTL_OMINULL_ADD_BLOCK_RULE      CTL_CODE(OMINULL_DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_OMINULL_CLEAR_BLOCK_RULES   CTL_CODE(OMINULL_DEVICE_TYPE, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_OMINULL_GET_STATS           CTL_CODE(OMINULL_DEVICE_TYPE, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Advanced Dynamic Policy, Isolation & Streaming IOCTL Definitions
#define IOCTL_OMINULL_ADD_RULE            CTL_CODE(OMINULL_DEVICE_TYPE, 0x810, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_OMINULL_DELETE_RULE         CTL_CODE(OMINULL_DEVICE_TYPE, 0x811, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_OMINULL_CLEAR_RULES         CTL_CODE(OMINULL_DEVICE_TYPE, 0x812, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_OMINULL_GET_RULES           CTL_CODE(OMINULL_DEVICE_TYPE, 0x813, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_OMINULL_STREAM_EVENT        CTL_CODE(OMINULL_DEVICE_TYPE, 0x820, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_OMINULL_SET_ISOLATION_MODE  CTL_CODE(OMINULL_DEVICE_TYPE, 0x830, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_OMINULL_CLEAR_ISOLATION_MODE CTL_CODE(OMINULL_DEVICE_TYPE, 0x831, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define OMINULL_MAX_RULES 128
#define OMINULL_MAX_PATH  260

#pragma pack(push, 1)

// Legacy IPv4 Block Rule Definition
typedef struct _OMINULL_BLOCK_RULE {
    UINT32 RemoteIpV4;       // IPv4 in host byte order
    UINT32 RemoteIpMask;     // Mask (0xFFFFFFFF = exact host, 0 = any)
    UINT16 RemotePort;       // Host byte order (0 = any)
    UINT8  Protocol;         // IPPROTO_TCP (6), IPPROTO_UDP (17), or 0 for any
    UINT8  Reserved;
    UINT64 ProcessId;        // PID to block (0 = any process)
} OMINULL_BLOCK_RULE, *POMINULL_BLOCK_RULE;

// Rule Actions
#define OMINULL_ACTION_BLOCK  1
#define OMINULL_ACTION_ALLOW  2

// Rule Directions
#define OMINULL_DIR_ANY       0
#define OMINULL_DIR_OUTBOUND  1
#define OMINULL_DIR_INBOUND   2

// Advanced Dynamic Filter Rule (Dual-Stack IPv4 / IPv6, CIDR, Port, Protocol, PID, Image Path)
typedef struct _OMINULL_RULE {
    UINT32 RuleId;                   // Unique rule ID (assigned by driver on add)
    UINT8  Action;                   // OMINULL_ACTION_BLOCK (1) or OMINULL_ACTION_ALLOW (2)
    UINT8  Direction;                // OMINULL_DIR_ANY (0), OUTBOUND (1), INBOUND (2)
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
    WCHAR  ProcessPath[OMINULL_MAX_PATH]; // Case-insensitive substring/path match
    UINT16 ProcessPathLen;           // Character length of ProcessPath (0 if no path filter)
} OMINULL_RULE, *POMINULL_RULE;

// Request/Response for GET_RULES
typedef struct _OMINULL_RULES_LIST {
    UINT32       RuleCount;
    OMINULL_RULE Rules[OMINULL_MAX_RULES];
} OMINULL_RULES_LIST, *POMINULL_RULES_LIST;

// Event Types for Real-Time Streaming Telemetry
#define OMINULL_EVENT_CONNECT_V4          1
#define OMINULL_EVENT_CONNECT_V6          2
#define OMINULL_EVENT_RECV_ACCEPT_V4      3
#define OMINULL_EVENT_RECV_ACCEPT_V6      4
#define OMINULL_EVENT_FLOW_ESTABLISHED_V4 5
#define OMINULL_EVENT_FLOW_ESTABLISHED_V6 6
#define OMINULL_EVENT_FLOW_CLOSED         7
#define OMINULL_EVENT_BLOCKED             8

// Real-Time Telemetry Event
typedef struct _OMINULL_EVENT {
    UINT64 Timestamp;                // System timestamp (100-ns intervals since Jan 1 1601)
    UINT32 EventType;                // OMINULL_EVENT_*
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
    WCHAR  ProcessPath[OMINULL_MAX_PATH];
    // Bytes attributable to this flow *in this reporting interval*, not for the
    // life of the connection. Zero means "not measured", which is a different
    // claim from "no traffic" and is reported as such by the hub. Appended
    // rather than inserted: Driver_StreamEvents rejects a payload whose size
    // does not match this struct, so a driver built against the older layout is
    // ignored rather than misread.
    UINT64 BytesIn;
    UINT64 BytesOut;
} OMINULL_EVENT, *POMINULL_EVENT;

// Runtime Statistics
typedef struct _OMINULL_STATS {
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
    UINT32 IsolationActive;
} OMINULL_STATS, *POMINULL_STATS;

// Host Isolation Configuration
typedef struct _OMINULL_ISOLATION_CONFIG {
    UINT32 ManagementServerIpV4;     // Management Hub IP (allowed during isolation)
    UINT16 ManagementServerPort;     // Management Hub Port (allowed during isolation)
    UINT8  AllowDhcp;                // 1 = permit DHCP renewal (UDP 67/68)
    UINT8  AllowDns;                 // 1 = permit DNS to management resolver (UDP 53)
} OMINULL_ISOLATION_CONFIG, *POMINULL_ISOLATION_CONFIG;

#pragma pack(pop)

#endif // OMINULL_IOCTL_H
