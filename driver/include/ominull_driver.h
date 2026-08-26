#ifndef OMINULL_DRIVER_H
#define OMINULL_DRIVER_H

#ifndef POOL_NX_OPTIN
#define POOL_NX_OPTIN 1
#endif

#include "wfp_kernel.h"
#include "ominull_ioctl.h"

#define OMINULL_TAG 0x4C4C554E // 'NULL' pool tag

#define DPFLTR_IHVDRIVER_ID 77
#define DPFLTR_INFO_LEVEL   3
#define DPFLTR_ERROR_LEVEL  0

#define RPC_C_AUTHN_DEFAULT 0xFFFFFFFF

#define OMINULL_EVENT_QUEUE_SIZE 512

enum {
    LAYER_IDX_CONNECT_V4 = 0,
    LAYER_IDX_CONNECT_V6,
    LAYER_IDX_RECV_ACCEPT_V4,
    LAYER_IDX_RECV_ACCEPT_V6,
    LAYER_IDX_FLOW_EST_V4,
    LAYER_IDX_FLOW_EST_V6,
    OMINULL_LAYER_COUNT
};

// Flow context tracked at FWPM_LAYER_ALE_FLOW_ESTABLISHED
typedef struct _OMINULL_FLOW_CONTEXT {
    UINT64        FlowId;
    UINT64        ProcessId;
    UINT8         IpVersion;       // 4 or 6
    UINT8         Protocol;
    UINT8         Direction;       // 1 = Outbound, 2 = Inbound
    UINT8         Reserved;
    UINT16        LocalPort;
    UINT16        RemotePort;
    union {
        struct {
            UINT32 LocalIp;
            UINT32 RemoteIp;
        } Ipv4;
        struct {
            UINT8  LocalIp[16];
            UINT8  RemoteIp[16];
        } Ipv6;
    } Addr;
    LARGE_INTEGER CreationTime;
    WCHAR         ProcessPath[OMINULL_MAX_PATH];
} OMINULL_FLOW_CONTEXT, *POMINULL_FLOW_CONTEXT;

// Global driver state tracking
typedef struct _OMINULL_GLOBAL_DATA {
    PDEVICE_OBJECT         DeviceObject;
    HANDLE                 EngineHandle;
    BOOLEAN                EngineOpened;
    BOOLEAN                SubLayerAdded;

    // Multi-layer Callout & Filter Tracking
    UINT32                 CalloutIds[OMINULL_LAYER_COUNT];
    UINT64                 FilterIds[OMINULL_LAYER_COUNT];
    BOOLEAN                CalloutRegistered[OMINULL_LAYER_COUNT];
    BOOLEAN                CalloutAdded[OMINULL_LAYER_COUNT];
    BOOLEAN                FilterAdded[OMINULL_LAYER_COUNT];

    // Dynamic Policy & Host Isolation Engine
    KSPIN_LOCK             PolicyLock;
    OMINULL_RULE           Rules[OMINULL_MAX_RULES];
    UINT32                 RuleCount;
    UINT32                 NextRuleId;
    BOOLEAN                IsolationActive;
    OMINULL_ISOLATION_CONFIG IsolationConfig;

    // Real-Time Telemetry Streaming (Inverted Call Model)
    KSPIN_LOCK             TelemetryLock;
    LIST_ENTRY             PendingIrpList;
    OMINULL_EVENT          EventQueue[OMINULL_EVENT_QUEUE_SIZE];
    UINT32                 EventHead;
    UINT32                 EventTail;
    UINT32                 EventCount;

    // Runtime Statistics
    OMINULL_STATS          Stats;
} OMINULL_GLOBAL_DATA, *POMINULL_GLOBAL_DATA;

extern OMINULL_GLOBAL_DATA g_GlobalData;

// Driver lifecycle routines
DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnload;

// IRP Dispatch Handlers
DRIVER_DISPATCH OminullDispatchCreate;
DRIVER_DISPATCH OminullDispatchClose;
DRIVER_DISPATCH OminullDispatchDeviceControl;

// Inverted Call & Telemetry Helpers
VOID OminullEmitEvent(_In_ const OMINULL_EVENT* Event);
VOID OminullFlushPendingIrps(VOID);
VOID NTAPI OminullIrpCancelRoutine(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);

// Policy & Isolation Evaluation
UINT8 OminullEvaluatePolicy(
    _In_ UINT8                      Direction,
    _In_ UINT8                      IpVersion,
    _In_ UINT8                      Protocol,
    _In_ UINT16                     LocalPort,
    _In_ UINT16                     RemotePort,
    _In_ UINT32                     RemoteIpV4,
    _In_reads_opt_(16) const UINT8* RemoteIpV6,
    _In_ UINT64                     ProcessId,
    _In_ const WCHAR*               ProcessPath
);

// WFP Callout Callbacks
void NTAPI OminullClassifyConnectV4(
    _In_ const FWPS_INCOMING_VALUES0* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER0* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* classifyOut
);

void NTAPI OminullClassifyConnectV6(
    _In_ const FWPS_INCOMING_VALUES0* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER0* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* classifyOut
);

void NTAPI OminullClassifyRecvAcceptV4(
    _In_ const FWPS_INCOMING_VALUES0* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER0* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* classifyOut
);

void NTAPI OminullClassifyRecvAcceptV6(
    _In_ const FWPS_INCOMING_VALUES0* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER0* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* classifyOut
);

void NTAPI OminullClassifyFlowEstV4(
    _In_ const FWPS_INCOMING_VALUES0* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER0* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* classifyOut
);

void NTAPI OminullClassifyFlowEstV6(
    _In_ const FWPS_INCOMING_VALUES0* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER0* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* classifyOut
);

NTSTATUS NTAPI OminullNotify(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    _In_ const GUID* filterKey,
    _Inout_ FWPS_FILTER0* filter
);

void NTAPI OminullFlowDelete(
    _In_ UINT16 layerId,
    _In_ UINT32 calloutId,
    _In_ UINT64 flowContext
);

// Registration helpers
NTSTATUS OminullRegisterCallouts(PDEVICE_OBJECT DeviceObject);
VOID OminullUnregisterCallouts(VOID);

// Forward aliases for legacy compatibility
typedef OMINULL_GLOBAL_DATA OMINULL_GLOBAL_DATA, *POMINULL_GLOBAL_DATA;
typedef OMINULL_FLOW_CONTEXT OMINULL_FLOW_CONTEXT, *POMINULL_FLOW_CONTEXT;

#endif // OMINULL_DRIVER_H
