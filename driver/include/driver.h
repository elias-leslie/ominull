#ifndef WFP_SENTINEL_DRIVER_H
#define WFP_SENTINEL_DRIVER_H

#include "wfp_kernel.h"
#include "wfpsentinel_ioctl.h"

#define WFPSENTINEL_TAG 0x53544E57 // 'WNTS' pool tag

#define DPFLTR_IHVDRIVER_ID 77
#define DPFLTR_INFO_LEVEL   3
#define DPFLTR_ERROR_LEVEL  0

#define RPC_C_AUTHN_DEFAULT 0xFFFFFFFF

#define WFPSENTINEL_EVENT_QUEUE_SIZE 512

enum {
    LAYER_IDX_CONNECT_V4 = 0,
    LAYER_IDX_CONNECT_V6,
    LAYER_IDX_RECV_ACCEPT_V4,
    LAYER_IDX_RECV_ACCEPT_V6,
    LAYER_IDX_FLOW_EST_V4,
    LAYER_IDX_FLOW_EST_V6,
    WFPSENTINEL_LAYER_COUNT
};

// Flow context tracked at FWPM_LAYER_ALE_FLOW_ESTABLISHED
typedef struct _WFPSENTINEL_FLOW_CONTEXT {
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
    WCHAR         ProcessPath[WFPSENTINEL_MAX_PATH];
} WFPSENTINEL_FLOW_CONTEXT, *PWFPSENTINEL_FLOW_CONTEXT;

// Global driver state tracking
typedef struct _WFPSENTINEL_GLOBAL_DATA {
    PDEVICE_OBJECT         DeviceObject;
    HANDLE                 EngineHandle;
    BOOLEAN                EngineOpened;
    BOOLEAN                SubLayerAdded;

    // Multi-layer Callout & Filter Tracking
    UINT32                 CalloutIds[WFPSENTINEL_LAYER_COUNT];
    UINT64                 FilterIds[WFPSENTINEL_LAYER_COUNT];
    BOOLEAN                CalloutRegistered[WFPSENTINEL_LAYER_COUNT];
    BOOLEAN                CalloutAdded[WFPSENTINEL_LAYER_COUNT];
    BOOLEAN                FilterAdded[WFPSENTINEL_LAYER_COUNT];

    // Dynamic Policy Engine
    KSPIN_LOCK             PolicyLock;
    WFPSENTINEL_RULE       Rules[WFPSENTINEL_MAX_RULES];
    UINT32                 RuleCount;
    UINT32                 NextRuleId;

    // Real-Time Telemetry Streaming (Inverted Call Model)
    KSPIN_LOCK             TelemetryLock;
    LIST_ENTRY             PendingIrpList;
    WFPSENTINEL_EVENT      EventQueue[WFPSENTINEL_EVENT_QUEUE_SIZE];
    UINT32                 EventHead;
    UINT32                 EventTail;
    UINT32                 EventCount;

    // Runtime Statistics
    WFPSENTINEL_STATS      Stats;
} WFPSENTINEL_GLOBAL_DATA, *PWFPSENTINEL_GLOBAL_DATA;

extern WFPSENTINEL_GLOBAL_DATA g_GlobalData;

// Driver lifecycle routines
DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnload;

// IRP Dispatch Handlers
DRIVER_DISPATCH WfpSentinelDispatchCreate;
DRIVER_DISPATCH WfpSentinelDispatchClose;
DRIVER_DISPATCH WfpSentinelDispatchDeviceControl;

// Inverted Call & Telemetry Helpers
VOID WfpSentinelEmitEvent(_In_ const WFPSENTINEL_EVENT* Event);
VOID WfpSentinelFlushPendingIrps(VOID);
VOID NTAPI WfpSentinelIrpCancelRoutine(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);

// WFP Callout Callbacks
void NTAPI WfpSentinelClassifyConnectV4(
    _In_ const FWPS_INCOMING_VALUES0* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER0* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* classifyOut
);

void NTAPI WfpSentinelClassifyConnectV6(
    _In_ const FWPS_INCOMING_VALUES0* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER0* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* classifyOut
);

void NTAPI WfpSentinelClassifyRecvAcceptV4(
    _In_ const FWPS_INCOMING_VALUES0* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER0* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* classifyOut
);

void NTAPI WfpSentinelClassifyRecvAcceptV6(
    _In_ const FWPS_INCOMING_VALUES0* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER0* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* classifyOut
);

void NTAPI WfpSentinelClassifyFlowEstV4(
    _In_ const FWPS_INCOMING_VALUES0* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER0* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* classifyOut
);

void NTAPI WfpSentinelClassifyFlowEstV6(
    _In_ const FWPS_INCOMING_VALUES0* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER0* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* classifyOut
);

NTSTATUS NTAPI WfpSentinelNotify(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    _In_ const GUID* filterKey,
    _Inout_ FWPS_FILTER0* filter
);

void NTAPI WfpSentinelFlowDelete(
    _In_ UINT16 layerId,
    _In_ UINT32 calloutId,
    _In_ UINT64 flowContext
);

// Registration helpers
NTSTATUS WfpSentinelRegisterCallouts(PDEVICE_OBJECT DeviceObject);
VOID WfpSentinelUnregisterCallouts(VOID);

#endif // WFP_SENTINEL_DRIVER_H
