#ifndef WFP_SENTINEL_DRIVER_H
#define WFP_SENTINEL_DRIVER_H

#include "wfp_kernel.h"

#define WFPSENTINEL_TAG 'STNW' // 'WNTS' pool tag

#define DPFLTR_IHVDRIVER_ID 77
#define DPFLTR_INFO_LEVEL   3
#define DPFLTR_ERROR_LEVEL  0

#define RPC_C_AUTHN_DEFAULT 0xFFFFFFFF

// Global driver state tracking
typedef struct _WFPSENTINEL_GLOBAL_DATA {
    PDEVICE_OBJECT DeviceObject;
    HANDLE         EngineHandle;
    UINT32         CalloutId;
    UINT64         FilterId;
    BOOLEAN        EngineOpened;
    BOOLEAN        SubLayerAdded;
    BOOLEAN        CalloutRegistered;
    BOOLEAN        CalloutAdded;
    BOOLEAN        FilterAdded;
} WFPSENTINEL_GLOBAL_DATA, *PWFPSENTINEL_GLOBAL_DATA;

extern WFPSENTINEL_GLOBAL_DATA g_GlobalData;

// Driver lifecycle routines
DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnload;

// WFP Callout Callbacks
void NTAPI WfpSentinelClassify(
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
