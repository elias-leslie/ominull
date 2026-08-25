#include "driver.h"

// Global driver state
WFPSENTINEL_GLOBAL_DATA g_GlobalData = { 0 };

static UNICODE_STRING g_NtDeviceName;
static UNICODE_STRING g_Win32DeviceName;

// Classification callback invoked for every outbound IPv4 connection attempt
void NTAPI
WfpSentinelClassify(
    _In_ const FWPS_INCOMING_VALUES0*          inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_opt_ void*                          layerData,
    _In_opt_ const void*                       classifyContext,
    _In_ const FWPS_FILTER0*                   filter,
    _In_ UINT64                                flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0*                classifyOut
)
{
    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(flowContext);

    if (!inFixedValues || !classifyOut) {
        return;
    }

    // Extract 4-tuple and protocol from ALE_AUTH_CONNECT_V4 fixed values
    UINT32 localIp = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_ADDRESS].value.uint32;
    UINT16 localPort = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_PORT].value.uint16;
    UINT32 remoteIp = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS].value.uint32;
    UINT16 remotePort = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT].value.uint16;
    UINT8 protocol = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL].value.uint8;

    // Extract process ID from metadata if present
    UINT64 processId = 0;
    if (inMetaValues && (inMetaValues->currentFields & FWPS_METADATA_FIELD_PROCESS_ID)) {
        processId = inMetaValues->processId;
    }

    // Extract application path if present
    FWP_BYTE_BLOB* appBlob = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_ALE_APP_ID].value.byteBlob;

    // Format and emit telemetry log to kernel debugger
    if (appBlob && appBlob->data && appBlob->size >= sizeof(wchar_t)) {
        DbgPrint("[wfpsentinel] CLASSIFY: PID=%llu App=%ws Proto=%u Local=%u.%u.%u.%u:%u -> Remote=%u.%u.%u.%u:%u\n",
            processId,
            (wchar_t*)appBlob->data,
            protocol,
            (localIp >> 24) & 0xFF, (localIp >> 16) & 0xFF, (localIp >> 8) & 0xFF, localIp & 0xFF,
            localPort,
            (remoteIp >> 24) & 0xFF, (remoteIp >> 16) & 0xFF, (remoteIp >> 8) & 0xFF, remoteIp & 0xFF,
            remotePort
        );
    } else {
        DbgPrint("[wfpsentinel] CLASSIFY: PID=%llu Proto=%u Local=%u.%u.%u.%u:%u -> Remote=%u.%u.%u.%u:%u\n",
            processId,
            protocol,
            (localIp >> 24) & 0xFF, (localIp >> 16) & 0xFF, (localIp >> 8) & 0xFF, localIp & 0xFF,
            localPort,
            (remoteIp >> 24) & 0xFF, (remoteIp >> 16) & 0xFF, (remoteIp >> 8) & 0xFF, remoteIp & 0xFF,
            remotePort
        );
    }

    // Set decision: Continue processing (Milestone 1 inspection callout)
    classifyOut->actionType = FWP_ACTION_CONTINUE;

    // Clear write action right if filter specifies
    if (filter && (filter->flags & FWPS_FILTER_FLAG_CLEAR_ACTION_RIGHT)) {
        classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
    }
}

// Notification callback for filter lifecycle events
NTSTATUS NTAPI
WfpSentinelNotify(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    _In_ const GUID*               filterKey,
    _Inout_ FWPS_FILTER0*         filter
)
{
    UNREFERENCED_PARAMETER(filterKey);
    UNREFERENCED_PARAMETER(filter);

    switch (notifyType) {
    case FWPS_CALLOUT_NOTIFY_ADD_FILTER:
        DbgPrint("[wfpsentinel] NOTIFY: Filter registered on callout\n");
        break;
    case FWPS_CALLOUT_NOTIFY_DELETE_FILTER:
        DbgPrint("[wfpsentinel] NOTIFY: Filter removed from callout\n");
        break;
    default:
        break;
    }

    return STATUS_SUCCESS;
}

// Flow teardown callback
void NTAPI
WfpSentinelFlowDelete(
    _In_ UINT16 layerId,
    _In_ UINT32 calloutId,
    _In_ UINT64 flowContext
)
{
    UNREFERENCED_PARAMETER(layerId);
    UNREFERENCED_PARAMETER(calloutId);
    UNREFERENCED_PARAMETER(flowContext);

    DbgPrint("[wfpsentinel] FLOW_DELETE: Connection flow destroyed\n");
}

// Register WFP sublayer, runtime callout, engine callout, and filter within a single transaction
NTSTATUS
WfpSentinelRegisterCallouts(
    _In_ PDEVICE_OBJECT DeviceObject
)
{
    NTSTATUS status = STATUS_SUCCESS;
    FWPM_SESSION0 session = { 0 };
    FWPM_SUBLAYER0 subLayer = { 0 };
    FWPS_CALLOUT0 sCallout = { 0 };
    FWPM_CALLOUT0 mCallout = { 0 };
    FWPM_FILTER0 filter = { 0 };
    BOOLEAN inTransaction = FALSE;

    // Configure dynamic session (cleaned up automatically if process/driver dies)
    session.displayData.name = L"WfpSentinelSession";
    session.displayData.description = L"WfpSentinel Kernel Inspection Session";
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;

    // 1. Open WFP filter engine
    status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_DEFAULT, NULL, &session, &g_GlobalData.EngineHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[wfpsentinel] ERROR: FwpmEngineOpen0 failed: 0x%08X\n", (UINT32)status);
        return status;
    }
    g_GlobalData.EngineOpened = TRUE;

    // 2. Begin transaction for atomic registration
    status = FwpmTransactionBegin0(g_GlobalData.EngineHandle, 0);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[wfpsentinel] ERROR: FwpmTransactionBegin0 failed: 0x%08X\n", (UINT32)status);
        goto ErrorCleanup;
    }
    inTransaction = TRUE;

    // 3. Add custom sublayer
    subLayer.subLayerKey = WFPSENTINEL_SUBLAYER_GUID;
    subLayer.displayData.name = L"WfpSentinelSubLayer";
    subLayer.displayData.description = L"WfpSentinel Inspection SubLayer";
    subLayer.weight = 0x8000;

    status = FwpmSubLayerAdd0(g_GlobalData.EngineHandle, &subLayer, NULL);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[wfpsentinel] ERROR: FwpmSubLayerAdd0 failed: 0x%08X\n", (UINT32)status);
        goto ErrorCleanup;
    }
    g_GlobalData.SubLayerAdded = TRUE;

    // 4. Register callout with WFP kernel runtime
    sCallout.calloutKey = WFPSENTINEL_ALE_CONNECT_CALLOUT_GUID;
    sCallout.classifyFn = WfpSentinelClassify;
    sCallout.notifyFn = WfpSentinelNotify;
    sCallout.flowDeleteFn = WfpSentinelFlowDelete;

    status = FwpsCalloutRegister0(DeviceObject, &sCallout, &g_GlobalData.CalloutId);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[wfpsentinel] ERROR: FwpsCalloutRegister0 failed: 0x%08X\n", (UINT32)status);
        goto ErrorCleanup;
    }
    g_GlobalData.CalloutRegistered = TRUE;

    // 5. Add callout object to the WFP engine
    mCallout.calloutKey = WFPSENTINEL_ALE_CONNECT_CALLOUT_GUID;
    mCallout.displayData.name = L"WfpSentinelAleConnectCallout";
    mCallout.displayData.description = L"WfpSentinel ALE Connect V4 Callout";
    mCallout.applicableLayer = FWPM_LAYER_ALE_AUTH_CONNECT_V4;

    status = FwpmCalloutAdd0(g_GlobalData.EngineHandle, &mCallout, NULL, NULL);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[wfpsentinel] ERROR: FwpmCalloutAdd0 failed: 0x%08X\n", (UINT32)status);
        goto ErrorCleanup;
    }
    g_GlobalData.CalloutAdded = TRUE;

    // 6. Add filter referencing the callout at FWPM_LAYER_ALE_AUTH_CONNECT_V4
    filter.filterKey = WFPSENTINEL_ALE_CONNECT_FILTER_GUID;
    filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    filter.subLayerKey = WFPSENTINEL_SUBLAYER_GUID;
    filter.displayData.name = L"WfpSentinelAleConnectFilter";
    filter.displayData.description = L"WfpSentinel Outbound IPv4 ALE Connect Inspection Filter";
    filter.action.type = FWP_ACTION_CALLOUT_INSPECTION;
    filter.action.calloutKey = WFPSENTINEL_ALE_CONNECT_CALLOUT_GUID;
    filter.weight.type = FWP_EMPTY; // Auto-weight within our sublayer
    filter.numFilterConditions = 0; // Classify all outbound connections

    status = FwpmFilterAdd0(g_GlobalData.EngineHandle, &filter, NULL, &g_GlobalData.FilterId);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[wfpsentinel] ERROR: FwpmFilterAdd0 failed: 0x%08X\n", (UINT32)status);
        goto ErrorCleanup;
    }
    g_GlobalData.FilterAdded = TRUE;

    // 7. Commit atomic transaction
    status = FwpmTransactionCommit0(g_GlobalData.EngineHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[wfpsentinel] ERROR: FwpmTransactionCommit0 failed: 0x%08X\n", (UINT32)status);
        goto ErrorCleanup;
    }

    DbgPrint("[wfpsentinel] WFP callout and filter registered successfully (CalloutId=%u, FilterId=%llu)\n",
        g_GlobalData.CalloutId, g_GlobalData.FilterId);

    return STATUS_SUCCESS;

ErrorCleanup:
    if (inTransaction) {
        FwpmTransactionAbort0(g_GlobalData.EngineHandle);
    }
    WfpSentinelUnregisterCallouts();
    return status;
}

// Unregister all WFP objects and close engine session cleanly with zero leaks
VOID
WfpSentinelUnregisterCallouts(VOID)
{
    if (g_GlobalData.EngineHandle != NULL) {
        if (g_GlobalData.FilterAdded) {
            FwpmFilterDeleteById0(g_GlobalData.EngineHandle, g_GlobalData.FilterId);
            g_GlobalData.FilterAdded = FALSE;
        }

        if (g_GlobalData.CalloutAdded) {
            FwpmCalloutDeleteById0(g_GlobalData.EngineHandle, g_GlobalData.CalloutId);
            g_GlobalData.CalloutAdded = FALSE;
        }

        if (g_GlobalData.SubLayerAdded) {
            FwpmSubLayerDeleteByKey0(g_GlobalData.EngineHandle, &WFPSENTINEL_SUBLAYER_GUID);
            g_GlobalData.SubLayerAdded = FALSE;
        }

        if (g_GlobalData.CalloutRegistered) {
            FwpsCalloutUnregisterById0(g_GlobalData.CalloutId);
            g_GlobalData.CalloutRegistered = FALSE;
        }

        if (g_GlobalData.EngineOpened) {
            FwpmEngineClose0(g_GlobalData.EngineHandle);
            g_GlobalData.EngineHandle = NULL;
            g_GlobalData.EngineOpened = FALSE;
        }

        DbgPrint("[wfpsentinel] All WFP objects unregistered and engine closed cleanly\n");
    } else if (g_GlobalData.CalloutRegistered) {
        FwpsCalloutUnregisterById0(g_GlobalData.CalloutId);
        g_GlobalData.CalloutRegistered = FALSE;
    }
}

// Driver unload routine
VOID
DriverUnload(
    _In_ PDRIVER_OBJECT DriverObject
)
{
    UNREFERENCED_PARAMETER(DriverObject);

    DbgPrint("[wfpsentinel] DriverUnload: initiating teardown\n");

    // Unregister callouts, remove filters and sublayers, close engine
    WfpSentinelUnregisterCallouts();

    // Delete symbolic link and device object
    IoDeleteSymbolicLink(&g_Win32DeviceName);
    if (g_GlobalData.DeviceObject != NULL) {
        IoDeleteDevice(g_GlobalData.DeviceObject);
        g_GlobalData.DeviceObject = NULL;
    }

    DbgPrint("[wfpsentinel] DriverUnload: teardown complete, driver unloaded\n");
}

// Driver initialization routine
NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    NTSTATUS status = STATUS_SUCCESS;
    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrint("[wfpsentinel] DriverEntry: initializing wfpsentinel.sys\n");

    // Set unload routine first
    DriverObject->DriverUnload = DriverUnload;

    // Create device object
    RtlInitUnicodeString(&g_NtDeviceName, L"\\Device\\WfpSentinel");
    RtlInitUnicodeString(&g_Win32DeviceName, L"\\DosDevices\\WfpSentinel");

    status = IoCreateDevice(
        DriverObject,
        0,
        &g_NtDeviceName,
        FILE_DEVICE_NETWORK,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &g_GlobalData.DeviceObject
    );

    if (!NT_SUCCESS(status)) {
        DbgPrint("[wfpsentinel] ERROR: IoCreateDevice failed: 0x%08X\n", (UINT32)status);
        return status;
    }

    status = IoCreateSymbolicLink(&g_Win32DeviceName, &g_NtDeviceName);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[wfpsentinel] ERROR: IoCreateSymbolicLink failed: 0x%08X\n", (UINT32)status);
        IoDeleteDevice(g_GlobalData.DeviceObject);
        g_GlobalData.DeviceObject = NULL;
        return status;
    }

    // Register WFP callouts and filters
    status = WfpSentinelRegisterCallouts(g_GlobalData.DeviceObject);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[wfpsentinel] ERROR: WfpSentinelRegisterCallouts failed: 0x%08X\n", (UINT32)status);
        IoDeleteSymbolicLink(&g_Win32DeviceName);
        IoDeleteDevice(g_GlobalData.DeviceObject);
        g_GlobalData.DeviceObject = NULL;
        return status;
    }

    DbgPrint("[wfpsentinel] DriverEntry: wfpsentinel.sys initialized and active\n");

    return STATUS_SUCCESS;
}
