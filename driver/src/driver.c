#include "driver.h"

// Global driver state
WFPSENTINEL_GLOBAL_DATA g_GlobalData = { 0 };

static UNICODE_STRING g_NtDeviceName;
static UNICODE_STRING g_Win32DeviceName;

// IRP Dispatch: Create / Open Handle
NTSTATUS NTAPI
WfpSentinelDispatchCreate(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP           Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

// IRP Dispatch: Close Handle
NTSTATUS NTAPI
WfpSentinelDispatchClose(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP           Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

// IRP Dispatch: Device Control (IOCTL Handler)
NTSTATUS NTAPI
WfpSentinelDispatchDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP           Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    ULONG ioctl = irpSp->Parameters.DeviceIoControl.IoControlCode;
    ULONG inLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
    PVOID buf = Irp->AssociatedIrp.SystemBuffer;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG bytesReturned = 0;
    KIRQL oldIrql;

    switch (ioctl) {
    case IOCTL_WFPSENTINEL_ADD_BLOCK_RULE:
        if (inLen < sizeof(WFPSENTINEL_BLOCK_RULE) || !buf) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        KeAcquireSpinLock(&g_GlobalData.PolicyLock, &oldIrql);
        if (g_GlobalData.RuleCount < WFPSENTINEL_MAX_RULES) {
            PWFPSENTINEL_BLOCK_RULE newRule = (PWFPSENTINEL_BLOCK_RULE)buf;
            RtlCopyMemory(&g_GlobalData.Rules[g_GlobalData.RuleCount], newRule, sizeof(WFPSENTINEL_BLOCK_RULE));
            g_GlobalData.RuleCount++;
            g_GlobalData.Stats.ActiveRuleCount = g_GlobalData.RuleCount;

            UINT32 ip = newRule->RemoteIpV4;
            DbgPrint("[wfpsentinel] IOCTL: Added Block Rule #%u -> Remote IP=%u.%u.%u.%u Port=%u Proto=%u PID=%llu\n",
                g_GlobalData.RuleCount,
                (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF,
                newRule->RemotePort,
                newRule->Protocol,
                newRule->ProcessId
            );
            status = STATUS_SUCCESS;
        } else {
            status = STATUS_INSUFFICIENT_RESOURCES;
        }
        KeReleaseSpinLock(&g_GlobalData.PolicyLock, oldIrql);
        break;

    case IOCTL_WFPSENTINEL_CLEAR_BLOCK_RULES:
        KeAcquireSpinLock(&g_GlobalData.PolicyLock, &oldIrql);
        RtlZeroMemory(g_GlobalData.Rules, sizeof(g_GlobalData.Rules));
        g_GlobalData.RuleCount = 0;
        g_GlobalData.Stats.ActiveRuleCount = 0;
        KeReleaseSpinLock(&g_GlobalData.PolicyLock, oldIrql);

        DbgPrint("[wfpsentinel] IOCTL: Cleared all block rules\n");
        status = STATUS_SUCCESS;
        break;

    case IOCTL_WFPSENTINEL_GET_STATS:
        if (outLen < sizeof(WFPSENTINEL_STATS) || !buf) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        KeAcquireSpinLock(&g_GlobalData.PolicyLock, &oldIrql);
        RtlCopyMemory(buf, &g_GlobalData.Stats, sizeof(WFPSENTINEL_STATS));
        bytesReturned = sizeof(WFPSENTINEL_STATS);
        KeReleaseSpinLock(&g_GlobalData.PolicyLock, oldIrql);

        status = STATUS_SUCCESS;
        break;

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = bytesReturned;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

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
    UNREFERENCED_PARAMETER(filter);

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

    // Evaluate connection against dynamic block policy
    BOOLEAN matchedBlockRule = FALSE;
    KIRQL oldIrql;

    KeAcquireSpinLock(&g_GlobalData.PolicyLock, &oldIrql);
    g_GlobalData.Stats.TotalClassified++;

    for (UINT32 i = 0; i < g_GlobalData.RuleCount; i++) {
        PWFPSENTINEL_BLOCK_RULE r = &g_GlobalData.Rules[i];

        if (r->Protocol != 0 && r->Protocol != protocol) {
            continue;
        }
        if (r->RemotePort != 0 && r->RemotePort != remotePort) {
            continue;
        }
        if (r->ProcessId != 0 && r->ProcessId != processId) {
            continue;
        }
        if (r->RemoteIpV4 != 0) {
            if ((remoteIp & r->RemoteIpMask) != (r->RemoteIpV4 & r->RemoteIpMask)) {
                continue;
            }
        }

        matchedBlockRule = TRUE;
        break;
    }

    if (matchedBlockRule) {
        g_GlobalData.Stats.TotalBlocked++;
    } else {
        g_GlobalData.Stats.TotalPermitted++;
    }
    KeReleaseSpinLock(&g_GlobalData.PolicyLock, oldIrql);

    if (matchedBlockRule) {
        // Enforce Block Verdict
        if (appBlob && appBlob->data && appBlob->size >= sizeof(wchar_t)) {
            DbgPrint("[wfpsentinel] BLOCKED: PID=%llu App=%ws Proto=%u -> Remote=%u.%u.%u.%u:%u (Policy Match)\n",
                processId,
                (wchar_t*)appBlob->data,
                protocol,
                (remoteIp >> 24) & 0xFF, (remoteIp >> 16) & 0xFF, (remoteIp >> 8) & 0xFF, remoteIp & 0xFF,
                remotePort
            );
        } else {
            DbgPrint("[wfpsentinel] BLOCKED: PID=%llu Proto=%u -> Remote=%u.%u.%u.%u:%u (Policy Match)\n",
                processId,
                protocol,
                (remoteIp >> 24) & 0xFF, (remoteIp >> 16) & 0xFF, (remoteIp >> 8) & 0xFF, remoteIp & 0xFF,
                remotePort
            );
        }

        classifyOut->actionType = FWP_ACTION_BLOCK;
        classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
    } else {
        // Enforce Permit Verdict
        if (appBlob && appBlob->data && appBlob->size >= sizeof(wchar_t)) {
            DbgPrint("[wfpsentinel] PERMIT: PID=%llu App=%ws Proto=%u Local=%u.%u.%u.%u:%u -> Remote=%u.%u.%u.%u:%u\n",
                processId,
                (wchar_t*)appBlob->data,
                protocol,
                (localIp >> 24) & 0xFF, (localIp >> 16) & 0xFF, (localIp >> 8) & 0xFF, localIp & 0xFF,
                localPort,
                (remoteIp >> 24) & 0xFF, (remoteIp >> 16) & 0xFF, (remoteIp >> 8) & 0xFF, remoteIp & 0xFF,
                remotePort
            );
        } else {
            DbgPrint("[wfpsentinel] PERMIT: PID=%llu Proto=%u Local=%u.%u.%u.%u:%u -> Remote=%u.%u.%u.%u:%u\n",
                processId,
                protocol,
                (localIp >> 24) & 0xFF, (localIp >> 16) & 0xFF, (localIp >> 8) & 0xFF, localIp & 0xFF,
                localPort,
                (remoteIp >> 24) & 0xFF, (remoteIp >> 16) & 0xFF, (remoteIp >> 8) & 0xFF, remoteIp & 0xFF,
                remotePort
            );
        }

        classifyOut->actionType = FWP_ACTION_PERMIT;
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
    session.displayData.description = L"WfpSentinel Kernel Enforcement Session";
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

    // 3. Add custom sublayer with highest priority (0xFFFF) to evaluate before all third-party sublayers
    subLayer.subLayerKey = WFPSENTINEL_SUBLAYER_GUID;
    subLayer.displayData.name = L"WfpSentinelSubLayer";
    subLayer.displayData.description = L"WfpSentinel Enforcement SubLayer";
    subLayer.weight = 0xFFFF;

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

    // 6. Add filter referencing the callout at FWPM_LAYER_ALE_AUTH_CONNECT_V4 with TERMINATING action
    filter.filterKey = WFPSENTINEL_ALE_CONNECT_FILTER_GUID;
    filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    filter.subLayerKey = WFPSENTINEL_SUBLAYER_GUID;
    filter.displayData.name = L"WfpSentinelAleConnectFilter";
    filter.displayData.description = L"WfpSentinel Outbound IPv4 ALE Connect Enforcement Filter";
    filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
    filter.action.calloutKey = WFPSENTINEL_ALE_CONNECT_CALLOUT_GUID;
    UINT64 filterWeight = 0xFFFFFFFFFFFFFFFFULL;
    filter.weight.type = FWP_UINT64;
    filter.weight.uint64 = &filterWeight; // Maximum explicit filter weight pointer
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

    DbgPrint("[wfpsentinel] DriverEntry: initializing wfpsentinel.sys (Phase 2 Enforcement)\n");

    // Initialize spin lock for dynamic policy synchronization
    KeInitializeSpinLock(&g_GlobalData.PolicyLock);
    g_GlobalData.RuleCount = 0;
    RtlZeroMemory(g_GlobalData.Rules, sizeof(g_GlobalData.Rules));
    RtlZeroMemory(&g_GlobalData.Stats, sizeof(g_GlobalData.Stats));

    // Set unload routine
    DriverObject->DriverUnload = DriverUnload;

    // Register IRP dispatch routines for user-mode control
    DriverObject->MajorFunction[IRP_MJ_CREATE] = WfpSentinelDispatchCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = WfpSentinelDispatchClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = WfpSentinelDispatchDeviceControl;

    // Create device object
    RtlInitUnicodeString(&g_NtDeviceName, WFPSENTINEL_DEVICE_NAME);
    RtlInitUnicodeString(&g_Win32DeviceName, WFPSENTINEL_SYMBOLIC_NAME);

    status = IoCreateDevice(
        DriverObject,
        0,
        &g_NtDeviceName,
        WFPSENTINEL_DEVICE_TYPE,
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
