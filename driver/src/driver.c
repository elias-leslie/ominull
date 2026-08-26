#include "ominull_driver.h"

// Global driver state
OMINULL_GLOBAL_DATA g_GlobalData = { 0 };

static UNICODE_STRING g_NtDeviceName;
static UNICODE_STRING g_Win32DeviceName;

// Helper: Extract process image path from ALE_APP_ID blob or metadata
static void
OminullExtractAppPath(
    _In_opt_ const FWP_BYTE_BLOB*                  AppBlob,
    _In_opt_ const FWPS_INCOMING_METADATA_VALUES0* MetaValues,
    _Out_writes_(MaxChars) WCHAR*                  OutPath,
    _In_ UINT32                                    MaxChars
)
{
    if (!OutPath || MaxChars == 0) return;
    OutPath[0] = L'\0';
    OutPath[MaxChars - 1] = L'\0';

    const FWP_BYTE_BLOB* blob = AppBlob;
    if ((!blob || !blob->data || blob->size == 0) && MetaValues) {
        if (MetaValues->currentFields & FWPS_METADATA_FIELD_PROCESS_PATH) {
            blob = MetaValues->processPath;
        }
    }

    if (blob && blob->data && blob->size >= sizeof(WCHAR)) {
        UINT32 chars = blob->size / sizeof(WCHAR);
        if (chars >= MaxChars) {
            chars = MaxChars - 1;
        }
        RtlCopyMemory(OutPath, blob->data, chars * sizeof(WCHAR));
        OutPath[chars] = L'\0';
    }
}

// Helper: Non-pageable case-insensitive substring match for process image path
static BOOLEAN
OminullPathMatchesPattern(
    _In_ const WCHAR* Path,
    _In_ const WCHAR* Pattern,
    _In_ UINT16       PatternLen
)
{
    if (!Pattern || PatternLen == 0 || Pattern[0] == L'\0') {
        return TRUE;
    }
    if (!Path || Path[0] == L'\0') {
        return FALSE;
    }

    size_t pathLen = 0;
    while (pathLen < OMINULL_MAX_PATH && Path[pathLen] != L'\0') {
        pathLen++;
    }

    if (pathLen < PatternLen) {
        return FALSE;
    }

    for (size_t i = 0; i <= pathLen - PatternLen; i++) {
        BOOLEAN match = TRUE;
        for (UINT16 j = 0; j < PatternLen; j++) {
            WCHAR c1 = Path[i + j];
            WCHAR c2 = Pattern[j];
            if (c1 >= L'A' && c1 <= L'Z') c1 += (L'a' - L'A');
            if (c2 >= L'A' && c2 <= L'Z') c2 += (L'a' - L'A');
            if (c1 != c2) {
                match = FALSE;
                break;
            }
        }
        if (match) {
            return TRUE;
        }
    }
    return FALSE;
}

// Helper: Match IPv6 address against prefix with arbitrary prefix length (0-128)
static BOOLEAN
OminullIpv6PrefixMatch(
    _In_reads_(16) const UINT8* Addr,
    _In_reads_(16) const UINT8* Prefix,
    _In_ UINT8                  PrefixLen
)
{
    if (PrefixLen == 0) {
        return TRUE;
    }
    if (PrefixLen > 128) {
        PrefixLen = 128;
    }

    UINT8 fullBytes = PrefixLen / 8;
    UINT8 remBits = PrefixLen % 8;

    for (UINT8 i = 0; i < fullBytes; i++) {
        if (Addr[i] != Prefix[i]) {
            return FALSE;
        }
    }

    if (remBits > 0) {
        UINT8 mask = (UINT8)(0xFF << (8 - remBits));
        if ((Addr[fullBytes] & mask) != (Prefix[fullBytes] & mask)) {
            return FALSE;
        }
    }

    return TRUE;
}

// Policy Engine: Evaluates connection parameters against dynamic rule table
UINT8
OminullEvaluatePolicy(
    _In_ UINT8                      Direction,
    _In_ UINT8                      IpVersion,
    _In_ UINT8                      Protocol,
    _In_ UINT16                     LocalPort,
    _In_ UINT16                     RemotePort,
    _In_ UINT32                     RemoteIpV4,
    _In_reads_opt_(16) const UINT8* RemoteIpV6,
    _In_ UINT64                     ProcessId,
    _In_ const WCHAR*               ProcessPath
)
{
    UINT8 verdict = OMINULL_ACTION_ALLOW;
    KIRQL oldIrql;

    KeAcquireSpinLock(&g_GlobalData.PolicyLock, &oldIrql);

    for (UINT32 i = 0; i < g_GlobalData.RuleCount; i++) {
        POMINULL_RULE r = &g_GlobalData.Rules[i];

        if (r->Direction != OMINULL_DIR_ANY && r->Direction != Direction) {
            continue;
        }
        if (r->IpVersion != 0 && r->IpVersion != IpVersion) {
            continue;
        }
        if (r->Protocol != 0 && r->Protocol != Protocol) {
            continue;
        }
        if (r->RemotePort != 0 && r->RemotePort != RemotePort) {
            continue;
        }
        if (r->LocalPort != 0 && r->LocalPort != LocalPort) {
            continue;
        }
        if (r->ProcessId != 0 && r->ProcessId != ProcessId) {
            continue;
        }

        if (IpVersion == 4 && r->RemoteIpV4Mask != 0) {
            if ((RemoteIpV4 & r->RemoteIpV4Mask) != (r->RemoteIpV4 & r->RemoteIpV4Mask)) {
                continue;
            }
        }

        if (IpVersion == 6 && r->RemoteIpV6PrefixLen > 0 && RemoteIpV6 != NULL) {
            if (!OminullIpv6PrefixMatch(RemoteIpV6, r->RemoteIpV6, r->RemoteIpV6PrefixLen)) {
                continue;
            }
        }

        if (r->ProcessPathLen > 0) {
            if (!OminullPathMatchesPattern(ProcessPath, r->ProcessPath, r->ProcessPathLen)) {
                continue;
            }
        }

        verdict = r->Action;
        break;
    }

    KeReleaseSpinLock(&g_GlobalData.PolicyLock, oldIrql);
    return verdict;
}

// Inverted Call: Emits telemetry event to pending IRP or ring buffer
VOID
OminullEmitEvent(
    _In_ const OMINULL_EVENT* Event
)
{
    KIRQL oldIrql;
    PIRP pendingIrp = NULL;

    KeAcquireSpinLock(&g_GlobalData.TelemetryLock, &oldIrql);

    while (!IsListEmpty(&g_GlobalData.PendingIrpList)) {
        PLIST_ENTRY entry = RemoveHeadList(&g_GlobalData.PendingIrpList);
        PIRP irp = CONTAINING_RECORD(entry, IRP, Tail.Overlay.ListEntry);
        InitializeListHead(&irp->Tail.Overlay.ListEntry);

        if (g_GlobalData.Stats.PendingIrpCount > 0) {
            g_GlobalData.Stats.PendingIrpCount--;
        }

        if (IoSetCancelRoutine(irp, NULL) != NULL) {
            pendingIrp = irp;
            break;
        }
    }

    if (pendingIrp != NULL) {
        PVOID targetBuf = pendingIrp->AssociatedIrp.SystemBuffer;
        if (targetBuf) {
            RtlCopyMemory(targetBuf, Event, sizeof(OMINULL_EVENT));
            pendingIrp->IoStatus.Information = sizeof(OMINULL_EVENT);
            pendingIrp->IoStatus.Status = STATUS_SUCCESS;
            g_GlobalData.Stats.TotalEventsStreamed++;
        } else {
            pendingIrp->IoStatus.Information = 0;
            pendingIrp->IoStatus.Status = STATUS_UNSUCCESSFUL;
        }
        KeReleaseSpinLock(&g_GlobalData.TelemetryLock, oldIrql);

        IoCompleteRequest(pendingIrp, IO_NO_INCREMENT);
    } else {
        if (g_GlobalData.EventCount < OMINULL_EVENT_QUEUE_SIZE) {
            RtlCopyMemory(&g_GlobalData.EventQueue[g_GlobalData.EventHead], Event, sizeof(OMINULL_EVENT));
            g_GlobalData.EventHead = (g_GlobalData.EventHead + 1) % OMINULL_EVENT_QUEUE_SIZE;
            g_GlobalData.EventCount++;
        } else {
            g_GlobalData.EventTail = (g_GlobalData.EventTail + 1) % OMINULL_EVENT_QUEUE_SIZE;
            RtlCopyMemory(&g_GlobalData.EventQueue[g_GlobalData.EventHead], Event, sizeof(OMINULL_EVENT));
            g_GlobalData.EventHead = (g_GlobalData.EventHead + 1) % OMINULL_EVENT_QUEUE_SIZE;
        }
        KeReleaseSpinLock(&g_GlobalData.TelemetryLock, oldIrql);
    }
}

// Inverted Call: Cancel routine for queued IRPs
VOID
NTAPI
OminullIrpCancelRoutine(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP           Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    KIRQL oldIrql;

    IoReleaseCancelSpinLock(Irp->CancelIrql);

    KeAcquireSpinLock(&g_GlobalData.TelemetryLock, &oldIrql);
    if (Irp->Tail.Overlay.ListEntry.Flink != NULL && Irp->Tail.Overlay.ListEntry.Blink != NULL) {
        RemoveEntryList(&Irp->Tail.Overlay.ListEntry);
        InitializeListHead(&Irp->Tail.Overlay.ListEntry);
        if (g_GlobalData.Stats.PendingIrpCount > 0) {
            g_GlobalData.Stats.PendingIrpCount--;
        }
    }
    KeReleaseSpinLock(&g_GlobalData.TelemetryLock, oldIrql);

    Irp->IoStatus.Status = STATUS_CANCELLED;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
}

// Inverted Call: Flushes and cancels all pending streaming IRPs on close/teardown
VOID
OminullFlushPendingIrps(VOID)
{
    KIRQL oldIrql;
    LIST_ENTRY cancelList;
    InitializeListHead(&cancelList);

    KeAcquireSpinLock(&g_GlobalData.TelemetryLock, &oldIrql);
    while (!IsListEmpty(&g_GlobalData.PendingIrpList)) {
        PLIST_ENTRY entry = RemoveHeadList(&g_GlobalData.PendingIrpList);
        PIRP irp = CONTAINING_RECORD(entry, IRP, Tail.Overlay.ListEntry);
        InitializeListHead(&irp->Tail.Overlay.ListEntry);

        if (IoSetCancelRoutine(irp, NULL) != NULL) {
            InsertTailList(&cancelList, entry);
        }
    }
    g_GlobalData.Stats.PendingIrpCount = 0;
    g_GlobalData.EventHead = 0;
    g_GlobalData.EventTail = 0;
    g_GlobalData.EventCount = 0;
    KeReleaseSpinLock(&g_GlobalData.TelemetryLock, oldIrql);

    while (!IsListEmpty(&cancelList)) {
        PLIST_ENTRY entry = RemoveHeadList(&cancelList);
        PIRP irp = CONTAINING_RECORD(entry, IRP, Tail.Overlay.ListEntry);
        irp->IoStatus.Status = STATUS_CANCELLED;
        irp->IoStatus.Information = 0;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
    }
}

// IRP Dispatch: Create / Open Handle
NTSTATUS NTAPI
OminullDispatchCreate(
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
OminullDispatchClose(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP           Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    OminullFlushPendingIrps();
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

// IRP Dispatch: Device Control (IOCTL Handler)
NTSTATUS NTAPI
OminullDispatchDeviceControl(
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
    case IOCTL_OMINULL_ADD_BLOCK_RULE: // Legacy IPv4 block IOCTL
        if (inLen < sizeof(OMINULL_BLOCK_RULE) || !buf) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        KeAcquireSpinLock(&g_GlobalData.PolicyLock, &oldIrql);
        if (g_GlobalData.RuleCount < OMINULL_MAX_RULES) {
            POMINULL_BLOCK_RULE legacyRule = (POMINULL_BLOCK_RULE)buf;
            POMINULL_RULE rule = &g_GlobalData.Rules[g_GlobalData.RuleCount];
            RtlZeroMemory(rule, sizeof(OMINULL_RULE));

            rule->RuleId = ++g_GlobalData.NextRuleId;
            rule->Action = OMINULL_ACTION_BLOCK;
            rule->Direction = OMINULL_DIR_OUTBOUND;
            rule->IpVersion = 4;
            rule->RemoteIpV4 = legacyRule->RemoteIpV4;
            rule->RemoteIpV4Mask = legacyRule->RemoteIpMask ? legacyRule->RemoteIpMask : 0xFFFFFFFF;
            rule->RemotePort = legacyRule->RemotePort;
            rule->Protocol = legacyRule->Protocol;
            rule->ProcessId = legacyRule->ProcessId;

            g_GlobalData.RuleCount++;
            g_GlobalData.Stats.ActiveRuleCount = g_GlobalData.RuleCount;

            UINT32 ip = rule->RemoteIpV4;
            DbgPrint("[ominull] IOCTL: Added Legacy Block Rule #%u (ID=%u) -> Remote IP=%u.%u.%u.%u Port=%u Proto=%u PID=%llu\n",
                g_GlobalData.RuleCount, rule->RuleId,
                (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF,
                rule->RemotePort, rule->Protocol, rule->ProcessId);
            status = STATUS_SUCCESS;
        } else {
            status = STATUS_INSUFFICIENT_RESOURCES;
        }
        KeReleaseSpinLock(&g_GlobalData.PolicyLock, oldIrql);
        break;

    case IOCTL_OMINULL_ADD_RULE: // Advanced Dynamic Policy IOCTL
        if (inLen < sizeof(OMINULL_RULE) || !buf) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        KeAcquireSpinLock(&g_GlobalData.PolicyLock, &oldIrql);
        if (g_GlobalData.RuleCount < OMINULL_MAX_RULES) {
            POMINULL_RULE inputRule = (POMINULL_RULE)buf;
            POMINULL_RULE rule = &g_GlobalData.Rules[g_GlobalData.RuleCount];
            RtlCopyMemory(rule, inputRule, sizeof(OMINULL_RULE));
            rule->ProcessPath[OMINULL_MAX_PATH - 1] = L'\0';

            rule->RuleId = ++g_GlobalData.NextRuleId;
            g_GlobalData.RuleCount++;
            g_GlobalData.Stats.ActiveRuleCount = g_GlobalData.RuleCount;

            if (outLen >= sizeof(UINT32) && buf) {
                *(UINT32*)buf = rule->RuleId;
                bytesReturned = sizeof(UINT32);
            }

            DbgPrint("[ominull] IOCTL: Added Dynamic Rule ID=%u Action=%u Dir=%u IPVer=%u Port=%u Proto=%u PID=%llu App=%ws\n",
                rule->RuleId, rule->Action, rule->Direction, rule->IpVersion,
                rule->RemotePort, rule->Protocol, rule->ProcessId,
                rule->ProcessPathLen > 0 ? rule->ProcessPath : L"(any)");
            status = STATUS_SUCCESS;
        } else {
            status = STATUS_INSUFFICIENT_RESOURCES;
        }
        KeReleaseSpinLock(&g_GlobalData.PolicyLock, oldIrql);
        break;

    case IOCTL_OMINULL_DELETE_RULE:
        if (inLen < sizeof(UINT32) || !buf) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        {
            UINT32 targetId = *(UINT32*)buf;
            BOOLEAN found = FALSE;

            KeAcquireSpinLock(&g_GlobalData.PolicyLock, &oldIrql);
            for (UINT32 i = 0; i < g_GlobalData.RuleCount; i++) {
                if (g_GlobalData.Rules[i].RuleId == targetId) {
                    found = TRUE;
                    for (UINT32 j = i; j + 1 < g_GlobalData.RuleCount; j++) {
                        g_GlobalData.Rules[j] = g_GlobalData.Rules[j + 1];
                    }
                    g_GlobalData.RuleCount--;
                    g_GlobalData.Stats.ActiveRuleCount = g_GlobalData.RuleCount;
                    RtlZeroMemory(&g_GlobalData.Rules[g_GlobalData.RuleCount], sizeof(OMINULL_RULE));
                    break;
                }
            }
            KeReleaseSpinLock(&g_GlobalData.PolicyLock, oldIrql);

            status = found ? STATUS_SUCCESS : STATUS_NOT_FOUND;
        }
        break;

    case IOCTL_OMINULL_CLEAR_BLOCK_RULES:
    case IOCTL_OMINULL_CLEAR_RULES:
        KeAcquireSpinLock(&g_GlobalData.PolicyLock, &oldIrql);
        RtlZeroMemory(g_GlobalData.Rules, sizeof(g_GlobalData.Rules));
        g_GlobalData.RuleCount = 0;
        g_GlobalData.Stats.ActiveRuleCount = 0;
        KeReleaseSpinLock(&g_GlobalData.PolicyLock, oldIrql);

        DbgPrint("[ominull] IOCTL: Cleared all kernel rules\n");
        status = STATUS_SUCCESS;
        break;

    case IOCTL_OMINULL_GET_RULES:
        if (outLen < sizeof(OMINULL_RULES_LIST) || !buf) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        KeAcquireSpinLock(&g_GlobalData.PolicyLock, &oldIrql);
        POMINULL_RULES_LIST list = (POMINULL_RULES_LIST)buf;
        list->RuleCount = g_GlobalData.RuleCount;
        RtlCopyMemory(list->Rules, g_GlobalData.Rules, g_GlobalData.RuleCount * sizeof(OMINULL_RULE));
        bytesReturned = sizeof(UINT32) + g_GlobalData.RuleCount * sizeof(OMINULL_RULE);
        KeReleaseSpinLock(&g_GlobalData.PolicyLock, oldIrql);

        status = STATUS_SUCCESS;
        break;

    case IOCTL_OMINULL_GET_STATS:
        if (outLen < sizeof(OMINULL_STATS) || !buf) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        KeAcquireSpinLock(&g_GlobalData.PolicyLock, &oldIrql);
        RtlCopyMemory(buf, &g_GlobalData.Stats, sizeof(OMINULL_STATS));
        bytesReturned = sizeof(OMINULL_STATS);
        KeReleaseSpinLock(&g_GlobalData.PolicyLock, oldIrql);

        status = STATUS_SUCCESS;
        break;

    case IOCTL_OMINULL_STREAM_EVENT: // Inverted Call Real-Time Event Streaming
        if (outLen < sizeof(OMINULL_EVENT) || !buf) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        KeAcquireSpinLock(&g_GlobalData.TelemetryLock, &oldIrql);
        if (g_GlobalData.EventCount > 0) {
            POMINULL_EVENT ev = &g_GlobalData.EventQueue[g_GlobalData.EventTail];
            RtlCopyMemory(buf, ev, sizeof(OMINULL_EVENT));
            g_GlobalData.EventTail = (g_GlobalData.EventTail + 1) % OMINULL_EVENT_QUEUE_SIZE;
            g_GlobalData.EventCount--;
            g_GlobalData.Stats.TotalEventsStreamed++;
            bytesReturned = sizeof(OMINULL_EVENT);
            KeReleaseSpinLock(&g_GlobalData.TelemetryLock, oldIrql);
            status = STATUS_SUCCESS;
        } else {
            IoMarkIrpPending(Irp);
            IoSetCancelRoutine(Irp, OminullIrpCancelRoutine);
            InsertTailList(&g_GlobalData.PendingIrpList, &Irp->Tail.Overlay.ListEntry);
            g_GlobalData.Stats.PendingIrpCount++;
            KeReleaseSpinLock(&g_GlobalData.TelemetryLock, oldIrql);
            return STATUS_PENDING;
        }
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

// Classify: Outbound IPv4 ALE Connect
void NTAPI
OminullClassifyConnectV4(
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

    UINT32 localIp = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_ADDRESS].value.uint32;
    UINT16 localPort = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_PORT].value.uint16;
    UINT32 remoteIp = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS].value.uint32;
    UINT16 remotePort = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT].value.uint16;
    UINT8 protocol = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL].value.uint8;

    UINT64 processId = 0;
    if (inMetaValues && (inMetaValues->currentFields & FWPS_METADATA_FIELD_PROCESS_ID)) {
        processId = inMetaValues->processId;
    }

    WCHAR appPath[OMINULL_MAX_PATH];
    FWP_BYTE_BLOB* appBlob = NULL;
    if (inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_ALE_APP_ID].value.type == FWP_BYTE_BLOB_TYPE) {
        appBlob = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_ALE_APP_ID].value.byteBlob;
    }
    OminullExtractAppPath(appBlob, inMetaValues, appPath, OMINULL_MAX_PATH);

    UINT8 verdict = OminullEvaluatePolicy(
        OMINULL_DIR_OUTBOUND, 4, protocol, localPort, remotePort, remoteIp, NULL, processId, appPath
    );

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_GlobalData.PolicyLock, &oldIrql);
    g_GlobalData.Stats.TotalClassified++;
    g_GlobalData.Stats.TotalV4Connections++;
    g_GlobalData.Stats.TotalOutboundConnections++;
    if (verdict == OMINULL_ACTION_BLOCK) {
        g_GlobalData.Stats.TotalBlocked++;
    } else {
        g_GlobalData.Stats.TotalPermitted++;
    }
    KeReleaseSpinLock(&g_GlobalData.PolicyLock, oldIrql);

    OMINULL_EVENT ev;
    RtlZeroMemory(&ev, sizeof(ev));
    KeQuerySystemTime((PLARGE_INTEGER)&ev.Timestamp);
    ev.EventType = (verdict == OMINULL_ACTION_BLOCK) ? OMINULL_EVENT_BLOCKED : OMINULL_EVENT_CONNECT_V4;
    ev.Action = (verdict == OMINULL_ACTION_BLOCK) ? 1 : 0;
    ev.ProcessId = processId;
    ev.IpVersion = 4;
    ev.Protocol = protocol;
    ev.Direction = OMINULL_DIR_OUTBOUND;
    ev.LocalPort = localPort;
    ev.RemotePort = remotePort;
    ev.Addr.Ipv4.LocalIp = localIp;
    ev.Addr.Ipv4.RemoteIp = remoteIp;
    RtlCopyMemory(ev.ProcessPath, appPath, sizeof(appPath));
    OminullEmitEvent(&ev);

    if (verdict == OMINULL_ACTION_BLOCK) {
        DbgPrint("[ominull] BLOCKED OUT V4: PID=%llu App=%ws Proto=%u -> Remote=%u.%u.%u.%u:%u\n",
            processId, appPath, protocol,
            (remoteIp >> 24) & 0xFF, (remoteIp >> 16) & 0xFF, (remoteIp >> 8) & 0xFF, remoteIp & 0xFF,
            remotePort);
        if (classifyOut->rights & FWPS_RIGHT_ACTION_WRITE) {
            classifyOut->actionType = FWP_ACTION_BLOCK;
            classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
        }
    } else {
        DbgPrint("[ominull] PERMIT OUT V4: PID=%llu Proto=%u Local=%u.%u.%u.%u:%u -> Remote=%u.%u.%u.%u:%u\n",
            processId, protocol,
            (localIp >> 24) & 0xFF, (localIp >> 16) & 0xFF, (localIp >> 8) & 0xFF, localIp & 0xFF, localPort,
            (remoteIp >> 24) & 0xFF, (remoteIp >> 16) & 0xFF, (remoteIp >> 8) & 0xFF, remoteIp & 0xFF, remotePort);
        classifyOut->actionType = FWP_ACTION_CONTINUE;
    }
}

// Classify: Outbound IPv6 ALE Connect
void NTAPI
OminullClassifyConnectV6(
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

    UINT8 localIp6[16] = { 0 };
    UINT8 remoteIp6[16] = { 0 };
    if (inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_ADDRESS].value.type == FWP_BYTE_ARRAY16_TYPE &&
        inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_ADDRESS].value.byteArray16) {
        RtlCopyMemory(localIp6, inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_ADDRESS].value.byteArray16->byteArray16, 16);
    }
    if (inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_ADDRESS].value.type == FWP_BYTE_ARRAY16_TYPE &&
        inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_ADDRESS].value.byteArray16) {
        RtlCopyMemory(remoteIp6, inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_ADDRESS].value.byteArray16->byteArray16, 16);
    }

    UINT16 localPort = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_PORT].value.uint16;
    UINT16 remotePort = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_PORT].value.uint16;
    UINT8 protocol = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_PROTOCOL].value.uint8;

    UINT64 processId = 0;
    if (inMetaValues && (inMetaValues->currentFields & FWPS_METADATA_FIELD_PROCESS_ID)) {
        processId = inMetaValues->processId;
    }

    WCHAR appPath[OMINULL_MAX_PATH];
    FWP_BYTE_BLOB* appBlob = NULL;
    if (inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_ALE_APP_ID].value.type == FWP_BYTE_BLOB_TYPE) {
        appBlob = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_ALE_APP_ID].value.byteBlob;
    }
    OminullExtractAppPath(appBlob, inMetaValues, appPath, OMINULL_MAX_PATH);

    UINT8 verdict = OminullEvaluatePolicy(
        OMINULL_DIR_OUTBOUND, 6, protocol, localPort, remotePort, 0, remoteIp6, processId, appPath
    );

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_GlobalData.PolicyLock, &oldIrql);
    g_GlobalData.Stats.TotalClassified++;
    g_GlobalData.Stats.TotalV6Connections++;
    g_GlobalData.Stats.TotalOutboundConnections++;
    if (verdict == OMINULL_ACTION_BLOCK) {
        g_GlobalData.Stats.TotalBlocked++;
    } else {
        g_GlobalData.Stats.TotalPermitted++;
    }
    KeReleaseSpinLock(&g_GlobalData.PolicyLock, oldIrql);

    OMINULL_EVENT ev;
    RtlZeroMemory(&ev, sizeof(ev));
    KeQuerySystemTime((PLARGE_INTEGER)&ev.Timestamp);
    ev.EventType = (verdict == OMINULL_ACTION_BLOCK) ? OMINULL_EVENT_BLOCKED : OMINULL_EVENT_CONNECT_V6;
    ev.Action = (verdict == OMINULL_ACTION_BLOCK) ? 1 : 0;
    ev.ProcessId = processId;
    ev.IpVersion = 6;
    ev.Protocol = protocol;
    ev.Direction = OMINULL_DIR_OUTBOUND;
    ev.LocalPort = localPort;
    ev.RemotePort = remotePort;
    RtlCopyMemory(ev.Addr.Ipv6.LocalIp, localIp6, 16);
    RtlCopyMemory(ev.Addr.Ipv6.RemoteIp, remoteIp6, 16);
    RtlCopyMemory(ev.ProcessPath, appPath, sizeof(appPath));
    OminullEmitEvent(&ev);

    if (verdict == OMINULL_ACTION_BLOCK) {
        DbgPrint("[ominull] BLOCKED OUT V6: PID=%llu App=%ws Proto=%u RemotePort=%u\n",
            processId, appPath, protocol, remotePort);
        if (classifyOut->rights & FWPS_RIGHT_ACTION_WRITE) {
            classifyOut->actionType = FWP_ACTION_BLOCK;
            classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
        }
    } else {
        DbgPrint("[ominull] PERMIT OUT V6: PID=%llu Proto=%u LocalPort=%u RemotePort=%u\n",
            processId, protocol, localPort, remotePort);
        classifyOut->actionType = FWP_ACTION_CONTINUE;
    }
}

// Classify: Inbound IPv4 ALE Recv / Accept
void NTAPI
OminullClassifyRecvAcceptV4(
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

    UINT32 localIp = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_ADDRESS].value.uint32;
    UINT16 localPort = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_PORT].value.uint16;
    UINT32 remoteIp = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_ADDRESS].value.uint32;
    UINT16 remotePort = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_PORT].value.uint16;
    UINT8 protocol = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_PROTOCOL].value.uint8;

    UINT64 processId = 0;
    if (inMetaValues && (inMetaValues->currentFields & FWPS_METADATA_FIELD_PROCESS_ID)) {
        processId = inMetaValues->processId;
    }

    WCHAR appPath[OMINULL_MAX_PATH];
    FWP_BYTE_BLOB* appBlob = NULL;
    if (inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_ALE_APP_ID].value.type == FWP_BYTE_BLOB_TYPE) {
        appBlob = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_ALE_APP_ID].value.byteBlob;
    }
    OminullExtractAppPath(appBlob, inMetaValues, appPath, OMINULL_MAX_PATH);

    UINT8 verdict = OminullEvaluatePolicy(
        OMINULL_DIR_INBOUND, 4, protocol, localPort, remotePort, remoteIp, NULL, processId, appPath
    );

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_GlobalData.PolicyLock, &oldIrql);
    g_GlobalData.Stats.TotalClassified++;
    g_GlobalData.Stats.TotalV4Connections++;
    g_GlobalData.Stats.TotalInboundConnections++;
    if (verdict == OMINULL_ACTION_BLOCK) {
        g_GlobalData.Stats.TotalBlocked++;
    } else {
        g_GlobalData.Stats.TotalPermitted++;
    }
    KeReleaseSpinLock(&g_GlobalData.PolicyLock, oldIrql);

    OMINULL_EVENT ev;
    RtlZeroMemory(&ev, sizeof(ev));
    KeQuerySystemTime((PLARGE_INTEGER)&ev.Timestamp);
    ev.EventType = (verdict == OMINULL_ACTION_BLOCK) ? OMINULL_EVENT_BLOCKED : OMINULL_EVENT_RECV_ACCEPT_V4;
    ev.Action = (verdict == OMINULL_ACTION_BLOCK) ? 1 : 0;
    ev.ProcessId = processId;
    ev.IpVersion = 4;
    ev.Protocol = protocol;
    ev.Direction = OMINULL_DIR_INBOUND;
    ev.LocalPort = localPort;
    ev.RemotePort = remotePort;
    ev.Addr.Ipv4.LocalIp = localIp;
    ev.Addr.Ipv4.RemoteIp = remoteIp;
    RtlCopyMemory(ev.ProcessPath, appPath, sizeof(appPath));
    OminullEmitEvent(&ev);

    if (verdict == OMINULL_ACTION_BLOCK) {
        DbgPrint("[ominull] BLOCKED IN V4: PID=%llu App=%ws Proto=%u Remote=%u.%u.%u.%u:%u -> LocalPort=%u\n",
            processId, appPath, protocol,
            (remoteIp >> 24) & 0xFF, (remoteIp >> 16) & 0xFF, (remoteIp >> 8) & 0xFF, remoteIp & 0xFF,
            remotePort, localPort);
        if (classifyOut->rights & FWPS_RIGHT_ACTION_WRITE) {
            classifyOut->actionType = FWP_ACTION_BLOCK;
            classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
        }
    } else {
        DbgPrint("[ominull] PERMIT IN V4: PID=%llu Proto=%u Remote=%u.%u.%u.%u:%u -> LocalPort=%u\n",
            processId, protocol,
            (remoteIp >> 24) & 0xFF, (remoteIp >> 16) & 0xFF, (remoteIp >> 8) & 0xFF, remoteIp & 0xFF,
            remotePort, localPort);
        classifyOut->actionType = FWP_ACTION_CONTINUE;
    }
}

// Classify: Inbound IPv6 ALE Recv / Accept
void NTAPI
OminullClassifyRecvAcceptV6(
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

    UINT8 localIp6[16] = { 0 };
    UINT8 remoteIp6[16] = { 0 };
    if (inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_LOCAL_ADDRESS].value.type == FWP_BYTE_ARRAY16_TYPE &&
        inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_LOCAL_ADDRESS].value.byteArray16) {
        RtlCopyMemory(localIp6, inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_LOCAL_ADDRESS].value.byteArray16->byteArray16, 16);
    }
    if (inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_REMOTE_ADDRESS].value.type == FWP_BYTE_ARRAY16_TYPE &&
        inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_REMOTE_ADDRESS].value.byteArray16) {
        RtlCopyMemory(remoteIp6, inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_REMOTE_ADDRESS].value.byteArray16->byteArray16, 16);
    }

    UINT16 localPort = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_LOCAL_PORT].value.uint16;
    UINT16 remotePort = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_REMOTE_PORT].value.uint16;
    UINT8 protocol = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_PROTOCOL].value.uint8;

    UINT64 processId = 0;
    if (inMetaValues && (inMetaValues->currentFields & FWPS_METADATA_FIELD_PROCESS_ID)) {
        processId = inMetaValues->processId;
    }

    WCHAR appPath[OMINULL_MAX_PATH];
    FWP_BYTE_BLOB* appBlob = NULL;
    if (inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_ALE_APP_ID].value.type == FWP_BYTE_BLOB_TYPE) {
        appBlob = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_ALE_APP_ID].value.byteBlob;
    }
    OminullExtractAppPath(appBlob, inMetaValues, appPath, OMINULL_MAX_PATH);

    UINT8 verdict = OminullEvaluatePolicy(
        OMINULL_DIR_INBOUND, 6, protocol, localPort, remotePort, 0, remoteIp6, processId, appPath
    );

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_GlobalData.PolicyLock, &oldIrql);
    g_GlobalData.Stats.TotalClassified++;
    g_GlobalData.Stats.TotalV6Connections++;
    g_GlobalData.Stats.TotalInboundConnections++;
    if (verdict == OMINULL_ACTION_BLOCK) {
        g_GlobalData.Stats.TotalBlocked++;
    } else {
        g_GlobalData.Stats.TotalPermitted++;
    }
    KeReleaseSpinLock(&g_GlobalData.PolicyLock, oldIrql);

    OMINULL_EVENT ev;
    RtlZeroMemory(&ev, sizeof(ev));
    KeQuerySystemTime((PLARGE_INTEGER)&ev.Timestamp);
    ev.EventType = (verdict == OMINULL_ACTION_BLOCK) ? OMINULL_EVENT_BLOCKED : OMINULL_EVENT_RECV_ACCEPT_V6;
    ev.Action = (verdict == OMINULL_ACTION_BLOCK) ? 1 : 0;
    ev.ProcessId = processId;
    ev.IpVersion = 6;
    ev.Protocol = protocol;
    ev.Direction = OMINULL_DIR_INBOUND;
    ev.LocalPort = localPort;
    ev.RemotePort = remotePort;
    RtlCopyMemory(ev.Addr.Ipv6.LocalIp, localIp6, 16);
    RtlCopyMemory(ev.Addr.Ipv6.RemoteIp, remoteIp6, 16);
    RtlCopyMemory(ev.ProcessPath, appPath, sizeof(appPath));
    OminullEmitEvent(&ev);

    if (verdict == OMINULL_ACTION_BLOCK) {
        DbgPrint("[ominull] BLOCKED IN V6: PID=%llu App=%ws Proto=%u LocalPort=%u RemotePort=%u\n",
            processId, appPath, protocol, localPort, remotePort);
        if (classifyOut->rights & FWPS_RIGHT_ACTION_WRITE) {
            classifyOut->actionType = FWP_ACTION_BLOCK;
            classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
        }
    } else {
        DbgPrint("[ominull] PERMIT IN V6: PID=%llu Proto=%u LocalPort=%u RemotePort=%u\n",
            processId, protocol, localPort, remotePort);
        classifyOut->actionType = FWP_ACTION_CONTINUE;
    }
}

// Classify: ALE Flow Established V4 (Context Tracking)
void NTAPI
OminullClassifyFlowEstV4(
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
    UNREFERENCED_PARAMETER(filter);

    if (!classifyOut) {
        return;
    }
    classifyOut->actionType = FWP_ACTION_CONTINUE;

    if (!inFixedValues || !inMetaValues) {
        return;
    }

    if (flowContext == 0 && (inMetaValues->currentFields & FWPS_METADATA_FIELD_FLOW_HANDLE)) {
        UINT64 flowHandle = inMetaValues->flowHandle;

        POMINULL_FLOW_CONTEXT flowCtx = (POMINULL_FLOW_CONTEXT)ExAllocatePoolWithTag(
            NonPagedPool, sizeof(OMINULL_FLOW_CONTEXT), OMINULL_TAG
        );

        if (flowCtx != NULL) {
            RtlZeroMemory(flowCtx, sizeof(OMINULL_FLOW_CONTEXT));
            flowCtx->FlowId = flowHandle;
            flowCtx->IpVersion = 4;
            flowCtx->Protocol = inFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_PROTOCOL].value.uint8;
            flowCtx->LocalPort = inFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_LOCAL_PORT].value.uint16;
            flowCtx->RemotePort = inFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_REMOTE_PORT].value.uint16;
            flowCtx->Addr.Ipv4.LocalIp = inFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_LOCAL_ADDRESS].value.uint32;
            flowCtx->Addr.Ipv4.RemoteIp = inFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_REMOTE_ADDRESS].value.uint32;
            flowCtx->Direction = (inMetaValues->currentFields & FWPS_METADATA_FIELD_PACKET_DIRECTION) ?
                (UINT8)inMetaValues->packetDirection : OMINULL_DIR_OUTBOUND;

            if (inMetaValues->currentFields & FWPS_METADATA_FIELD_PROCESS_ID) {
                flowCtx->ProcessId = inMetaValues->processId;
            }

            FWP_BYTE_BLOB* appBlob = NULL;
            if (inFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_ALE_APP_ID].value.type == FWP_BYTE_BLOB_TYPE) {
                appBlob = inFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_ALE_APP_ID].value.byteBlob;
            }
            OminullExtractAppPath(appBlob, inMetaValues, flowCtx->ProcessPath, OMINULL_MAX_PATH);
            KeQuerySystemTime(&flowCtx->CreationTime);

            NTSTATUS status = FwpsFlowAssociateContext0(
                flowHandle,
                inFixedValues->layerId,
                g_GlobalData.CalloutIds[LAYER_IDX_FLOW_EST_V4],
                (UINT64)flowCtx
            );

            if (NT_SUCCESS(status)) {
                KIRQL oldIrql;
                KeAcquireSpinLock(&g_GlobalData.PolicyLock, &oldIrql);
                g_GlobalData.Stats.TotalFlowsEstablished++;
                g_GlobalData.Stats.TotalFlowsActive++;
                KeReleaseSpinLock(&g_GlobalData.PolicyLock, oldIrql);

                OMINULL_EVENT ev;
                RtlZeroMemory(&ev, sizeof(ev));
                ev.Timestamp = (UINT64)flowCtx->CreationTime.QuadPart;
                ev.EventType = OMINULL_EVENT_FLOW_ESTABLISHED_V4;
                ev.Action = 0;
                ev.ProcessId = flowCtx->ProcessId;
                ev.IpVersion = 4;
                ev.Protocol = flowCtx->Protocol;
                ev.Direction = flowCtx->Direction;
                ev.LocalPort = flowCtx->LocalPort;
                ev.RemotePort = flowCtx->RemotePort;
                ev.Addr.Ipv4.LocalIp = flowCtx->Addr.Ipv4.LocalIp;
                ev.Addr.Ipv4.RemoteIp = flowCtx->Addr.Ipv4.RemoteIp;
                ev.FlowId = flowHandle;
                RtlCopyMemory(ev.ProcessPath, flowCtx->ProcessPath, sizeof(ev.ProcessPath));
                OminullEmitEvent(&ev);

                DbgPrint("[ominull] FLOW_ESTABLISHED V4: FlowId=%llu PID=%llu Proto=%u %u.%u.%u.%u:%u -> %u.%u.%u.%u:%u\n",
                    flowHandle, flowCtx->ProcessId, flowCtx->Protocol,
                    (flowCtx->Addr.Ipv4.LocalIp >> 24) & 0xFF, (flowCtx->Addr.Ipv4.LocalIp >> 16) & 0xFF,
                    (flowCtx->Addr.Ipv4.LocalIp >> 8) & 0xFF, flowCtx->Addr.Ipv4.LocalIp & 0xFF, flowCtx->LocalPort,
                    (flowCtx->Addr.Ipv4.RemoteIp >> 24) & 0xFF, (flowCtx->Addr.Ipv4.RemoteIp >> 16) & 0xFF,
                    (flowCtx->Addr.Ipv4.RemoteIp >> 8) & 0xFF, flowCtx->Addr.Ipv4.RemoteIp & 0xFF, flowCtx->RemotePort);
            } else {
                ExFreePoolWithTag(flowCtx, OMINULL_TAG);
            }
        }
    }
}

// Classify: ALE Flow Established V6 (Context Tracking)
void NTAPI
OminullClassifyFlowEstV6(
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
    UNREFERENCED_PARAMETER(filter);

    if (!classifyOut) {
        return;
    }
    classifyOut->actionType = FWP_ACTION_CONTINUE;

    if (!inFixedValues || !inMetaValues) {
        return;
    }

    if (flowContext == 0 && (inMetaValues->currentFields & FWPS_METADATA_FIELD_FLOW_HANDLE)) {
        UINT64 flowHandle = inMetaValues->flowHandle;

        POMINULL_FLOW_CONTEXT flowCtx = (POMINULL_FLOW_CONTEXT)ExAllocatePoolWithTag(
            NonPagedPool, sizeof(OMINULL_FLOW_CONTEXT), OMINULL_TAG
        );

        if (flowCtx != NULL) {
            RtlZeroMemory(flowCtx, sizeof(OMINULL_FLOW_CONTEXT));
            flowCtx->FlowId = flowHandle;
            flowCtx->IpVersion = 6;
            flowCtx->Protocol = inFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_PROTOCOL].value.uint8;
            flowCtx->LocalPort = inFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_LOCAL_PORT].value.uint16;
            flowCtx->RemotePort = inFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_REMOTE_PORT].value.uint16;

            if (inFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_LOCAL_ADDRESS].value.type == FWP_BYTE_ARRAY16_TYPE &&
                inFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_LOCAL_ADDRESS].value.byteArray16) {
                RtlCopyMemory(flowCtx->Addr.Ipv6.LocalIp, inFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_LOCAL_ADDRESS].value.byteArray16->byteArray16, 16);
            }
            if (inFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_REMOTE_ADDRESS].value.type == FWP_BYTE_ARRAY16_TYPE &&
                inFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_REMOTE_ADDRESS].value.byteArray16) {
                RtlCopyMemory(flowCtx->Addr.Ipv6.RemoteIp, inFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_REMOTE_ADDRESS].value.byteArray16->byteArray16, 16);
            }

            flowCtx->Direction = (inMetaValues->currentFields & FWPS_METADATA_FIELD_PACKET_DIRECTION) ?
                (UINT8)inMetaValues->packetDirection : OMINULL_DIR_OUTBOUND;

            if (inMetaValues->currentFields & FWPS_METADATA_FIELD_PROCESS_ID) {
                flowCtx->ProcessId = inMetaValues->processId;
            }

            FWP_BYTE_BLOB* appBlob = NULL;
            if (inFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_ALE_APP_ID].value.type == FWP_BYTE_BLOB_TYPE) {
                appBlob = inFixedValues->incomingValue[FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_ALE_APP_ID].value.byteBlob;
            }
            OminullExtractAppPath(appBlob, inMetaValues, flowCtx->ProcessPath, OMINULL_MAX_PATH);
            KeQuerySystemTime(&flowCtx->CreationTime);

            NTSTATUS status = FwpsFlowAssociateContext0(
                flowHandle,
                inFixedValues->layerId,
                g_GlobalData.CalloutIds[LAYER_IDX_FLOW_EST_V6],
                (UINT64)flowCtx
            );

            if (NT_SUCCESS(status)) {
                KIRQL oldIrql;
                KeAcquireSpinLock(&g_GlobalData.PolicyLock, &oldIrql);
                g_GlobalData.Stats.TotalFlowsEstablished++;
                g_GlobalData.Stats.TotalFlowsActive++;
                KeReleaseSpinLock(&g_GlobalData.PolicyLock, oldIrql);

                OMINULL_EVENT ev;
                RtlZeroMemory(&ev, sizeof(ev));
                ev.Timestamp = (UINT64)flowCtx->CreationTime.QuadPart;
                ev.EventType = OMINULL_EVENT_FLOW_ESTABLISHED_V6;
                ev.Action = 0;
                ev.ProcessId = flowCtx->ProcessId;
                ev.IpVersion = 6;
                ev.Protocol = flowCtx->Protocol;
                ev.Direction = flowCtx->Direction;
                ev.LocalPort = flowCtx->LocalPort;
                ev.RemotePort = flowCtx->RemotePort;
                RtlCopyMemory(ev.Addr.Ipv6.LocalIp, flowCtx->Addr.Ipv6.LocalIp, 16);
                RtlCopyMemory(ev.Addr.Ipv6.RemoteIp, flowCtx->Addr.Ipv6.RemoteIp, 16);
                ev.FlowId = flowHandle;
                RtlCopyMemory(ev.ProcessPath, flowCtx->ProcessPath, sizeof(ev.ProcessPath));
                OminullEmitEvent(&ev);

                DbgPrint("[ominull] FLOW_ESTABLISHED V6: FlowId=%llu PID=%llu Proto=%u LocalPort=%u RemotePort=%u\n",
                    flowHandle, flowCtx->ProcessId, flowCtx->Protocol, flowCtx->LocalPort, flowCtx->RemotePort);
            } else {
                ExFreePoolWithTag(flowCtx, OMINULL_TAG);
            }
        }
    }
}

// Notification callback for filter lifecycle events
NTSTATUS NTAPI
OminullNotify(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    _In_ const GUID*              filterKey,
    _Inout_ FWPS_FILTER0*         filter
)
{
    UNREFERENCED_PARAMETER(filterKey);
    UNREFERENCED_PARAMETER(filter);

    switch (notifyType) {
    case FWPS_CALLOUT_NOTIFY_ADD_FILTER:
        DbgPrint("[ominull] NOTIFY: Filter registered on callout\n");
        break;
    case FWPS_CALLOUT_NOTIFY_DELETE_FILTER:
        DbgPrint("[ominull] NOTIFY: Filter removed from callout\n");
        break;
    default:
        break;
    }

    return STATUS_SUCCESS;
}

// Flow teardown callback
void NTAPI
OminullFlowDelete(
    _In_ UINT16 layerId,
    _In_ UINT32 calloutId,
    _In_ UINT64 flowContext
)
{
    UNREFERENCED_PARAMETER(layerId);
    UNREFERENCED_PARAMETER(calloutId);

    if (flowContext != 0) {
        POMINULL_FLOW_CONTEXT ctx = (POMINULL_FLOW_CONTEXT)flowContext;

        OMINULL_EVENT ev;
        RtlZeroMemory(&ev, sizeof(ev));
        KeQuerySystemTime((PLARGE_INTEGER)&ev.Timestamp);
        ev.EventType = OMINULL_EVENT_FLOW_CLOSED;
        ev.Action = 0;
        ev.ProcessId = ctx->ProcessId;
        ev.IpVersion = ctx->IpVersion;
        ev.Protocol = ctx->Protocol;
        ev.Direction = ctx->Direction;
        ev.LocalPort = ctx->LocalPort;
        ev.RemotePort = ctx->RemotePort;
        if (ctx->IpVersion == 4) {
            ev.Addr.Ipv4.LocalIp = ctx->Addr.Ipv4.LocalIp;
            ev.Addr.Ipv4.RemoteIp = ctx->Addr.Ipv4.RemoteIp;
        } else {
            RtlCopyMemory(ev.Addr.Ipv6.LocalIp, ctx->Addr.Ipv6.LocalIp, 16);
            RtlCopyMemory(ev.Addr.Ipv6.RemoteIp, ctx->Addr.Ipv6.RemoteIp, 16);
        }
        ev.FlowId = ctx->FlowId;
        RtlCopyMemory(ev.ProcessPath, ctx->ProcessPath, sizeof(ev.ProcessPath));
        OminullEmitEvent(&ev);

        KIRQL oldIrql;
        KeAcquireSpinLock(&g_GlobalData.PolicyLock, &oldIrql);
        if (g_GlobalData.Stats.TotalFlowsActive > 0) {
            g_GlobalData.Stats.TotalFlowsActive--;
        }
        KeReleaseSpinLock(&g_GlobalData.PolicyLock, oldIrql);

        DbgPrint("[ominull] FLOW_DELETE: Connection flow destroyed (FlowId=%llu, PID=%llu)\n",
            ctx->FlowId, ctx->ProcessId);

        ExFreePoolWithTag(ctx, OMINULL_TAG);
    }
}

// Layer configuration table for unified multi-layer registration
typedef struct _OMINULL_LAYER_CONFIG {
    const GUID*                 LayerGuid;
    const GUID*                 CalloutGuid;
    const GUID*                 FilterGuid;
    const wchar_t*              CalloutName;
    const wchar_t*              CalloutDesc;
    const wchar_t*              FilterName;
    const wchar_t*              FilterDesc;
    FWPS_CALLOUT_CLASSIFY_FN0   ClassifyFn;
    FWP_ACTION_TYPE             FilterActionType;
} OMINULL_LAYER_CONFIG;

static const OMINULL_LAYER_CONFIG g_LayerConfigs[OMINULL_LAYER_COUNT] = {
    { // 0: Connect V4
        &FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        &OMINULL_ALE_CONNECT_V4_CALLOUT_GUID,
        &OMINULL_ALE_CONNECT_V4_FILTER_GUID,
        L"OminullAleConnectV4Callout",
        L"Ominull ALE Connect V4 Callout",
        L"OminullAleConnectV4Filter",
        L"Ominull Outbound IPv4 ALE Connect Enforcement Filter",
        OminullClassifyConnectV4,
        FWP_ACTION_CALLOUT_UNKNOWN
    },
    { // 1: Connect V6
        &FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        &OMINULL_ALE_CONNECT_V6_CALLOUT_GUID,
        &OMINULL_ALE_CONNECT_V6_FILTER_GUID,
        L"OminullAleConnectV6Callout",
        L"Ominull ALE Connect V6 Callout",
        L"OminullAleConnectV6Filter",
        L"Ominull Outbound IPv6 ALE Connect Enforcement Filter",
        OminullClassifyConnectV6,
        FWP_ACTION_CALLOUT_UNKNOWN
    },
    { // 2: Recv Accept V4
        &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
        &OMINULL_ALE_RECV_ACCEPT_V4_CALLOUT_GUID,
        &OMINULL_ALE_RECV_ACCEPT_V4_FILTER_GUID,
        L"OminullAleRecvAcceptV4Callout",
        L"Ominull ALE Recv Accept V4 Callout",
        L"OminullAleRecvAcceptV4Filter",
        L"Ominull Inbound IPv4 ALE Recv Accept Enforcement Filter",
        OminullClassifyRecvAcceptV4,
        FWP_ACTION_CALLOUT_UNKNOWN
    },
    { // 3: Recv Accept V6
        &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
        &OMINULL_ALE_RECV_ACCEPT_V6_CALLOUT_GUID,
        &OMINULL_ALE_RECV_ACCEPT_V6_FILTER_GUID,
        L"OminullAleRecvAcceptV6Callout",
        L"Ominull ALE Recv Accept V6 Callout",
        L"OminullAleRecvAcceptV6Filter",
        L"Ominull Inbound IPv6 ALE Recv Accept Enforcement Filter",
        OminullClassifyRecvAcceptV6,
        FWP_ACTION_CALLOUT_UNKNOWN
    },
    { // 4: Flow Established V4
        &FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4,
        &OMINULL_ALE_FLOW_EST_V4_CALLOUT_GUID,
        &OMINULL_ALE_FLOW_EST_V4_FILTER_GUID,
        L"OminullAleFlowEstV4Callout",
        L"Ominull ALE Flow Established V4 Callout",
        L"OminullAleFlowEstV4Filter",
        L"Ominull Flow Established IPv4 Context Filter",
        OminullClassifyFlowEstV4,
        FWP_ACTION_CALLOUT_INSPECTION
    },
    { // 5: Flow Established V6
        &FWPM_LAYER_ALE_FLOW_ESTABLISHED_V6,
        &OMINULL_ALE_FLOW_EST_V6_CALLOUT_GUID,
        &OMINULL_ALE_FLOW_EST_V6_FILTER_GUID,
        L"OminullAleFlowEstV6Callout",
        L"Ominull ALE Flow Established V6 Callout",
        L"OminullAleFlowEstV6Filter",
        L"Ominull Flow Established IPv6 Context Filter",
        OminullClassifyFlowEstV6,
        FWP_ACTION_CALLOUT_INSPECTION
    }
};

// Register all 6 WFP sublayers, runtime callouts, engine callouts, and filters atomically
NTSTATUS
OminullRegisterCallouts(
    _In_ PDEVICE_OBJECT DeviceObject
)
{
    NTSTATUS status = STATUS_SUCCESS;
    FWPM_SESSION0 session = { 0 };
    FWPM_SUBLAYER0 subLayer = { 0 };
    BOOLEAN inTransaction = FALSE;

    session.displayData.name = L"OminullSession";
    session.displayData.description = L"Ominull Kernel Enforcement Session";
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;

    // 1. Register all runtime callouts with WFP kernel runtime FIRST
    for (int i = 0; i < OMINULL_LAYER_COUNT; i++) {
        FWPS_CALLOUT0 sCallout = { 0 };
        sCallout.calloutKey = *g_LayerConfigs[i].CalloutGuid;
        sCallout.classifyFn = g_LayerConfigs[i].ClassifyFn;
        sCallout.notifyFn = OminullNotify;
        sCallout.flowDeleteFn = (i == LAYER_IDX_FLOW_EST_V4 || i == LAYER_IDX_FLOW_EST_V6) ? OminullFlowDelete : NULL;

        status = FwpsCalloutRegister0(DeviceObject, &sCallout, &g_GlobalData.CalloutIds[i]);
        if (!NT_SUCCESS(status)) {
            DbgPrint("[ominull] ERROR: FwpsCalloutRegister0 failed for layer %d: 0x%08X\n", i, (UINT32)status);
            goto ErrorCleanup;
        }
        g_GlobalData.CalloutRegistered[i] = TRUE;
    }

    // 2. Open WFP filter engine
    status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_DEFAULT, NULL, &session, &g_GlobalData.EngineHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[ominull] ERROR: FwpmEngineOpen0 failed: 0x%08X\n", (UINT32)status);
        goto ErrorCleanup;
    }
    g_GlobalData.EngineOpened = TRUE;

    // 3. Begin transaction for atomic multi-layer registration
    status = FwpmTransactionBegin0(g_GlobalData.EngineHandle, 0);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[ominull] ERROR: FwpmTransactionBegin0 failed: 0x%08X\n", (UINT32)status);
        goto ErrorCleanup;
    }
    inTransaction = TRUE;

    // 4. Add custom sublayer at priority 0xFFFF
    subLayer.subLayerKey = OMINULL_SUBLAYER_GUID;
    subLayer.displayData.name = L"OminullSubLayer";
    subLayer.displayData.description = L"Ominull Enforcement SubLayer";
    subLayer.weight = 0xFFFF;

    status = FwpmSubLayerAdd0(g_GlobalData.EngineHandle, &subLayer, NULL);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[ominull] ERROR: FwpmSubLayerAdd0 failed: 0x%08X\n", (UINT32)status);
        goto ErrorCleanup;
    }
    g_GlobalData.SubLayerAdded = TRUE;

    // 5. Add callouts and filters for all 6 layers
    for (int i = 0; i < OMINULL_LAYER_COUNT; i++) {
        FWPM_CALLOUT0 mCallout = { 0 };
        mCallout.calloutKey = *g_LayerConfigs[i].CalloutGuid;
        mCallout.displayData.name = (wchar_t*)g_LayerConfigs[i].CalloutName;
        mCallout.displayData.description = (wchar_t*)g_LayerConfigs[i].CalloutDesc;
        mCallout.applicableLayer = *g_LayerConfigs[i].LayerGuid;

        status = FwpmCalloutAdd0(g_GlobalData.EngineHandle, &mCallout, NULL, NULL);
        if (!NT_SUCCESS(status)) {
            DbgPrint("[ominull] ERROR: FwpmCalloutAdd0 failed for layer %d: 0x%08X\n", i, (UINT32)status);
            goto ErrorCleanup;
        }
        g_GlobalData.CalloutAdded[i] = TRUE;

        FWPM_FILTER0 filter = { 0 };
        filter.filterKey = *g_LayerConfigs[i].FilterGuid;
        filter.layerKey = *g_LayerConfigs[i].LayerGuid;
        filter.subLayerKey = OMINULL_SUBLAYER_GUID;
        filter.displayData.name = (wchar_t*)g_LayerConfigs[i].FilterName;
        filter.displayData.description = (wchar_t*)g_LayerConfigs[i].FilterDesc;
        filter.action.type = g_LayerConfigs[i].FilterActionType;
        filter.action.calloutKey = *g_LayerConfigs[i].CalloutGuid;
        filter.weight.type = FWP_EMPTY;
        filter.numFilterConditions = 0;

        status = FwpmFilterAdd0(g_GlobalData.EngineHandle, &filter, NULL, &g_GlobalData.FilterIds[i]);
        if (!NT_SUCCESS(status)) {
            DbgPrint("[ominull] ERROR: FwpmFilterAdd0 failed for layer %d: 0x%08X\n", i, (UINT32)status);
            goto ErrorCleanup;
        }
        g_GlobalData.FilterAdded[i] = TRUE;
    }

    // 6. Commit atomic transaction
    status = FwpmTransactionCommit0(g_GlobalData.EngineHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[ominull] ERROR: FwpmTransactionCommit0 failed: 0x%08X\n", (UINT32)status);
        goto ErrorCleanup;
    }

    DbgPrint("[ominull] All %d WFP layers, callouts, and filters registered successfully\n", OMINULL_LAYER_COUNT);
    return STATUS_SUCCESS;

ErrorCleanup:
    if (inTransaction && g_GlobalData.EngineHandle != NULL) {
        FwpmTransactionAbort0(g_GlobalData.EngineHandle);
    }
    OminullUnregisterCallouts();
    return status;
}

// Unregister all WFP objects and close engine session cleanly with zero leaks
VOID
OminullUnregisterCallouts(VOID)
{
    if (g_GlobalData.EngineHandle != NULL) {
        for (int i = 0; i < OMINULL_LAYER_COUNT; i++) {
            if (g_GlobalData.FilterAdded[i]) {
                FwpmFilterDeleteById0(g_GlobalData.EngineHandle, g_GlobalData.FilterIds[i]);
                g_GlobalData.FilterAdded[i] = FALSE;
            }
        }

        for (int i = 0; i < OMINULL_LAYER_COUNT; i++) {
            if (g_GlobalData.CalloutAdded[i]) {
                FwpmCalloutDeleteByKey0(g_GlobalData.EngineHandle, g_LayerConfigs[i].CalloutGuid);
                g_GlobalData.CalloutAdded[i] = FALSE;
            }
        }

        if (g_GlobalData.SubLayerAdded) {
            FwpmSubLayerDeleteByKey0(g_GlobalData.EngineHandle, &OMINULL_SUBLAYER_GUID);
            g_GlobalData.SubLayerAdded = FALSE;
        }

        for (int i = 0; i < OMINULL_LAYER_COUNT; i++) {
            if (g_GlobalData.CalloutRegistered[i]) {
                FwpsCalloutUnregisterById0(g_GlobalData.CalloutIds[i]);
                g_GlobalData.CalloutRegistered[i] = FALSE;
            }
        }

        if (g_GlobalData.EngineOpened) {
            FwpmEngineClose0(g_GlobalData.EngineHandle);
            g_GlobalData.EngineHandle = NULL;
            g_GlobalData.EngineOpened = FALSE;
        }

        DbgPrint("[ominull] All WFP objects unregistered and engine closed cleanly\n");
    } else {
        for (int i = 0; i < OMINULL_LAYER_COUNT; i++) {
            if (g_GlobalData.CalloutRegistered[i]) {
                FwpsCalloutUnregisterById0(g_GlobalData.CalloutIds[i]);
                g_GlobalData.CalloutRegistered[i] = FALSE;
            }
        }
    }
}

// Driver unload routine
VOID
DriverUnload(
    _In_ PDRIVER_OBJECT DriverObject
)
{
    UNREFERENCED_PARAMETER(DriverObject);

    DbgPrint("[ominull] DriverUnload: initiating teardown\n");

    OminullUnregisterCallouts();
    OminullFlushPendingIrps();

    IoDeleteSymbolicLink(&g_Win32DeviceName);
    if (g_GlobalData.DeviceObject != NULL) {
        IoDeleteDevice(g_GlobalData.DeviceObject);
        g_GlobalData.DeviceObject = NULL;
    }

    DbgPrint("[ominull] DriverUnload: teardown complete, driver unloaded\n");
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

    DbgPrint("[ominull] DriverEntry: initializing ominull.sys (Dual-Stack ALE & Inverted Call Engine)\n");

    KeInitializeSpinLock(&g_GlobalData.PolicyLock);
    KeInitializeSpinLock(&g_GlobalData.TelemetryLock);
    InitializeListHead(&g_GlobalData.PendingIrpList);

    g_GlobalData.RuleCount = 0;
    g_GlobalData.NextRuleId = 0;
    g_GlobalData.EventHead = 0;
    g_GlobalData.EventTail = 0;
    g_GlobalData.EventCount = 0;
    RtlZeroMemory(g_GlobalData.Rules, sizeof(g_GlobalData.Rules));
    RtlZeroMemory(g_GlobalData.EventQueue, sizeof(g_GlobalData.EventQueue));
    RtlZeroMemory(&g_GlobalData.Stats, sizeof(g_GlobalData.Stats));

    DriverObject->DriverUnload = DriverUnload;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = OminullDispatchCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = OminullDispatchClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = OminullDispatchDeviceControl;

    RtlInitUnicodeString(&g_NtDeviceName, OMINULL_DEVICE_NAME);
    RtlInitUnicodeString(&g_Win32DeviceName, OMINULL_SYMBOLIC_NAME);

    status = IoCreateDevice(
        DriverObject,
        0,
        &g_NtDeviceName,
        OMINULL_DEVICE_TYPE,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &g_GlobalData.DeviceObject
    );

    if (!NT_SUCCESS(status)) {
        DbgPrint("[ominull] ERROR: IoCreateDevice failed: 0x%08X\n", (UINT32)status);
        return status;
    }

    status = IoCreateSymbolicLink(&g_Win32DeviceName, &g_NtDeviceName);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[ominull] ERROR: IoCreateSymbolicLink failed: 0x%08X\n", (UINT32)status);
        IoDeleteDevice(g_GlobalData.DeviceObject);
        g_GlobalData.DeviceObject = NULL;
        return status;
    }

    status = OminullRegisterCallouts(g_GlobalData.DeviceObject);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[ominull] ERROR: OminullRegisterCallouts failed: 0x%08X\n", (UINT32)status);
        IoDeleteSymbolicLink(&g_Win32DeviceName);
        IoDeleteDevice(g_GlobalData.DeviceObject);
        g_GlobalData.DeviceObject = NULL;
        return status;
    }

    DbgPrint("[ominull] DriverEntry: ominull.sys fully active across all 6 dual-stack layers\n");
    return STATUS_SUCCESS;
}

