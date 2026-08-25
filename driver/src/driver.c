#include "driver.h"

VOID
DriverUnload(
    _In_ PDRIVER_OBJECT DriverObject
)
{
    UNREFERENCED_PARAMETER(DriverObject);

    DbgPrint("[wfpsentinel] DriverUnload: unloading driver cleanly\n");
}

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrint("[wfpsentinel] DriverEntry: initializing wfpsentinel.sys\n");

    // Register driver unload callback for clean teardown via sc.exe stop
    DriverObject->DriverUnload = DriverUnload;

    DbgPrint("[wfpsentinel] DriverEntry: driver loaded successfully\n");

    return STATUS_SUCCESS;
}
