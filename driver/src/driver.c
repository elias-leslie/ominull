#include "driver.h"

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    NTSTATUS status = STATUS_SUCCESS;
    WDF_DRIVER_CONFIG config;
    WDFDRIVER hDriver;

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, 
        "[wfpsentinel] DriverEntry: initializing KMDF driver\n"));

    WDF_DRIVER_CONFIG_INIT(&config, EchoEvtDeviceAdd);
    config.EvtDriverUnload = EchoEvtDriverUnload;

    status = WdfDriverCreate(
        DriverObject,
        RegistryPath,
        WDF_NO_OBJECT_ATTRIBUTES,
        &config,
        &hDriver
    );

    if (!NT_SUCCESS(status)) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
            "[wfpsentinel] WdfDriverCreate failed with status 0x%08X\n", status));
        return status;
    }

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, 
        "[wfpsentinel] DriverEntry: successfully created KMDF driver object\n"));

    return status;
}

NTSTATUS
EchoEvtDeviceAdd(
    _In_    WDFDRIVER       Driver,
    _Inout_ PWDFDEVICE_INIT DeviceInit
)
{
    UNREFERENCED_PARAMETER(Driver);
    NTSTATUS status = STATUS_SUCCESS;
    WDFDEVICE device;

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, 
        "[wfpsentinel] EchoEvtDeviceAdd: creating device object\n"));

    status = WdfDeviceCreate(&DeviceInit, WDF_NO_OBJECT_ATTRIBUTES, &device);
    if (!NT_SUCCESS(status)) {
        KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
            "[wfpsentinel] WdfDeviceCreate failed with status 0x%08X\n", status));
        return status;
    }

    return status;
}

VOID
EchoEvtDriverUnload(
    _In_ WDFDRIVER Driver
)
{
    UNREFERENCED_PARAMETER(Driver);
    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, 
        "[wfpsentinel] EchoEvtDriverUnload: driver unloading cleanly\n"));
}
