#ifndef WFPSENTINEL_DRIVER_H
#define WFPSENTINEL_DRIVER_H

#include <ntddk.h>
#include <wdf.h>

#define WFPSENTINEL_POOL_TAG 'StnW'

// Function Declarations
DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_DEVICE_ADD EchoEvtDeviceAdd;
EVT_WDF_DRIVER_UNLOAD EchoEvtDriverUnload;

#endif // WFPSENTINEL_DRIVER_H
