#ifndef WFP_SENTINEL_DRIVER_H
#define WFP_SENTINEL_DRIVER_H

#include <ntddk.h>

#define WFPSENTINEL_TAG 'STNW' // 'WNTS' pool tag

// Driver lifecycle routines
DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnload;

#endif // WFP_SENTINEL_DRIVER_H
