#ifndef OMINULL_DPI_H
#define OMINULL_DPI_H

#if defined(_KERNEL_MODE) || defined(NTDDI_VERSION)
#include <ntddk.h>
#endif

#define OMINULL_MAX_DOMAIN_LEN 256

// DPI Inspection Results
typedef struct _OMINULL_DPI_RESULT {
    BOOLEAN Identified;
    UINT8   ProtocolType; // 1 = TLS (SNI), 2 = HTTP (Host), 3 = DNS (Query)
    CHAR    DomainName[OMINULL_MAX_DOMAIN_LEN];
    UINT16  DomainNameLen;
} OMINULL_DPI_RESULT, *POMINULL_DPI_RESULT;

// Parsing functions
BOOLEAN OminullDpiParseTlsSni(
    _In_reads_bytes_(Length) const UINT8* Buffer,
    _In_ SIZE_T Length,
    _Out_ POMINULL_DPI_RESULT Result
);

BOOLEAN OminullDpiParseHttpHost(
    _In_reads_bytes_(Length) const UINT8* Buffer,
    _In_ SIZE_T Length,
    _Out_ POMINULL_DPI_RESULT Result
);

BOOLEAN OminullDpiParseDnsQuery(
    _In_reads_bytes_(Length) const UINT8* Buffer,
    _In_ SIZE_T Length,
    _Out_ POMINULL_DPI_RESULT Result
);

BOOLEAN OminullDpiInspectPayload(
    _In_reads_bytes_(Length) const UINT8* Buffer,
    _In_ SIZE_T Length,
    _In_ UINT16 Port,
    _Out_ POMINULL_DPI_RESULT Result
);

#endif // OMINULL_DPI_H
