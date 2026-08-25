#ifndef WFP_KERNEL_H
#define WFP_KERNEL_H

#include <ntddk.h>

// Forward declarations & opaque pointers
typedef void* PSID;
typedef struct _SEC_WINNT_AUTH_IDENTITY_W SEC_WINNT_AUTH_IDENTITY_W;
typedef struct FWPM_SESSION0_ FWPM_SESSION0;
typedef struct FWPM_SUBLAYER0_ FWPM_SUBLAYER0;
typedef struct FWPM_CALLOUT0_ FWPM_CALLOUT0;
typedef struct FWPM_FILTER0_ FWPM_FILTER0;
typedef struct FWPS_CALLOUT0_ FWPS_CALLOUT0;
typedef struct FWPS_INCOMING_VALUES0_ FWPS_INCOMING_VALUES0;
typedef struct FWPS_INCOMING_METADATA_VALUES0_ FWPS_INCOMING_METADATA_VALUES0;
typedef struct FWPS_CLASSIFY_OUT0_ FWPS_CLASSIFY_OUT0;
typedef struct FWPS_FILTER0_ FWPS_FILTER0;

// WFP Action Flags & Types (UINT32)
typedef UINT32 FWP_ACTION_TYPE;
#define FWP_ACTION_FLAG_TERMINATING     (0x00001000)
#define FWP_ACTION_FLAG_NON_TERMINATING (0x00002000)
#define FWP_ACTION_FLAG_CALLOUT         (0x00004000)

#define FWP_ACTION_BLOCK                (0x00000001 | FWP_ACTION_FLAG_TERMINATING)
#define FWP_ACTION_PERMIT               (0x00000002 | FWP_ACTION_FLAG_TERMINATING)
#define FWP_ACTION_CALLOUT_TERMINATING  (0x00000003 | FWP_ACTION_FLAG_CALLOUT | FWP_ACTION_FLAG_TERMINATING)
#define FWP_ACTION_CALLOUT_INSPECTION   (0x00000004 | FWP_ACTION_FLAG_CALLOUT | FWP_ACTION_FLAG_NON_TERMINATING)
#define FWP_ACTION_CALLOUT_UNKNOWN      (0x00000005 | FWP_ACTION_FLAG_CALLOUT)
#define FWP_ACTION_CONTINUE             (0x00000006 | FWP_ACTION_FLAG_NON_TERMINATING)
#define FWP_ACTION_NONE                 (0x00000007)
#define FWP_ACTION_NONE_NO_MATCH        (0x00000008)

typedef UINT32 FWP_DATA_TYPE;
#define FWP_EMPTY            0
#define FWP_UINT8            1
#define FWP_UINT16           2
#define FWP_UINT32           3
#define FWP_UINT64           4
#define FWP_INT8             5
#define FWP_INT16            6
#define FWP_INT32            7
#define FWP_INT64            8
#define FWP_FLOAT            9
#define FWP_DOUBLE           10
#define FWP_BYTE_ARRAY16_TYPE 11
#define FWP_BYTE_BLOB_TYPE   12
#define FWP_SID              13
#define FWP_SECURITY_DESCRIPTOR_TYPE 14
#define FWP_TOKEN_INFORMATION_TYPE 15
#define FWP_TOKEN_ACCESS_INFORMATION_TYPE 16
#define FWP_UNICODE_STRING_TYPE 17
#define FWP_BYTE_ARRAY6_TYPE 18

typedef struct FWP_BYTE_BLOB_ {
    UINT32 size;
    UINT8* data;
} FWP_BYTE_BLOB;

typedef struct FWP_BYTE_ARRAY16_ {
    UINT8 byteArray16[16];
} FWP_BYTE_ARRAY16;

typedef struct FWP_VALUE0_ {
    FWP_DATA_TYPE type;
    union {
        UINT8 uint8;
        UINT16 uint16;
        UINT32 uint32;
        UINT64* uint64;
        INT8 int8;
        INT16 int16;
        INT32 int32;
        INT64* int64;
        float float32;
        double* double64;
        FWP_BYTE_ARRAY16* byteArray16;
        FWP_BYTE_BLOB* byteBlob;
        PSID sid;
        FWP_BYTE_BLOB* sd;
        FWP_BYTE_BLOB* tokenInformation;
        FWP_BYTE_BLOB* tokenAccessInformation;
        LPWSTR unicodeString;
    };
} FWP_VALUE0;

typedef struct FWPM_DISPLAY_DATA0_ {
    wchar_t* name;
    wchar_t* description;
} FWPM_DISPLAY_DATA0;

// Session flags
#define FWPM_SESSION_FLAG_DYNAMIC (0x00000001)

struct FWPM_SESSION0_ {
    GUID sessionKey;
    FWPM_DISPLAY_DATA0 displayData;
    UINT32 flags;
    UINT32 txnWaitTimeoutInMSec;
    UINT32 processId;
    PSID sid;
    wchar_t* username;
    BOOLEAN kernelMode;
};

// SubLayer
struct FWPM_SUBLAYER0_ {
    GUID subLayerKey;
    FWPM_DISPLAY_DATA0 displayData;
    UINT32 flags;
    GUID* providerKey;
    FWP_BYTE_BLOB providerData;
    UINT16 weight;
};

// Callout
typedef enum FWPS_CALLOUT_NOTIFY_TYPE_ {
    FWPS_CALLOUT_NOTIFY_ADD_FILTER,
    FWPS_CALLOUT_NOTIFY_DELETE_FILTER,
    FWPS_CALLOUT_NOTIFY_TYPE_MAX
} FWPS_CALLOUT_NOTIFY_TYPE;

typedef struct FWPS_INCOMING_VALUE0_ {
    FWP_VALUE0 value;
} FWPS_INCOMING_VALUE0;

typedef struct FWPS_INCOMING_VALUES0_ {
    UINT16 layerId;
    UINT32 valueCount;
    FWPS_INCOMING_VALUE0* incomingValue;
} FWPS_INCOMING_VALUES0;

#define FWPS_METADATA_FIELD_FLOW_HANDLE                (0x00000001)
#define FWPS_METADATA_FIELD_SYSTEM_FLAGS               (0x00000002)
#define FWPS_METADATA_FIELD_PROCESS_ID                 (0x00000004)
#define FWPS_METADATA_FIELD_PROCESS_PATH               (0x00000008)
#define FWPS_METADATA_FIELD_TOKEN                      (0x00000010)
#define FWPS_METADATA_FIELD_SOURCE_INTERFACE_INDEX     (0x00000020)
#define FWPS_METADATA_FIELD_DESTINATION_INTERFACE_INDEX (0x00000040)
#define FWPS_METADATA_FIELD_COMPARTMENT_ID             (0x00000080)
#define FWPS_METADATA_FIELD_TRANSPORT_ENDPOINT_HANDLE  (0x00000100)
#define FWPS_METADATA_FIELD_TRANSPORT_CONTROL_DATA     (0x00000200)
#define FWPS_METADATA_FIELD_REMOTE_SCOPE_ID            (0x00000400)
#define FWPS_METADATA_FIELD_PACKET_DIRECTION           (0x00000800)

typedef struct FWPS_INCOMING_METADATA_VALUES0_ {
    UINT32 currentFields;
    UINT32 flags;
    UINT64 reserved;
    UINT64 flowHandle;
    UINT32 systemFlags;
    UINT64 processId;
    FWP_BYTE_BLOB* processPath;
    HANDLE token;
    UINT32 sourceInterfaceIndex;
    UINT32 destinationInterfaceIndex;
    UINT32 compartmentId;
    UINT64 transportEndpointHandle;
    FWP_BYTE_BLOB* transportControlData;
    UINT32 remoteScopeId;
    UINT32 packetDirection;
} FWPS_INCOMING_METADATA_VALUES0;

#define FWPS_RIGHT_ACTION_WRITE (0x00000001)

typedef struct FWPS_CLASSIFY_OUT0_ {
    FWP_ACTION_TYPE actionType;
    UINT64 outContext;
    UINT64 filterId;
    UINT32 rights;
    UINT32 flags;
} FWPS_CLASSIFY_OUT0;

typedef struct FWPS_FILTER_CONDITION0_ {
    UINT16 fieldId;
    UINT16 matchType;
    void* conditionValue;
} FWPS_FILTER_CONDITION0;

typedef struct FWPS_ACTION0_ {
    FWP_ACTION_TYPE type;
    UINT32 calloutId;
} FWPS_ACTION0;

#define FWPS_FILTER_FLAG_CLEAR_ACTION_RIGHT (0x0001)

struct FWPS_FILTER0_ {
    UINT64 filterId;
    FWP_VALUE0 weight;
    UINT16 subLayerWeight;
    UINT16 flags;
    UINT32 numFilterConditions;
    FWPS_FILTER_CONDITION0* filterCondition;
    FWPS_ACTION0 action;
    UINT64 context;
    GUID* reserved;
    UINT64 providerContext;
};

typedef void (NTAPI *FWPS_CALLOUT_CLASSIFY_FN0)(
    _In_ const FWPS_INCOMING_VALUES0* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER0* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* classifyOut
);

typedef NTSTATUS (NTAPI *FWPS_CALLOUT_NOTIFY_FN0)(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    _In_ const GUID* filterKey,
    _Inout_ FWPS_FILTER0* filter
);

typedef void (NTAPI *FWPS_CALLOUT_FLOW_DELETE_NOTIFY_FN0)(
    _In_ UINT16 layerId,
    _In_ UINT32 calloutId,
    _In_ UINT64 flowContext
);

struct FWPS_CALLOUT0_ {
    GUID calloutKey;
    UINT32 flags;
    FWPS_CALLOUT_CLASSIFY_FN0 classifyFn;
    FWPS_CALLOUT_NOTIFY_FN0 notifyFn;
    FWPS_CALLOUT_FLOW_DELETE_NOTIFY_FN0 flowDeleteFn;
};

struct FWPM_CALLOUT0_ {
    GUID calloutKey;
    FWPM_DISPLAY_DATA0 displayData;
    UINT32 flags;
    GUID* providerKey;
    FWP_BYTE_BLOB providerData;
    GUID applicableLayer;
    UINT32 calloutId;
};

// Filter Condition & Action
typedef UINT32 FWP_MATCH_TYPE;
#define FWP_MATCH_EQUAL 0

typedef struct FWPM_ACTION0_ {
    FWP_ACTION_TYPE type;
    union {
        GUID filterType;
        GUID calloutKey;
    };
} FWPM_ACTION0;

typedef struct FWPM_FILTER_CONDITION0_ {
    GUID fieldKey;
    FWP_MATCH_TYPE matchType;
    void* conditionValue;
} FWPM_FILTER_CONDITION0;

struct FWPM_FILTER0_ {
    GUID filterKey;
    FWPM_DISPLAY_DATA0 displayData;
    UINT32 flags;
    GUID* providerKey;
    FWP_BYTE_BLOB providerData;
    GUID layerKey;
    GUID subLayerKey;
    FWP_VALUE0 weight;
    UINT32 numFilterConditions;
    FWPM_FILTER_CONDITION0* filterCondition;
    FWPM_ACTION0 action;
    union {
        UINT64 rawContext;
        GUID providerContextKey;
    };
    GUID* reserved;
    UINT64 filterId;
    FWP_VALUE0 effectiveWeight;
};

// ALE Fields
typedef enum FWPS_FIELDS_ALE_AUTH_CONNECT_V4_ {
    FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_ADDRESS,
    FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_PORT,
    FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL,
    FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS,
    FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT,
    FWPS_FIELD_ALE_AUTH_CONNECT_V4_ALE_APP_ID,
    FWPS_FIELD_ALE_AUTH_CONNECT_V4_ALE_USER_ID,
    FWPS_FIELD_ALE_AUTH_CONNECT_V4_FLAGS,
    FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_INTERFACE,
    FWPS_FIELD_ALE_AUTH_CONNECT_V4_INTERFACE_TYPE,
    FWPS_FIELD_ALE_AUTH_CONNECT_V4_TUNNEL_TYPE,
    FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_DESTINATION_ADDRESS_TYPE,
    FWPS_FIELD_ALE_AUTH_CONNECT_V4_MAX
} FWPS_FIELDS_ALE_AUTH_CONNECT_V4;

// Well-known WFP Layer GUIDs
// FWPM_LAYER_ALE_AUTH_CONNECT_V4: {c38d57d1-05a7-4c33-904f-7fbceee60e82}
static const GUID FWPM_LAYER_ALE_AUTH_CONNECT_V4 = {
    0xc38d57d1, 0x05a7, 0x4c33, { 0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82 }
};

// FWPM_LAYER_ALE_AUTH_CONNECT_V6: {4a72393b-319f-44bc-84c3-ba54dcb3b6b4}
static const GUID FWPM_LAYER_ALE_AUTH_CONNECT_V6 = {
    0x4a72393b, 0x319f, 0x44bc, { 0x84, 0xc3, 0xba, 0x54, 0xdc, 0xb3, 0xb6, 0xb4 }
};

// WfpSentinel Custom GUIDs
// Sublayer GUID: {d9e5c461-5f87-4f2c-93d0-6e8a947c8240}
static const GUID WFPSENTINEL_SUBLAYER_GUID = {
    0xd9e5c461, 0x5f87, 0x4f2c, { 0x93, 0xd0, 0x6e, 0x8a, 0x94, 0x7c, 0x82, 0x40 }
};

// Callout GUID: {d9e5c462-5f87-4f2c-93d0-6e8a947c8241}
static const GUID WFPSENTINEL_ALE_CONNECT_CALLOUT_GUID = {
    0xd9e5c462, 0x5f87, 0x4f2c, { 0x93, 0xd0, 0x6e, 0x8a, 0x94, 0x7c, 0x82, 0x41 }
};

// Filter GUID: {d9e5c463-5f87-4f2c-93d0-6e8a947c8242}
static const GUID WFPSENTINEL_ALE_CONNECT_FILTER_GUID = {
    0xd9e5c463, 0x5f87, 0x4f2c, { 0x93, 0xd0, 0x6e, 0x8a, 0x94, 0x7c, 0x82, 0x42 }
};

// WFP Kernel-Mode Function Prototypes (exported by fwpkclnt.sys)
NTSTATUS NTAPI FwpmEngineOpen0(
    _In_opt_ const wchar_t* serverName,
    _In_ UINT32 authnService,
    _In_opt_ SEC_WINNT_AUTH_IDENTITY_W* authIdentity,
    _In_opt_ const FWPM_SESSION0* session,
    _Out_ HANDLE* engineHandle
);

NTSTATUS NTAPI FwpmEngineClose0(
    _Inout_ HANDLE engineHandle
);

NTSTATUS NTAPI FwpmTransactionBegin0(
    _In_ HANDLE engineHandle,
    _In_ UINT32 flags
);

NTSTATUS NTAPI FwpmTransactionCommit0(
    _In_ HANDLE engineHandle
);

NTSTATUS NTAPI FwpmTransactionAbort0(
    _In_ HANDLE engineHandle
);

NTSTATUS NTAPI FwpmSubLayerAdd0(
    _In_ HANDLE engineHandle,
    _In_ const FWPM_SUBLAYER0* subLayer,
    _In_opt_ PSECURITY_DESCRIPTOR sd
);

NTSTATUS NTAPI FwpmSubLayerDeleteByKey0(
    _In_ HANDLE engineHandle,
    _In_ const GUID* key
);

NTSTATUS NTAPI FwpsCalloutRegister0(
    _Inout_ void* deviceObject,
    _In_ const FWPS_CALLOUT0* callout,
    _Out_opt_ UINT32* calloutId
);

NTSTATUS NTAPI FwpsCalloutUnregisterById0(
    _In_ const UINT32 id
);

NTSTATUS NTAPI FwpmCalloutAdd0(
    _In_ HANDLE engineHandle,
    _In_ const FWPM_CALLOUT0* callout,
    _In_opt_ PSECURITY_DESCRIPTOR sd,
    _Out_opt_ UINT32* id
);

NTSTATUS NTAPI FwpmCalloutDeleteById0(
    _In_ HANDLE engineHandle,
    _In_ UINT32 id
);

NTSTATUS NTAPI FwpmFilterAdd0(
    _In_ HANDLE engineHandle,
    _In_ const FWPM_FILTER0* filter,
    _In_opt_ PSECURITY_DESCRIPTOR sd,
    _Out_opt_ UINT64* id
);

NTSTATUS NTAPI FwpmFilterDeleteById0(
    _In_ HANDLE engineHandle,
    _In_ UINT64 id
);

#endif // WFP_KERNEL_H
