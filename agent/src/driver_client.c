#include "../include/agent.h"

HANDLE Driver_Open(void) {
    HANDLE hDevice = CreateFileA(
        OMINULL_USERMODE_PATH,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    static bool loggedOnce = false;
    if (hDevice == INVALID_HANDLE_VALUE) {
        if (!loggedOnce) {
            DWORD err = GetLastError();
            if (err == ERROR_FILE_NOT_FOUND) {
                fprintf(stderr, "[-] Ominull driver device not found. Retrying in background...\n");
            } else {
                fprintf(stderr, "[-] Failed to open Ominull driver (Error: %lu)\n", err);
            }
            loggedOnce = true;
        }
        return INVALID_HANDLE_VALUE;
    }
    loggedOnce = false;

    return hDevice;
}

void Driver_Close(HANDLE hDevice) {
    if (hDevice != INVALID_HANDLE_VALUE && hDevice != NULL) {
        CloseHandle(hDevice);
    }
}

bool Driver_StreamEvents(HANDLE hDevice, OMINULL_EVENT* outEvent) {
    if (hDevice == INVALID_HANDLE_VALUE || !outEvent) {
        return false;
    }

    DWORD bytesReturned = 0;
    BOOL success = DeviceIoControl(
        hDevice,
        IOCTL_OMINULL_STREAM_EVENT,
        NULL,
        0,
        outEvent,
        sizeof(OMINULL_EVENT),
        &bytesReturned,
        NULL
    );

    return (success && bytesReturned == sizeof(OMINULL_EVENT));
}

bool Driver_SetIsolation(HANDLE hDevice, bool enable, uint32_t allowHubIP, uint16_t allowHubPort) {
    if (hDevice == INVALID_HANDLE_VALUE) {
        return false;
    }

    if (!enable) {
        DWORD bytesReturned = 0;
        BOOL success = DeviceIoControl(
            hDevice,
            IOCTL_OMINULL_CLEAR_ISOLATION_MODE,
            NULL,
            0,
            NULL,
            0,
            &bytesReturned,
            NULL
        );
        return success ? true : false;
    }

    OMINULL_ISOLATION_CONFIG config;
    ZeroMemory(&config, sizeof(config));
    config.ManagementServerIpV4 = allowHubIP;
    config.ManagementServerPort = allowHubPort;
    config.AllowDhcp = 1;
    config.AllowDns = 1;

    DWORD bytesReturned = 0;
    BOOL success = DeviceIoControl(
        hDevice,
        IOCTL_OMINULL_SET_ISOLATION_MODE,
        &config,
        sizeof(config),
        NULL,
        0,
        &bytesReturned,
        NULL
    );

    return success ? true : false;
}
