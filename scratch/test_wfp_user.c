#include <windows.h>
#include <fwpmu.h>
#include <stdio.h>

int main() {
    HANDLE hEngine = NULL;
    DWORD result = FwpmEngineOpen0(NULL, RPC_C_AUTHN_DEFAULT, NULL, NULL, &hEngine);
    printf("FwpmEngineOpen0 result: %lu\n", (unsigned long)result);
    if (hEngine) {
        FwpmEngineClose0(hEngine);
    }
    return 0;
}
