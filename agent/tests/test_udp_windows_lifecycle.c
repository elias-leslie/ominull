#include <ws2tcpip.h>
#define OMINULL_UDP_OWNER L"LifecycleProbe"
#include "../windows/udp_collector.h"
int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    DWORD status = UDPWinStart();
    printf("start=%lu session=%ls\n", status, g_UDPWinProperties.name);
    if (status) {
        UDPWinStop();
        return 1;
    }
    if (argc == 2 && !strcmp(argv[1], "crash"))
        ExitProcess(0);
    if (argc == 2 && !strcmp(argv[1], "hold"))
        Sleep(10000);
    OMINULL_EVENT event;
    UDPWinDrain(&event, 1);
    UDPWinTransportLost(&event, 0);
    char health[512];
    UDPWinHealthJSON(health, sizeof(health));
    UDPWinStop();
    return 0;
}
