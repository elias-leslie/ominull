#include "../include/agent.h"

#define OMINULL_DEFAULT_CA_PATH "C:\\Program Files\\Ominull\\ca.crt"
#define OMINULL_DEFAULT_PFX_PATH "C:\\Program Files\\Ominull\\client.pfx"

/* ReadKeyFile loads the API key written beside the binary at enrolment. The
 * file holds the key and nothing else; trailing whitespace is tolerated because
 * an operator repairing one by hand will leave a newline behind. */
static bool ReadKeyFile(const char* path, char* out, size_t cap) {
    FILE* f = fopen(path, "rb");
    if (!f) return false;
    size_t n = fread(out, 1, cap - 1, f);
    int truncated = (n == cap - 1) && (fgetc(f) != EOF);
    fclose(f);
    out[n] = '\0';
    while (n > 0 && (unsigned char)out[n - 1] <= ' ') out[--n] = '\0';
    if (truncated) {
        fprintf(stderr, "[-] The key in %s is longer than this agent can hold; refusing a "
                        "truncated key rather than failing authentication later.\n", path);
        return false;
    }
    return n > 0;
}

static void PrintUsage(const char* prog) {
    printf("Ominull Endpoint Agent (v%s)\n", OMINULL_AGENT_VERSION);
    printf("Usage:\n");
    printf("  %s --console --hub <url> --key <api_key>   Run in foreground (interactive)\n", prog);
    printf("  %s --service --hub <url> --key <api_key>   Run under Service Control Manager\n", prog);
    printf("  %s --install --hub <url> --key <api_key>   Install Windows Service\n", prog);
    printf("  %s --uninstall                             Uninstall Windows Service\n", prog);
    printf("  %s --restart-service                       Wait for the service to stop, then start it\n", prog);
    printf("                                             (internal: how self-update restarts itself)\n");
    printf("\nOptions:\n");
    printf("  --ca <path>          CA certificate the hub is verified against (default %s).\n", OMINULL_DEFAULT_CA_PATH);
    printf("  --key-file <path>    Read the API key from a file instead of the command line.\n");
    printf("                       --install rewrites --key into this form; a service command\n");
    printf("                       line is readable through `sc qc` by any logged-on user.\n");
    printf("  --client-pfx <path>  PKCS#12 archive holding this endpoint's own certificate and key\n");
    printf("                       (default %s). Presented to the hub so it can\n", OMINULL_DEFAULT_PFX_PATH);
    printf("                       tell this endpoint from any other holding the same tenant key.\n");
    printf("  --allow-plaintext    Permit an http:// hub. Telemetry and the API key then cross the network in the clear.\n");
    printf("  --version            Print the version and exit.\n");
}

int main(int argc, char* argv[]) {
    /* Line-buffered, like the Linux daemon. Block buffering is the default when
     * stdout is not a console, which is every way this agent is ever actually
     * read: a service redirect, an SSH pipe, a support transcript. A probe that
     * is stopped before 4 KB has accumulated prints nothing at all, so the
     * absence of an error line has meant nothing - and that is exactly the
     * condition anyone reads this log in.
     *
     * Unbuffered, not line-buffered: the Microsoft CRT accepts _IOLBF and then
     * treats it as full buffering, so asking for lines here would have looked
     * correct and changed nothing. */
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    AGENT_CONFIG config;
    ZeroMemory(&config, sizeof(config));
    strcpy(config.hub_url, "https://10.0.0.58:9443");
    strcpy(config.api_key, "<provision-via-bootstrap>");
    strcpy(config.ca_path, OMINULL_DEFAULT_CA_PATH);
    strcpy(config.client_pfx_path, OMINULL_DEFAULT_PFX_PATH);
    strcpy(config.role_tag, "workstation");
    strcpy(config.location_id, "loc-home");

    DWORD hostLen = sizeof(config.hostname);
    if (!GetComputerNameA(config.hostname, &hostLen)) {
        strcpy(config.hostname, "win11-target-01");
    }
    snprintf(config.endpoint_id, sizeof(config.endpoint_id), "win11-%s", config.hostname);

    /* Observe the address, hardware address and OS once, before either the
       console or the service path takes the config. */
    Agent_DetectHostIdentity(&config);

    bool doInstall = false;
    bool doUninstall = false;
    bool doConsole = false;
    bool doService = false;
    bool doRestart = false;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--install") == 0) {
            doInstall = true;
        } else if (strcmp(argv[i], "--uninstall") == 0) {
            doUninstall = true;
        } else if (strcmp(argv[i], "--console") == 0) {
            doConsole = true;
        } else if (strcmp(argv[i], "--service") == 0) {
            doService = true;
        } else if (strcmp(argv[i], "--restart-service") == 0) {
            doRestart = true;
        } else if (strcmp(argv[i], "--hub") == 0 && i + 1 < argc) {
            strncpy(config.hub_url, argv[++i], sizeof(config.hub_url) - 1);
        } else if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) {
            strncpy(config.api_key, argv[++i], sizeof(config.api_key) - 1);
        } else if (strcmp(argv[i], "--id") == 0 && i + 1 < argc) {
            strncpy(config.endpoint_id, argv[++i], sizeof(config.endpoint_id) - 1);
        } else if (strcmp(argv[i], "--role") == 0 && i + 1 < argc) {
            strncpy(config.role_tag, argv[++i], sizeof(config.role_tag) - 1);
        } else if (strcmp(argv[i], "--location") == 0 && i + 1 < argc) {
            strncpy(config.location_id, argv[++i], sizeof(config.location_id) - 1);
        } else if (strcmp(argv[i], "--cf-id") == 0 && i + 1 < argc) {
            strncpy(config.cf_client_id, argv[++i], sizeof(config.cf_client_id) - 1);
        } else if (strcmp(argv[i], "--cf-secret") == 0 && i + 1 < argc) {
            strncpy(config.cf_client_secret, argv[++i], sizeof(config.cf_client_secret) - 1);
        } else if (strcmp(argv[i], "--ca") == 0 && i + 1 < argc) {
            strncpy(config.ca_path, argv[++i], sizeof(config.ca_path) - 1);
        } else if (strcmp(argv[i], "--client-pfx") == 0 && i + 1 < argc) {
            strncpy(config.client_pfx_path, argv[++i], sizeof(config.client_pfx_path) - 1);
        } else if (strcmp(argv[i], "--key-file") == 0 && i + 1 < argc) {
            strncpy(config.key_path, argv[++i], sizeof(config.key_path) - 1);
        } else if (strcmp(argv[i], "--allow-plaintext") == 0) {
            config.allow_plaintext = true;
        } else if (strcmp(argv[i], "--verbose") == 0 || strcmp(argv[i], "-v") == 0) {
            config.verbose = true;
        } else if (strcmp(argv[i], "--version") == 0) {
            printf("%s\n", OMINULL_AGENT_VERSION);
            return 0;
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            PrintUsage(argv[0]);
            return 0;
        } else {
            /* Unrecognised arguments stop the agent instead of being ignored.
             *
             * Ignoring one meant `ominulld.exe --version` - not an option until
             * now - started a full agent under the compiled-in defaults, with
             * no service supervising it. An option missing its value lands here
             * too, so --key-file with nothing after it stops rather than
             * running on with the placeholder key. */
            fprintf(stderr, "[-] %s: unrecognised argument, or an option missing its value.\n", argv[i]);
            fprintf(stderr, "    Nothing was started. Run with --help for the accepted options.\n");
            return 2;
        }
    }

    // --key-file wins over --key: a registration that carries both is one being
    // migrated, and the file is the copy that is actually protected.
    if (config.key_path[0] && !ReadKeyFile(config.key_path, config.api_key, sizeof(config.api_key))) {
        fprintf(stderr, "[-] Cannot read the API key from %s. Enrolment writes it; without it "
                        "this agent has no identity to report under.\n", config.key_path);
        return 1;
    }

    // The restart helper runs as a detached child of a service that is exiting,
    // and does nothing but bring that service back. It is checked before every
    // other mode so a stray --service or --hub on its command line could never
    // start a second agent alongside the one it is restarting.
    if (doRestart) {
        return Service_WaitStoppedAndStart();
    }

    if (doInstall) {
        return Service_Install(&config) ? 0 : 1;
    }

    if (doUninstall) {
        return Service_Uninstall() ? 0 : 1;
    }

    // Runs before either mode starts: if this process is the result of an
    // update, retire the previous binary; if a new build keeps failing to come
    // back, put the previous one back instead.
    if (doConsole || doService) {
        // Set before the check, not in Service_SetConfig afterwards: a rollback
        // in Update_CheckStartup restarts the service, and it needs to know
        // whether there is a service to restart.
        config.is_service = doService;
        Update_CheckStartup(&config);
    }

    if (doConsole) {
        printf("[*] Starting Ominull Agent in Console Mode (PID: %lu)...\n", GetCurrentProcessId());
        /* The key is not echoed. This is the interactive path, so the line
         * lands wherever the operator redirected the console - and a support
         * transcript is the last place the fleet's tenant credential should
         * end up. Where it came from is the part that is actually diagnostic. */
        printf("[*] Connecting to Hub at: %s (key: %s)\n", config.hub_url,
               config.key_path[0] ? config.key_path : "supplied on the command line");
        if (Hub_UsesTLS(&config)) {
            printf("[*] Hub trust: TLS, pinned to %s\n", config.ca_path);
        } else {
            printf("[*] Hub trust: NONE - cleartext transport%s\n",
                   config.allow_plaintext ? " (--allow-plaintext)" : " (will refuse to report)");
        }
        RunAgentLoop(&config);
        return 0;
    }

    if (doService) {
        Service_SetConfig(&config);
        Service_Run();
        return 0;
    }

    PrintUsage(argv[0]);
    return 1;
}
