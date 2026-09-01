#include "../include/agent.h"

#define OMINULL_DEFAULT_CA_PATH "C:\\Program Files\\Ominull\\ca.crt"
#define OMINULL_DEFAULT_PFX_PATH "C:\\Program Files\\Ominull\\client.pfx"

/* ReadKeyFile loads the device credential written beside the binary at enrolment. The
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

static void SetConfigValue(AGENT_CONFIG* config, const char* key, const char* value) {
    if (strcmp(key, "hub_url") == 0) snprintf(config->hub_url, sizeof(config->hub_url), "%s", value);
    else if (strcmp(key, "key_path") == 0 || strcmp(key, "device_credential_path") == 0) snprintf(config->key_path, sizeof(config->key_path), "%s", value);
    else if (strcmp(key, "device_credential") == 0 || strcmp(key, "api_key") == 0) snprintf(config->api_key, sizeof(config->api_key), "%s", value);
    else if (strcmp(key, "endpoint_id") == 0) snprintf(config->endpoint_id, sizeof(config->endpoint_id), "%s", value);
    else if (strcmp(key, "role_tag") == 0) snprintf(config->role_tag, sizeof(config->role_tag), "%s", value);
    else if (strcmp(key, "location_id") == 0) snprintf(config->location_id, sizeof(config->location_id), "%s", value);
    else if (strcmp(key, "ca_path") == 0) snprintf(config->ca_path, sizeof(config->ca_path), "%s", value);
    else if (strcmp(key, "client_pfx_path") == 0) snprintf(config->client_pfx_path, sizeof(config->client_pfx_path), "%s", value);
    else if (strcmp(key, "pin_hub_ca") == 0) config->pin_hub_ca = strcmp(value, "0") != 0;
    else if (strcmp(key, "allow_plaintext") == 0) config->allow_plaintext = strcmp(value, "1") == 0;
}

static bool LoadConfigFile(AGENT_CONFIG* config, const char* path) {
    FILE* file = fopen(path, "rb");
    if (!file) return false;
    char line[1024];
    while (fgets(line, sizeof(line), file)) {
        char* value = strchr(line, '=');
        if (!value) continue;
        *value++ = '\0';
        value[strcspn(value, "\r\n")] = '\0';
        if (line[0] == '#') continue;
        SetConfigValue(config, line, value);
    }
    fclose(file);
    return true;
}

static void PrintUsage(const char* prog) {
    printf("Ominull Endpoint Agent (v%s)\n", OMINULL_AGENT_VERSION);
    printf("Usage:\n");
    printf("  %s --console --hub <url> --key-file <path>   Run in foreground (interactive)\n", prog);
    printf("  %s --service --hub <url> --key-file <path>   Run under Service Control Manager\n", prog);
    printf("\nOptions:\n");
    printf("  --ca <path>          CA certificate the hub is verified against (default %s).\n", OMINULL_DEFAULT_CA_PATH);
    printf("  --key-file <path>    Read the unique device credential from a protected file.\n");
    printf("                       Enrollment writes this file; a service command\n");
    printf("                       line is readable through `sc qc` by any logged-on user.\n");
    printf("  --client-pfx <path>  PKCS#12 archive holding this endpoint's own certificate and key\n");
    printf("                       (default %s). Presented to the hub so it can\n", OMINULL_DEFAULT_PFX_PATH);
    printf("                       the client certificate adds a second matching proof.\n");
    printf("  --allow-plaintext    Permit an http:// hub. Telemetry and the device credential then cross the network in the clear.\n");
    printf("  --version            Print the version and exit.\n");
    printf("  --config <path>      Read package-owned runtime configuration from this file.\n");
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
    strcpy(config.config_path, OMINULL_DEFAULT_CONFIG_PATH);
    strcpy(config.role_tag, "workstation");
    strcpy(config.location_id, "loc-home");
    config.pin_hub_ca = true;

    DWORD hostLen = sizeof(config.hostname);
    if (!GetComputerNameA(config.hostname, &hostLen)) {
        strcpy(config.hostname, "win11-target-01");
    }
    snprintf(config.endpoint_id, sizeof(config.endpoint_id), "win11-%s", config.hostname);

    /* Observe the address, hardware address and OS once, before either the
       console or the service path takes the config. */
    Agent_DetectHostIdentity(&config);

    bool doConsole = false;
    bool doService = false;
    bool doConfigure = false;
    char nativePackage[MAX_PATH] = {0};

    for (int i = 1; i + 1 < argc; i++) {
        if (strcmp(argv[i], "--config") == 0) {
            strncpy(config.config_path, argv[i + 1], sizeof(config.config_path) - 1);
            break;
        }
    }
    LoadConfigFile(&config, config.config_path);

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--console") == 0) {
            doConsole = true;
        } else if (strcmp(argv[i], "--service") == 0) {
            doService = true;
        } else if (strcmp(argv[i], "--configure-stdin") == 0) {
            doConfigure = true;
        } else if (strcmp(argv[i], "--apply-msi") == 0 && i + 1 < argc) {
            strncpy(nativePackage, argv[++i], sizeof(nativePackage) - 1);
        } else if (strcmp(argv[i], "--config") == 0 && i + 1 < argc) {
            strncpy(config.config_path, argv[++i], sizeof(config.config_path) - 1);
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
        } else if (strcmp(argv[i], "--cf-id") == 0 || strcmp(argv[i], "--cf-secret") == 0) {
            fprintf(stderr, "[-] Cloudflare service-token authentication is not supported; use the unique device credential.\n");
            return 2;
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

    if (doConfigure) {
        return Service_ConfigureFromStdin() ? 0 : 1;
    }
	if (nativePackage[0]) {
		return Update_RunNativeInstaller(nativePackage);
	}

    // --key-file wins over --key: a registration that carries both is one being
    // migrated, and the file is the copy that is actually protected.
    if (config.key_path[0] && !ReadKeyFile(config.key_path, config.api_key, sizeof(config.api_key))) {
        fprintf(stderr, "[-] Cannot read the device credential from %s. Enrolment writes it; without it "
                        "this agent has no identity to report under.\n", config.key_path);
        return 1;
    }
	if (!config.api_key[0] || strcmp(config.api_key, "<provision-via-bootstrap>") == 0) {
		fprintf(stderr, "[-] No enrolled device credential is configured; refusing to start.\n");
		return 1;
	}

    // The package-owned service and console paths share the same explicit mode
    // flag; native package rollback handles replacement failures before this
    // process starts.
    if (doConsole || doService) {
        config.is_service = doService;
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
			if (config.pin_hub_ca) {
				printf("[*] Hub trust: TLS, pinned to %s\n", config.ca_path);
			} else {
				printf("[*] Hub trust: TLS, Windows machine certificate store\n");
			}
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
