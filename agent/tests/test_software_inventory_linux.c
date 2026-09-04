/*
 * Unit test suite for Linux Authoritative Software Inventory Collector (Slice 7A).
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>

#include "software_inventory_linux.h"

static int g_tests_run = 0;
static int g_tests_failed = 0;

#define ASSERT_TRUE(expr) do { \
    g_tests_run++; \
    if (!(expr)) { \
        fprintf(stderr, "FAIL: %s:%d: assertion failed: %s\n", __FILE__, __LINE__, #expr); \
        g_tests_failed++; \
    } \
} while (0)

#define ASSERT_STR_EQ(a, b) do { \
    g_tests_run++; \
    if (strcmp((a), (b)) != 0) { \
        fprintf(stderr, "FAIL: %s:%d: strings not equal:\n  got:  \"%s\"\n  want: \"%s\"\n", __FILE__, __LINE__, (a), (b)); \
        g_tests_failed++; \
    } \
} while (0)

static void test_dpkg_status_parsing(void) {
    printf("[*] Testing dpkg status parser...\n");

    /* Create mock status file */
    char tmp_path[] = "/tmp/test_dpkg_status_XXXXXX";
    int fd = mkstemp(tmp_path);
    ASSERT_TRUE(fd >= 0);

    const char* sample_data =
        "Package: openssh-server\n"
        "Status: install ok installed\n"
        "Priority: optional\n"
        "Section: net\n"
        "Installed-Size: 1048\n"
        "Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>\n"
        "Architecture: amd64\n"
        "Version: 1:8.9p1-3ubuntu0.6\n"
        "Depends: libc6 (>= 2.34)\n"
        "Description: secure shell (SSH) server, for secure access from remote machines\n"
        "\n"
        "Package: curl\n"
        "Status: deinstall ok config-files\n"
        "Priority: optional\n"
        "Section: web\n"
        "Maintainer: Debian curl Team <team+curl@tracker.debian.org>\n"
        "Architecture: amd64\n"
        "Version: 7.81.0-1ubuntu1.15\n"
        "\n"
        "Package: nginx-common\n"
        "Status: install ok installed\n"
        "Priority: optional\n"
        "Section: httpd\n"
        "Maintainer: Debian Nginx Maintainers <pkg-nginx-maintainers@alioth-lists.debian.net>\n"
        "Architecture: all\n"
        "Version: 1.18.0-6ubuntu14.4\n"
        "\n"
        "Package: removed-tool\n"
        "Status: purge ok not-installed\n"
        "Maintainer: Some Dev <dev@example.com>\n"
        "Architecture: amd64\n"
        "Version: 2.0.0\n"
        "\n"
        "Package: zlib1g\n"
        "Status: install ok installed\n"
        "Maintainer: Mark Adler <madler@alumni.caltech.edu>\n"
        "Architecture: amd64\n"
        "Version: 1:1.2.11.dfsg-2ubuntu9.2\n";

    ssize_t written = write(fd, sample_data, strlen(sample_data));
    ASSERT_TRUE(written == (ssize_t)strlen(sample_data));
    close(fd);

    SoftwareInventoryBatch* batch = (SoftwareInventoryBatch*)calloc(1, sizeof(SoftwareInventoryBatch));
    ASSERT_TRUE(batch != NULL);

    int res = SoftwareInv_CollectDpkgStatus(tmp_path, batch);
    ASSERT_TRUE(res == 0);
    /* Should only collect installed packages: openssh-server, nginx-common, zlib1g (3 packages) */
    ASSERT_TRUE(batch->count == 3);
    ASSERT_STR_EQ(batch->primary_source, "dpkg");

    /* Package 1: openssh-server */
    ASSERT_STR_EQ(batch->items[0].product, "openssh-server");
    ASSERT_STR_EQ(batch->items[0].version, "1:8.9p1-3ubuntu0.6");
    ASSERT_STR_EQ(batch->items[0].architecture, "amd64");
    ASSERT_STR_EQ(batch->items[0].vendor, "ubuntu");
    ASSERT_STR_EQ(batch->items[0].confidence, "authoritative");
    ASSERT_STR_EQ(batch->items[0].install_scope, "system");
    ASSERT_STR_EQ(batch->items[0].raw_product, "openssh-server");
    ASSERT_STR_EQ(batch->items[0].raw_version, "1:8.9p1-3ubuntu0.6");
    ASSERT_STR_EQ(batch->items[0].raw_vendor, "Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>");

    /* Package 2: nginx-common */
    ASSERT_STR_EQ(batch->items[1].product, "nginx-common");
    ASSERT_STR_EQ(batch->items[1].version, "1.18.0-6ubuntu14.4");
    ASSERT_STR_EQ(batch->items[1].architecture, "all");
    ASSERT_STR_EQ(batch->items[1].vendor, "debian");

    /* Package 3: zlib1g */
    ASSERT_STR_EQ(batch->items[2].product, "zlib1g");
    ASSERT_STR_EQ(batch->items[2].version, "1:1.2.11.dfsg-2ubuntu9.2");
    ASSERT_STR_EQ(batch->items[2].vendor, "mark adler");

    /* Test JSON Serialization */
    char json_buf[4096];
    size_t json_len = SoftwareInv_SerializeJSON("test-endpoint-01", batch, json_buf, sizeof(json_buf));
    ASSERT_TRUE(json_len > 0);
    ASSERT_TRUE(strstr(json_buf, "\"endpoint_id\":\"test-endpoint-01\"") != NULL);
    ASSERT_TRUE(strstr(json_buf, "\"source\":\"dpkg\"") != NULL);
    ASSERT_TRUE(strstr(json_buf, "\"product\":\"openssh-server\"") != NULL);
    ASSERT_TRUE(strstr(json_buf, "\"vendor\":\"ubuntu\"") != NULL);
    ASSERT_TRUE(strstr(json_buf, "\"product\":\"nginx-common\"") != NULL);
    ASSERT_TRUE(strstr(json_buf, "\"product\":\"zlib1g\"") != NULL);

    unlink(tmp_path);
    free(batch);
}

static void test_vendor_normalization(void) {
    printf("[*] Testing vendor normalization...\n");
    char vendor[128];

    SoftwareInv_NormalizeVendor("Ubuntu Core Developers <ubuntu-devel-discuss@lists.ubuntu.com>", vendor, sizeof(vendor));
    ASSERT_STR_EQ(vendor, "ubuntu");

    SoftwareInv_NormalizeVendor("Debian QA Group <packages@qa.debian.org>", vendor, sizeof(vendor));
    ASSERT_STR_EQ(vendor, "debian");

    SoftwareInv_NormalizeVendor("Red Hat, Inc. <http://bugzilla.redhat.com/bugzilla>", vendor, sizeof(vendor));
    ASSERT_STR_EQ(vendor, "redhat");

    SoftwareInv_NormalizeVendor("Canonical Ltd. <info@canonical.com>", vendor, sizeof(vendor));
    ASSERT_STR_EQ(vendor, "canonical");

    SoftwareInv_NormalizeVendor("Microsoft Corporation <support@microsoft.com>", vendor, sizeof(vendor));
    ASSERT_STR_EQ(vendor, "microsoft");

    SoftwareInv_NormalizeVendor("Google Inc. <support@google.com>", vendor, sizeof(vendor));
    ASSERT_STR_EQ(vendor, "google");

    SoftwareInv_NormalizeVendor("Random Developer <dev@test.invalid>", vendor, sizeof(vendor));
    ASSERT_STR_EQ(vendor, "random developer");

    SoftwareInv_NormalizeVendor("", vendor, sizeof(vendor));
    ASSERT_STR_EQ(vendor, "unknown");

    SoftwareInv_NormalizeVendor(NULL, vendor, sizeof(vendor));
    ASSERT_STR_EQ(vendor, "unknown");
}

static void test_json_escaping(void) {
    printf("[*] Testing JSON escaping...\n");
    char escaped[256];

    SoftwareInv_EscapeJson("hello \"world\" \\ test\nnewline\ttab", escaped, sizeof(escaped));
    ASSERT_STR_EQ(escaped, "hello \\\"world\\\" \\\\ test\\nnewline\\ttab");

    SoftwareInv_EscapeJson(NULL, escaped, sizeof(escaped));
    ASSERT_STR_EQ(escaped, "");
}

static void test_live_host_dpkg(void) {
    printf("[*] Testing live host package collection (if dpkg present)...\n");
    SoftwareInventoryBatch* batch = (SoftwareInventoryBatch*)calloc(1, sizeof(SoftwareInventoryBatch));
    ASSERT_TRUE(batch != NULL);

    if (access("/var/lib/dpkg/status", R_OK) == 0) {
        int res = SoftwareInv_CollectLinux(NULL, batch);
        ASSERT_TRUE(res == 0);
        ASSERT_TRUE(batch->count > 0);
        printf("    -> Discovered %zu authoritative installed packages on host\n", batch->count);

        char json_buf[1024];
        /* Test small buffer bounds handling */
        size_t written = SoftwareInv_SerializeJSON("host-endpoint", batch, json_buf, sizeof(json_buf));
        ASSERT_TRUE(written > 0);
        ASSERT_TRUE(json_buf[written - 1] == '}');
        ASSERT_TRUE(json_buf[written - 2] == ']');
    } else {
        printf("    -> /var/lib/dpkg/status not present on this test runner, skipped live host collection\n");
    }
    free(batch);
}

int main(void) {
    printf("=== Running Ominull Linux Software Inventory Tests (Slice 7A) ===\n");
    test_dpkg_status_parsing();
    test_vendor_normalization();
    test_json_escaping();
    test_live_host_dpkg();

    printf("Summary: %d tests passed, %d tests failed.\n", g_tests_run - g_tests_failed, g_tests_failed);
    return g_tests_failed == 0 ? 0 : 1;
}
