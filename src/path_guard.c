#include "path_guard.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define MAX_PATH_LEN 1024

static int starts_with_path(const char *path, const char *prefix) {
    size_t len = strlen(prefix);

    return strncmp(path, prefix, len) == 0 &&
           (path[len] == '\0' || path[len] == '/');
}

int is_protected_path(const char *resolved_path) {
    char project_root[MAX_PATH_LEN];
    char protected_data[MAX_PATH_LEN];
    char protected_binary[MAX_PATH_LEN];

    const char *blocked_system_paths[] = {
        "/etc",
        "/bin",
        "/sbin",
        "/usr",
        "/lib",
        "/lib64",
        "/boot",
        "/dev",
        "/proc",
        "/sys",
        "/run",
        "/var"
    };

    size_t count = sizeof(blocked_system_paths) / sizeof(blocked_system_paths[0]);

    for (size_t i = 0; i < count; i++) {
        if (starts_with_path(resolved_path, blocked_system_paths[i])) {
            return 1;
        }
    }

    if (getcwd(project_root, sizeof(project_root)) == NULL) {
        perror("getcwd");
        return 1;
    }

    int len1 = snprintf(protected_data, sizeof(protected_data),
                    "%s/data", project_root);

    if (len1 < 0 || len1 >= (int)sizeof(protected_data)) {
        fprintf(stderr, "protected_data 경로가 너무 깁니다.\n");
        return 1;
    }

    int len2 = snprintf(protected_binary, sizeof(protected_binary),
                        "%s/factoreal", project_root);

    if (len2 < 0 || len2 >= (int)sizeof(protected_binary)) {
        fprintf(stderr, "protected_binary 경로가 너무 깁니다.\n");
        return 1;
    }

    if (starts_with_path(resolved_path, protected_data)) {
        return 1;
    }

    if (strcmp(resolved_path, protected_binary) == 0) {
        return 1;
    }

    return 0;
}