#include "../include/auth.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define PASSWORD_SIZE 256

static void print_usage(const char *prog) {
    printf("Usage:\n");
    printf("  %s lock <path>\n", prog);
    printf("  %s access <path>\n", prog);
    printf("  %s remove <path>\n", prog);
    printf("  %s status <path>\n", prog);
    printf("\nExamples:\n");
    printf("  %s lock secret.txt\n", prog);
    printf("  %s access secret.txt\n", prog);
    printf("  %s remove secret.txt\n", prog);
    printf("  %s status secret.txt\n", prog);
}

static int read_password(char *buffer, size_t size) {
    char *password = getpass("Password: ");

    if (password == NULL) {
        fprintf(stderr, "비밀번호 입력 실패\n");
        return -1;
    }

    strncpy(buffer, password, size - 1);
    buffer[size - 1] = '\0';

    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        print_usage(argv[0]);
        return 1;
    }

    const char *command = argv[1];
    const char *path = argv[2];

    int result = -1;

    if (strcmp(command, "status") == 0) {
        if (auth_is_locked(path)) {
            printf("잠금 상태입니다: %s\n", path);
        } else {
            printf("잠금 상태가 아닙니다: %s\n", path);
        }

        return 0;
    }

    char password[PASSWORD_SIZE];

    if (read_password(password, sizeof(password)) != 0) {
        return 1;
    }

    if (strcmp(command, "lock") == 0) {
        result = auth_lock_file(path, password);
    } else if (strcmp(command, "access") == 0) {
        result = auth_access(path, password);
    } else if (strcmp(command, "remove") == 0) {
        result = auth_remove_lock(path, password);
    } else {
        print_usage(argv[0]);
        return 1;
    }

    return result == 0 ? 0 : 1;
}