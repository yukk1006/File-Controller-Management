#include "auth.h"
#include "gpg_wrapper.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/stat.h>

#define INPUT_SIZE 1024
#define PASSWORD_SIZE 256
#define MAX_PATH_LEN 1024

void handle_sigint(int signo) {
    (void)signo;

    printf("\nCtrl+C 입력 감지. 열린 파일/디렉토리를 자동 close합니다...\n");

    auth_close_all_open_files();

    printf("Factoreal을 종료합니다.\n");
    exit(0);
}

static void print_usage(void) {
    printf("\n");
    printf("========== Factoreal ==========\n");
    printf("사용 가능한 명령어:\n\n");

    printf("[Auth Mode - Password/chmod]\n");
    printf("  lock <파일/디렉토리 경로>        : 비밀번호 설정 후 Factoreal 관리 대상으로 등록\n");
    printf("  open <파일/디렉토리 경로>        : 비밀번호 인증 후 파일 copy 생성 / 디렉토리 권한 복구\n");
    printf("  close <파일/디렉토리 경로>       : 파일 copy 반영 / 디렉토리 다시 chmod 000\n");
    printf("  remove <파일/디렉토리 경로>      : 비밀번호 인증 후 Factoreal 관리 대상에서 제거\n");
    printf("  status <파일/디렉토리 경로>      : Auth 관리 상태 확인\n\n");

    printf("[GPG Mode - Encryption]\n");
    printf("  gpg_lock <경로>          : GPG 방식으로 파일/디렉토리 암호화\n");
    printf("  gpg_unlock <경로>        : GPG 방식으로 복호화\n");
    printf("  gpg_open <경로>          : GPG 암호화 파일 open\n");
    printf("  gpg_close <경로>         : GPG open 파일 close\n\n");

    printf("[Common]\n");
    printf("  help                             : 사용법 출력\n");
    printf("  exit                             : 열린 항목 자동 close 후 종료\n");
    printf("  Ctrl+C                           : 열린 항목 자동 close 후 강제 종료\n");
    printf("==================================\n\n");
}

static int ask_exit_confirm(void) {
    char answer[32];

    printf("정말로 종료하시겠습니까? (y/n): ");

    if (fgets(answer, sizeof(answer), stdin) == NULL) {
        clearerr(stdin);
        return 0;
    }

    if (answer[0] == 'y' || answer[0] == 'Y') {
        return 1;
    }

    printf("프로그램을 계속 실행합니다.\n");
    return 0;
}

static int resolve_path(const char *input_path, char *resolved_path) {
    struct stat st;

    if (input_path == NULL) {
        fprintf(stderr, "경로가 입력되지 않았습니다.\n");
        return -1;
    }

    if (stat(input_path, &st) != 0) {
        fprintf(stderr, "경로를 찾을 수 없습니다: %s\n", input_path);
        return -1;
    }

    if (!S_ISREG(st.st_mode) && !S_ISDIR(st.st_mode)) {
        fprintf(stderr, "일반 파일 또는 디렉토리만 사용할 수 있습니다.\n");
        return -1;
    }

    if (realpath(input_path, resolved_path) == NULL) {
        fprintf(stderr, "경로를 해석할 수 없습니다: %s\n", input_path);
        return -1;
    }

    return 0;
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

static void execute_command(const char *command, const char *path_arg) {
    char resolved_path[MAX_PATH_LEN];
    char password[PASSWORD_SIZE];
    int result = -1;

    if (strcmp(command, "help") == 0) {
        print_usage();
        return;
    }

    if (strcmp(command, "exit") == 0) {
        if (ask_exit_confirm()) {
            printf("열린 파일/디렉토리를 자동 close합니다...\n");
            auth_close_all_open_files();
            printf("Factoreal을 종료합니다.\n");
            exit(0);
        }

        printf("프로그램을 계속 실행합니다.\n");
        return;
    }

    if (path_arg == NULL) {
        fprintf(stderr, "경로를 입력해주세요.\n");
        return;
    }

    if (
        strcmp(command, "lock") != 0 &&
        strcmp(command, "open") != 0 &&
        strcmp(command, "close") != 0 &&
        strcmp(command, "remove") != 0 &&
        strcmp(command, "status") != 0 &&
        strcmp(command, "gpg_lock") != 0 &&
        strcmp(command, "gpg_unlock") != 0 &&
        strcmp(command, "gpg_open") != 0 &&
        strcmp(command, "gpg_close") != 0
    ) {
        fprintf(stderr, "잘못된 명령어입니다!\n");
        return;
    }

    if (resolve_path(path_arg, resolved_path) != 0) {
        return;
    }

    if (strcmp(command, "status") == 0) {
        if (auth_is_locked(resolved_path)) {
            printf("Factoreal 관리 대상입니다: %s\n", resolved_path);
        } else {
            printf("Factoreal 관리 대상이 아닙니다: %s\n", resolved_path);
        }
        return;
    }

    if (read_password(password, sizeof(password)) != 0) {
        return;
    }

    if (strcmp(command, "lock") == 0) {
        result = auth_lock_file(resolved_path, password);

    } else if (strcmp(command, "open") == 0) {
        result = auth_open_file(resolved_path, password);

    } else if (strcmp(command, "close") == 0) {
        result = auth_close_file(resolved_path, password);

    } else if (strcmp(command, "remove") == 0) {
        result = auth_remove_lock(resolved_path, password);

    } else if (strcmp(command, "gpg_lock") == 0) {
        result = gpg_lock(resolved_path, password);

    } else if (strcmp(command, "gpg_unlock") == 0) {
        result = gpg_unlock(resolved_path, password);

    } else if (strcmp(command, "gpg_open") == 0) {
        result = open_file(resolved_path, password);

    } else if (strcmp(command, "gpg_close") == 0) {
        result = close_file(resolved_path, password);
    }

    if (result != 0) {
        fprintf(stderr, "명령 실행에 실패했습니다.\n");
    }
}

int main(void) {
    char input[INPUT_SIZE];

    signal(SIGINT, handle_sigint);

    print_usage();

    while (1) {
        printf("factoreal> ");
        fflush(stdout);

        if (fgets(input, sizeof(input), stdin) == NULL) {
            clearerr(stdin);
            continue;
        }

        char *command = strtok(input, " \n");
        char *path_arg = strtok(NULL, " \n");

        if (command == NULL) {
            continue;
        }

        execute_command(command, path_arg);
    }

    return 0;
}