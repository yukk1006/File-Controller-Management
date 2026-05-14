#include "auth.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>

#define PASS_DB "data/.pass_db"
#define TEMP_DB "data/.pass_db.tmp"

#define MAX_DB_SIZE 8192
#define MAX_LINE 1024
#define MAX_PATH_LEN 512

#define SALT "factoreal_salt"

/*
 * 간단한 비밀번호 해시 함수
 * 실제 보안 목적이라면 bcrypt, Argon2, PBKDF2 사용 권장
 */
static unsigned long hash_password(const char *password) {
    unsigned long hash = 1469598103934665603UL;
    const char *p = password;

    while (*p) {
        hash ^= (unsigned char)(*p++);
        hash *= 1099511628211UL;
    }

    p = SALT;
    while (*p) {
        hash ^= (unsigned char)(*p++);
        hash *= 1099511628211UL;
    }

    return hash;
}

/*
 * .pass_db 전체 내용을 read()로 읽기
 */
static ssize_t read_db(char *buffer, size_t size) {
    int fd = open(PASS_DB, O_RDONLY);

    if (fd < 0) {
        buffer[0] = '\0';
        return 0;
    }

    ssize_t n = read(fd, buffer, size - 1);

    if (n < 0) {
        perror("read");
        close(fd);
        return -1;
    }

    buffer[n] = '\0';
    close(fd);

    return n;
}

/*
 * DB에서 path에 해당하는 잠금 정보 찾기
 * 저장 형식:
 * path|password_hash|original_mode
 */
static int find_record(const char *path, unsigned long *saved_hash, mode_t *saved_mode) {
    char buffer[MAX_DB_SIZE];

    if (read_db(buffer, sizeof(buffer)) < 0) {
        return 0;
    }

    char *line = strtok(buffer, "\n");

    while (line != NULL) {
        char db_path[MAX_PATH_LEN];
        unsigned long db_hash;
        unsigned int db_mode;

        if (sscanf(line, "%511[^|]|%lu|%o", db_path, &db_hash, &db_mode) == 3) {
            if (strcmp(db_path, path) == 0) {
                if (saved_hash != NULL) {
                    *saved_hash = db_hash;
                }

                if (saved_mode != NULL) {
                    *saved_mode = (mode_t)db_mode;
                }

                return 1;
            }
        }

        line = strtok(NULL, "\n");
    }

    return 0;
}

/*
 * DB에 새 잠금 정보 추가
 */
static int add_record(const char *path, unsigned long hash, mode_t mode) {
    int fd = open(PASS_DB, O_WRONLY | O_CREAT | O_APPEND, 0600);

    if (fd < 0) {
        perror("open");
        return -1;
    }

    char line[MAX_LINE];
    int len = snprintf(line, sizeof(line), "%s|%lu|%o\n", path, hash, mode);

    if (len < 0 || len >= (int)sizeof(line)) {
        fprintf(stderr, "DB에 저장할 데이터가 너무 깁니다.\n");
        close(fd);
        return -1;
    }

    if (write(fd, line, len) != len) {
        perror("write");
        close(fd);
        return -1;
    }

    close(fd);
    return 0;
}

/*
 * DB에서 path에 해당하는 잠금 정보 삭제
 */
static int remove_record(const char *path) {
    char buffer[MAX_DB_SIZE];

    if (read_db(buffer, sizeof(buffer)) < 0) {
        return -1;
    }

    int fd = open(TEMP_DB, O_WRONLY | O_CREAT | O_TRUNC, 0600);

    if (fd < 0) {
        perror("open temp");
        return -1;
    }

    char *line = strtok(buffer, "\n");

    while (line != NULL) {
        char db_path[MAX_PATH_LEN];
        unsigned long db_hash;
        unsigned int db_mode;

        if (sscanf(line, "%511[^|]|%lu|%o", db_path, &db_hash, &db_mode) == 3) {
            if (strcmp(db_path, path) != 0) {
                char out[MAX_LINE];
                int len = snprintf(out, sizeof(out), "%s\n", line);

                if (len < 0 || len >= (int)sizeof(out)) {
                    fprintf(stderr, "임시 DB에 쓸 데이터가 너무 깁니다.\n");
                    close(fd);
                    return -1;
                }

                if (write(fd, out, len) != len) {
                    perror("write temp");
                    close(fd);
                    return -1;
                }
            }
        }

        line = strtok(NULL, "\n");
    }

    close(fd);

    if (rename(TEMP_DB, PASS_DB) != 0) {
        perror("rename");
        return -1;
    }

    return 0;
}

/*
 * 비밀번호 검증 + 저장된 원래 권한 가져오기
 */
static int verify_password_and_get_mode(
    const char *path,
    const char *password,
    mode_t *saved_mode
) {
    unsigned long saved_hash;

    if (!find_record(path, &saved_hash, saved_mode)) {
        fprintf(stderr, "잠금 정보가 없습니다.\n");
        return -1;
    }

    if (hash_password(password) != saved_hash) {
        fprintf(stderr, "비밀번호가 틀렸습니다.\n");
        return -1;
    }

    return 0;
}

/*
 * 현재 잠금 등록 여부 확인
 */
int auth_is_locked(const char *path) {
    return find_record(path, NULL, NULL);
}

/*
 * 최초 잠금 설정
 * 기존 파일/디렉토리에 비밀번호 설정 후 chmod 000
 */
int auth_lock_file(const char *path, const char *password) {
    struct stat st;

    if (stat(path, &st) != 0) {
        perror("stat");
        return -1;
    }

    if (!S_ISREG(st.st_mode) && !S_ISDIR(st.st_mode)) {
        fprintf(stderr, "일반 파일 또는 디렉토리만 잠글 수 있습니다.\n");
        return -1;
    }

    if (auth_is_locked(path)) {
        fprintf(stderr, "이미 잠긴 파일 또는 디렉토리입니다.\n");
        return -1;
    }

    unsigned long hash = hash_password(password);
    mode_t original_mode = st.st_mode & 0777;

    if (add_record(path, hash, original_mode) != 0) {
        return -1;
    }

    if (chmod(path, 0000) != 0) {
        perror("chmod");
        remove_record(path);
        return -1;
    }

    printf("잠금 완료: %s\n", path);
    return 0;
}

/*
 * 파일 접근
 * 비밀번호 인증 → 권한 임시 복구 → vim 실행 → vim 종료 후 다시 chmod 000
 */
static int auth_edit_file(const char *path, const char *password) {
    mode_t saved_mode;

    if (verify_password_and_get_mode(path, password, &saved_mode) != 0) {
        return -1;
    }

    if (chmod(path, saved_mode) != 0) {
        perror("chmod temporary unlock");
        return -1;
    }

    pid_t pid = fork();

    if (pid < 0) {
        perror("fork");
        chmod(path, 0000);
        return -1;
    }

    if (pid == 0) {
        execlp("vim", "vim", path, NULL);
        perror("execlp");
        _exit(1);
    }

    int status;
    waitpid(pid, &status, 0);

    if (chmod(path, 0000) != 0) {
        perror("chmod relock");
        return -1;
    }

    printf("파일 작업 종료. 다시 잠금 처리되었습니다: %s\n", path);
    return 0;
}

/*
 * 디렉토리 접근
 * 비밀번호 인증 → 권한 임시 복구 → Enter 입력 대기 → 다시 chmod 000
 */
static int auth_access_directory(const char *path, const char *password) {
    mode_t saved_mode;

    if (verify_password_and_get_mode(path, password, &saved_mode) != 0) {
        return -1;
    }

    if (chmod(path, saved_mode) != 0) {
        perror("chmod temporary unlock");
        return -1;
    }

    printf("디렉토리 접근이 허용되었습니다: %s\n", path);
    printf("작업이 끝나면 Enter를 누르세요...");

    int c;
    while ((c = getchar()) != '\n' && c != EOF);

    getchar();

    if (chmod(path, 0000) != 0) {
        perror("chmod relock");
        return -1;
    }

    printf("디렉토리 작업 종료. 다시 잠금 처리되었습니다: %s\n", path);
    return 0;
}

/*
 * 접근 함수
 * 파일이면 vim 실행
 * 디렉토리면 Enter 대기 방식
 */
int auth_access(const char *path, const char *password) {
    struct stat st;

    if (stat(path, &st) != 0) {
        perror("stat");
        return -1;
    }

    if (S_ISREG(st.st_mode)) {
        return auth_edit_file(path, password);
    }

    if (S_ISDIR(st.st_mode)) {
        return auth_access_directory(path, password);
    }

    fprintf(stderr, "일반 파일 또는 디렉토리만 접근할 수 있습니다.\n");
    return -1;
}

/*
 * 완전 해제
 * 비밀번호 인증 → 원래 권한 복구 → DB 기록 삭제
 */
int auth_remove_lock(const char *path, const char *password) {
    mode_t saved_mode;

    if (verify_password_and_get_mode(path, password, &saved_mode) != 0) {
        return -1;
    }

    if (chmod(path, saved_mode) != 0) {
        perror("chmod restore");
        return -1;
    }

    if (remove_record(path) != 0) {
        return -1;
    }

    printf("잠금이 완전히 해제되었습니다: %s\n", path);
    return 0;
}