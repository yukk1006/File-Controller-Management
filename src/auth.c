#include "auth.h"
#include "logger.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <pwd.h>
#include <dirent.h>
#include <errno.h>
#include <sodium.h>
#include <sys/stat.h>
#include <sys/types.h>

#define PASS_DB "data/.pass_db"
#define TEMP_DB "data/.pass_db.tmp"
#define DATA_DIR "data"

#define MAX_DB_SIZE 65536
#define MAX_LINE 2048
#define MAX_PATH_LEN 512
#define MAX_STATE_LEN 16
#define COPY_NONE "-"

#define BUF_SIZE 4096

typedef struct {
    char path[MAX_PATH_LEN];
    uid_t owner_uid;
    gid_t owner_gid;
    mode_t original_mode;
    char type; /* 'F' file, 'D' directory */
    char password_hash[crypto_pwhash_STRBYTES];
    char state[MAX_STATE_LEN]; /* LOCKED or OPEN */
    char copy_path[MAX_PATH_LEN];
} AuthRecord;

/*
 * 현재 실제 실행 사용자 이름 가져오기
 * SUID 환경에서는 getuid()가 실제 사용자, geteuid()가 root일 수 있음
 */
static const char *get_current_username(void) {
    const char *user = getlogin();

    if (user != NULL) {
        return user;
    }

    struct passwd *pw = getpwuid(getuid());

    if (pw != NULL) {
        return pw->pw_name;
    }

    return "unknown";
}

/*
 * libsodium 초기화
 */
static int init_crypto(void) {
    if (sodium_init() < 0) {
        fprintf(stderr, "libsodium 초기화 실패\n");
        return -1;
    }

    return 0;
}

/*
 * 비밀번호 해시 생성
 */
static int make_password_hash(const char *password, char *out_hash) {
    if (init_crypto() != 0) {
        return -1;
    }

    if (crypto_pwhash_str(
            out_hash,
            password,
            strlen(password),
            crypto_pwhash_OPSLIMIT_INTERACTIVE,
            crypto_pwhash_MEMLIMIT_INTERACTIVE
        ) != 0) {
        fprintf(stderr, "비밀번호 해시 생성 실패\n");
        return -1;
    }

    return 0;
}

/*
 * 비밀번호 검증
 */
static int verify_password_hash(const char *stored_hash, const char *password) {
    if (init_crypto() != 0) {
        return -1;
    }

    if (crypto_pwhash_str_verify(
            stored_hash,
            password,
            strlen(password)
        ) != 0) {
        return -1;
    }

    return 0;
}

/*
 * data 디렉토리 준비
 */
static int ensure_data_dir(void) {
    struct stat st;

    if (stat(DATA_DIR, &st) == 0) {
        if (S_ISDIR(st.st_mode)) {
            return 0;
        }

        fprintf(stderr, "data가 디렉토리가 아닙니다.\n");
        return -1;
    }

    if (mkdir(DATA_DIR, 0700) != 0) {
        perror("mkdir data");
        return -1;
    }

    return 0;
}

/*
 * write() 전체 쓰기 보장
 */
static int write_all(int fd, const char *buf, size_t len) {
    size_t total = 0;

    while (total < len) {
        ssize_t n = write(fd, buf + total, len - total);

        if (n < 0) {
            perror("write");
            return -1;
        }

        total += (size_t)n;
    }

    return 0;
}

/*
 * DB 전체 읽기
 */
static ssize_t read_db(char *buffer, size_t size) {
    int fd = open(PASS_DB, O_RDONLY);

    if (fd < 0) {
        buffer[0] = '\0';
        return 0;
    }

    ssize_t n = read(fd, buffer, size - 1);

    if (n < 0) {
        perror("read db");
        close(fd);
        return -1;
    }

    buffer[n] = '\0';
    close(fd);

    return n;
}

/*
 * DB 한 줄 파싱
 * format:
 * path|uid|gid|mode|type|hash|state|copy_path
 */
static int parse_record_line(const char *line, AuthRecord *rec) {
    unsigned int uid_num;
    unsigned int gid_num;
    unsigned int mode_num;

    char path[MAX_PATH_LEN];
    char hash[crypto_pwhash_STRBYTES];
    char state[MAX_STATE_LEN];
    char copy_path[MAX_PATH_LEN];
    char type;

    int matched = sscanf(
        line,
        "%511[^|]|%u|%u|%o|%c|%127[^|]|%15[^|]|%511[^\n]",
        path,
        &uid_num,
        &gid_num,
        &mode_num,
        &type,
        hash,
        state,
        copy_path
    );

    if (matched != 8) {
        return -1;
    }

    strncpy(rec->path, path, sizeof(rec->path) - 1);
    rec->path[sizeof(rec->path) - 1] = '\0';

    rec->owner_uid = (uid_t)uid_num;
    rec->owner_gid = (gid_t)gid_num;
    rec->original_mode = (mode_t)mode_num;
    rec->type = type;

    strncpy(rec->password_hash, hash, sizeof(rec->password_hash) - 1);
    rec->password_hash[sizeof(rec->password_hash) - 1] = '\0';

    strncpy(rec->state, state, sizeof(rec->state) - 1);
    rec->state[sizeof(rec->state) - 1] = '\0';

    strncpy(rec->copy_path, copy_path, sizeof(rec->copy_path) - 1);
    rec->copy_path[sizeof(rec->copy_path) - 1] = '\0';

    return 0;
}

/*
 * DB 한 줄 생성
 */
static int record_to_line(const AuthRecord *rec, char *line, size_t size) {
    int len = snprintf(
        line,
        size,
        "%s|%u|%u|%o|%c|%s|%s|%s\n",
        rec->path,
        (unsigned int)rec->owner_uid,
        (unsigned int)rec->owner_gid,
        rec->original_mode,
        rec->type,
        rec->password_hash,
        rec->state,
        rec->copy_path
    );

    if (len < 0 || len >= (int)size) {
        return -1;
    }

    return len;
}

/*
 * DB에서 특정 path 검색
 */
static int find_record(const char *path, AuthRecord *out_rec) {
    char buffer[MAX_DB_SIZE];

    if (read_db(buffer, sizeof(buffer)) < 0) {
        return 0;
    }

    char *line = strtok(buffer, "\n");

    while (line != NULL) {
        AuthRecord rec;

        if (parse_record_line(line, &rec) == 0) {
            if (strcmp(rec.path, path) == 0) {
                if (out_rec != NULL) {
                    *out_rec = rec;
                }

                return 1;
            }
        }

        line = strtok(NULL, "\n");
    }

    return 0;
}

/*
 * DB에 record 추가
 */
static int add_record(const AuthRecord *new_rec) {
    if (ensure_data_dir() != 0) {
        return -1;
    }

    int fd = open(PASS_DB, O_WRONLY | O_CREAT | O_APPEND, 0600);

    if (fd < 0) {
        perror("open db");
        return -1;
    }

    char line[MAX_LINE];

    int len = record_to_line(new_rec, line, sizeof(line));

    if (len < 0) {
        fprintf(stderr, "DB line 생성 실패\n");
        close(fd);
        return -1;
    }

    if (write_all(fd, line, (size_t)len) != 0) {
        close(fd);
        return -1;
    }

    close(fd);
    return 0;
}

/*
 * DB record 업데이트
 */
static int update_record(const AuthRecord *updated_rec) {
    char buffer[MAX_DB_SIZE];

    if (read_db(buffer, sizeof(buffer)) < 0) {
        return -1;
    }

    int fd = open(TEMP_DB, O_WRONLY | O_CREAT | O_TRUNC, 0600);

    if (fd < 0) {
        perror("open temp db");
        return -1;
    }

    char *line = strtok(buffer, "\n");

    while (line != NULL) {
        AuthRecord rec;

        if (parse_record_line(line, &rec) == 0) {
            char out[MAX_LINE];
            int len;

            if (strcmp(rec.path, updated_rec->path) == 0) {
                len = record_to_line(updated_rec, out, sizeof(out));
            } else {
                len = snprintf(out, sizeof(out), "%s\n", line);
            }

            if (len < 0 || len >= (int)sizeof(out)) {
                close(fd);
                return -1;
            }

            if (write_all(fd, out, (size_t)len) != 0) {
                close(fd);
                return -1;
            }
        }

        line = strtok(NULL, "\n");
    }

    close(fd);

    if (rename(TEMP_DB, PASS_DB) != 0) {
        perror("rename db");
        return -1;
    }

    return 0;
}

/*
 * DB record 삭제
 */
static int remove_record(const char *path) {
    char buffer[MAX_DB_SIZE];

    if (read_db(buffer, sizeof(buffer)) < 0) {
        return -1;
    }

    int fd = open(TEMP_DB, O_WRONLY | O_CREAT | O_TRUNC, 0600);

    if (fd < 0) {
        perror("open temp db");
        return -1;
    }

    char *line = strtok(buffer, "\n");

    while (line != NULL) {
        AuthRecord rec;

        if (parse_record_line(line, &rec) == 0) {
            if (strcmp(rec.path, path) != 0) {
                char out[MAX_LINE];
                int len = snprintf(out, sizeof(out), "%s\n", line);

                if (len < 0 || len >= (int)sizeof(out)) {
                    close(fd);
                    return -1;
                }

                if (write_all(fd, out, (size_t)len) != 0) {
                    close(fd);
                    return -1;
                }
            }
        }

        line = strtok(NULL, "\n");
    }

    close(fd);

    if (rename(TEMP_DB, PASS_DB) != 0) {
        perror("rename db");
        return -1;
    }

    return 0;
}

/*
 * symlink 거부용 검사
 */
static int reject_symlink(const char *path) {
    struct stat lst;

    if (lstat(path, &lst) != 0) {
        perror("lstat");
        return -1;
    }

    if (S_ISLNK(lst.st_mode)) {
        fprintf(stderr, "심볼릭 링크는 사용할 수 없습니다.\n");
        return -1;
    }

    return 0;
}

/*
 * basename 추출
 */
static const char *get_base_name(const char *path) {
    const char *p = strrchr(path, '/');

    if (p == NULL) {
        return path;
    }

    return p + 1;
}

/*
 * 파일 복사
 */
static int copy_file_content(const char *src, const char *dst, mode_t dst_mode, uid_t uid, gid_t gid) {
    int in_fd = open(src, O_RDONLY);

    if (in_fd < 0) {
        perror("open src");
        return -1;
    }

    int out_fd = open(dst, O_WRONLY | O_CREAT | O_TRUNC, dst_mode);

    if (out_fd < 0) {
        perror("open dst");
        close(in_fd);
        return -1;
    }

    char buf[BUF_SIZE];

    while (1) {
        ssize_t n = read(in_fd, buf, sizeof(buf));

        if (n < 0) {
            perror("read file");
            close(in_fd);
            close(out_fd);
            return -1;
        }

        if (n == 0) {
            break;
        }

        if (write_all(out_fd, buf, (size_t)n) != 0) {
            close(in_fd);
            close(out_fd);
            return -1;
        }
    }

    close(in_fd);
    close(out_fd);

    chmod(dst, dst_mode);
    chown(dst, uid, gid);

    return 0;
}

/*
 * 파일/디렉토리 재귀 삭제
 */
static int remove_tree(const char *path) {
    struct stat st;

    if (lstat(path, &st) != 0) {
        return -1;
    }

    if (S_ISREG(st.st_mode)) {
        return unlink(path);
    }

    if (S_ISDIR(st.st_mode)) {
        DIR *dir = opendir(path);

        if (dir == NULL) {
            perror("opendir remove");
            return -1;
        }

        struct dirent *entry;

        while ((entry = readdir(dir)) != NULL) {
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
                continue;
            }

            char child[MAX_PATH_LEN];

            snprintf(child, sizeof(child), "%s/%s", path, entry->d_name);

            if (remove_tree(child) != 0) {
                closedir(dir);
                return -1;
            }
        }

        closedir(dir);

        return rmdir(path);
    }

    fprintf(stderr, "지원하지 않는 파일 타입입니다: %s\n", path);
    return -1;
}

/*
 * 디렉토리 내부 비우기
 */
static int clear_directory(const char *path) {
    DIR *dir = opendir(path);

    if (dir == NULL) {
        perror("opendir clear");
        return -1;
    }

    struct dirent *entry;

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        char child[MAX_PATH_LEN];

        snprintf(child, sizeof(child), "%s/%s", path, entry->d_name);

        if (remove_tree(child) != 0) {
            closedir(dir);
            return -1;
        }
    }

    closedir(dir);
    return 0;
}

/*
 * 디렉토리 재귀 복사
 * workspace_mode가 1이면 copy 쪽 권한을 사용자 편집용 0600/0700으로 설정
 */
static int copy_directory_recursive(
    const char *src,
    const char *dst,
    uid_t uid,
    gid_t gid,
    int workspace_mode
) {
    DIR *dir = opendir(src);

    if (dir == NULL) {
        perror("opendir copy");
        return -1;
    }

    if (mkdir(dst, 0700) != 0 && errno != EEXIST) {
        perror("mkdir dst");
        closedir(dir);
        return -1;
    }

    chmod(dst, 0700);
    chown(dst, uid, gid);

    struct dirent *entry;

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        char src_child[MAX_PATH_LEN];
        char dst_child[MAX_PATH_LEN];

        snprintf(src_child, sizeof(src_child), "%s/%s", src, entry->d_name);
        snprintf(dst_child, sizeof(dst_child), "%s/%s", dst, entry->d_name);

        struct stat st;

        if (lstat(src_child, &st) != 0) {
            perror("lstat copy child");
            closedir(dir);
            return -1;
        }

        if (S_ISLNK(st.st_mode)) {
            fprintf(stderr, "심볼릭 링크는 복사하지 않습니다: %s\n", src_child);
            closedir(dir);
            return -1;
        }

        if (S_ISREG(st.st_mode)) {
            mode_t mode = workspace_mode ? 0600 : (st.st_mode & 0777);

            if (copy_file_content(src_child, dst_child, mode, uid, gid) != 0) {
                closedir(dir);
                return -1;
            }
        } else if (S_ISDIR(st.st_mode)) {
            if (copy_directory_recursive(src_child, dst_child, uid, gid, workspace_mode) != 0) {
                closedir(dir);
                return -1;
            }
        } else {
            fprintf(stderr, "지원하지 않는 파일 타입입니다: %s\n", src_child);
            closedir(dir);
            return -1;
        }
    }

    closedir(dir);
    return 0;
}

/*
 * 임시 작업 경로 생성
 */
static int make_workspace_path(const char *original_path, char *out_path, size_t size) {
    const char *base = get_base_name(original_path);

    int len = snprintf(
        out_path,
        size,
        "/tmp/factoreal_%u_%d_%s",
        (unsigned int)getuid(),
        getpid(),
        base
    );

    if (len < 0 || len >= (int)size) {
        fprintf(stderr, "workspace path가 너무 깁니다.\n");
        return -1;
    }

    return 0;
}

/*
 * 비밀번호 검증 + 로그 기록
 */
static int verify_record_password(const AuthRecord *rec, const char *password) {
    const char *user = get_current_username();

    if (verify_password_hash(rec->password_hash, password) != 0) {
        write_access_log(user, rec->path, 0);
        fprintf(stderr, "비밀번호가 틀렸습니다.\n");
        return -1;
    }

    write_access_log(user, rec->path, 1);
    return 0;
}

/*
 * 현재 잠금 등록 여부
 */
int auth_is_locked(const char *path) {
    return find_record(path, NULL);
}

/*
 * lock/register
 * 조건:
 * 1. 파일 소유주와 실행 사용자 real uid가 같아야 등록 가능
 * 2. 일반 파일 또는 디렉토리만 허용
 * 3. symlink 거부
 */
int auth_lock_file(const char *path, const char *password) {
    struct stat st;

    if (reject_symlink(path) != 0) {
        return -1;
    }

    if (stat(path, &st) != 0) {
        perror("stat");
        return -1;
    }

    if (!S_ISREG(st.st_mode) && !S_ISDIR(st.st_mode)) {
        fprintf(stderr, "일반 파일 또는 디렉토리만 잠글 수 있습니다.\n");
        return -1;
    }

    if (st.st_uid != getuid()) {
        fprintf(stderr, "파일 소유주만 Factoreal에 등록할 수 있습니다.\n");
        return -1;
    }

    if (auth_is_locked(path)) {
        fprintf(stderr, "이미 Factoreal 관리 대상입니다.\n");
        return -1;
    }

    AuthRecord rec;

    memset(&rec, 0, sizeof(rec));

    strncpy(rec.path, path, sizeof(rec.path) - 1);
    rec.owner_uid = st.st_uid;
    rec.owner_gid = st.st_gid;
    rec.original_mode = st.st_mode & 0777;
    rec.type = S_ISDIR(st.st_mode) ? 'D' : 'F';

    if (make_password_hash(password, rec.password_hash) != 0) {
        return -1;
    }

    strncpy(rec.state, "LOCKED", sizeof(rec.state) - 1);
    strncpy(rec.copy_path, COPY_NONE, sizeof(rec.copy_path) - 1);

    if (add_record(&rec) != 0) {
        return -1;
    }

    if (chmod(path, 0000) != 0) {
        perror("chmod lock");
        remove_record(path);
        return -1;
    }

    printf("Factoreal 관리 대상으로 등록하고 잠금 처리했습니다: %s\n", path);
    return 0;
}

/*
 * open
 * 원본은 chmod 000 유지
 * copy 파일/디렉토리만 생성
 */
int auth_open_file(const char *path, const char *password) {
    AuthRecord rec;
    char workspace[MAX_PATH_LEN];

    if (!find_record(path, &rec)) {
        fprintf(stderr, "Factoreal 관리 대상이 아닙니다.\n");
        return -1;
    }

    if (verify_record_password(&rec, password) != 0) {
        return -1;
    }

    if (strcmp(rec.state, "OPEN") == 0) {
        printf("이미 open 상태입니다. copy path: %s\n", rec.copy_path);
        return -1;
    }

    if (make_workspace_path(path, workspace, sizeof(workspace)) != 0) {
        return -1;
    }

    remove_tree(workspace);

    if (rec.type == 'F') {
        if (copy_file_content(path, workspace, 0600, getuid(), getgid()) != 0) {
            return -1;
        }
    } else if (rec.type == 'D') {
        if (copy_directory_recursive(path, workspace, getuid(), getgid(), 1) != 0) {
            return -1;
        }
    } else {
        fprintf(stderr, "잘못된 record type입니다.\n");
        return -1;
    }

    strncpy(rec.state, "OPEN", sizeof(rec.state) - 1);
    strncpy(rec.copy_path, workspace, sizeof(rec.copy_path) - 1);

    if (update_record(&rec) != 0) {
        return -1;
    }

    printf("작업용 copy가 생성되었습니다.\n");
    printf("copy path: %s\n", rec.copy_path);
    printf("원본은 계속 잠금 상태입니다.\n");

    return 0;
}

/*
 * close
 * copy 내용을 원본에 반영하고 copy 삭제
 * 원본은 chmod 000 유지
 */
int auth_close_file(const char *path, const char *password) {
    AuthRecord rec;

    if (!find_record(path, &rec)) {
        fprintf(stderr, "Factoreal 관리 대상이 아닙니다.\n");
        return -1;
    }

    if (verify_record_password(&rec, password) != 0) {
        return -1;
    }

    if (strcmp(rec.state, "OPEN") != 0) {
        fprintf(stderr, "open 상태가 아닙니다.\n");
        return -1;
    }

    if (strcmp(rec.copy_path, COPY_NONE) == 0) {
        fprintf(stderr, "copy path가 없습니다.\n");
        return -1;
    }

    if (rec.type == 'F') {
        if (copy_file_content(rec.copy_path, rec.path, rec.original_mode, rec.owner_uid, rec.owner_gid) != 0) {
            return -1;
        }

        unlink(rec.copy_path);
    } else if (rec.type == 'D') {
        if (clear_directory(rec.path) != 0) {
            return -1;
        }

        if (copy_directory_recursive(rec.copy_path, rec.path, rec.owner_uid, rec.owner_gid, 0) != 0) {
            return -1;
        }

        remove_tree(rec.copy_path);
    } else {
        fprintf(stderr, "잘못된 record type입니다.\n");
        return -1;
    }

    if (chmod(rec.path, 0000) != 0) {
        perror("chmod relock");
        return -1;
    }

    strncpy(rec.state, "LOCKED", sizeof(rec.state) - 1);
    strncpy(rec.copy_path, COPY_NONE, sizeof(rec.copy_path) - 1);

    if (update_record(&rec) != 0) {
        return -1;
    }

    printf("copy 내용을 원본에 반영하고 다시 잠금 처리했습니다: %s\n", path);
    return 0;
}

/*
 * remove
 * 비밀번호 검증 후 원래 권한 복구, DB 삭제
 */
int auth_remove_lock(const char *path, const char *password) {
    AuthRecord rec;

    if (!find_record(path, &rec)) {
        fprintf(stderr, "Factoreal 관리 대상이 아닙니다.\n");
        return -1;
    }

    if (verify_record_password(&rec, password) != 0) {
        return -1;
    }

    if (strcmp(rec.state, "OPEN") == 0) {
        fprintf(stderr, "현재 OPEN 상태입니다. 먼저 close를 수행하세요.\n");
        return -1;
    }

    if (chmod(rec.path, rec.original_mode) != 0) {
        perror("chmod restore");
        return -1;
    }

    if (remove_record(rec.path) != 0) {
        return -1;
    }

    printf("Factoreal 관리 대상에서 제거하고 원래 권한을 복구했습니다: %s\n", path);
    return 0;
}