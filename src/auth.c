#include "auth.h"
#include "logger.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <pwd.h>
#include <errno.h>
#include <sodium.h>
#include <sys/stat.h>
#include <sys/types.h>

#define PASS_DB "data/.pass_db"
#define TEMP_DB "data/.pass_db.tmp"
#define DATA_DIR "data"

#define MAX_DB_SIZE 65536
#define MAX_LINE 2048
#define MAX_STATE_LEN 16
#define COPY_NONE "-"
#define BUF_SIZE 4096

typedef struct {
    char path[MAX_PATH_LEN];
    uid_t owner_uid;
    gid_t owner_gid;
    mode_t original_mode;
    char type; /* F: file, D: directory */
    char password_hash[crypto_pwhash_STRBYTES];
    char state[MAX_STATE_LEN]; /* LOCKED or OPEN */
    char copy_path[MAX_PATH_LEN];
} AuthRecord;

static int init_crypto(void) {
    if (sodium_init() < 0) {
        fprintf(stderr, "libsodium 초기화 실패\n");
        return -1;
    }
    return 0;
}

static int make_password_hash(const char *password, char *out_hash) {
    if (init_crypto() != 0) return -1;

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

static int verify_password_hash(const char *stored_hash, const char *password) {
    if (init_crypto() != 0) return -1;

    return crypto_pwhash_str_verify(
        stored_hash,
        password,
        strlen(password)
    );
}

static int ensure_data_dir(void) {
    struct stat st;

    if (stat(DATA_DIR, &st) == 0) {
        if (S_ISDIR(st.st_mode)) return 0;
        fprintf(stderr, "data가 디렉토리가 아닙니다.\n");
        return -1;
    }

    if (mkdir(DATA_DIR, 0700) != 0) {
        perror("mkdir data");
        return -1;
    }

    return 0;
}

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

static int parse_record_line(const char *line, AuthRecord *rec) {
    unsigned int uid_num;
    unsigned int gid_num;
    unsigned int mode_num;

    int matched = sscanf(
        line,
        "%511[^|]|%u|%u|%o|%c|%127[^|]|%15[^|]|%511[^\n]",
        rec->path,
        &uid_num,
        &gid_num,
        &mode_num,
        &rec->type,
        rec->password_hash,
        rec->state,
        rec->copy_path
    );

    if (matched != 8) return -1;

    rec->owner_uid = (uid_t)uid_num;
    rec->owner_gid = (gid_t)gid_num;
    rec->original_mode = (mode_t)mode_num;

    return 0;
}

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

    if (len < 0 || len >= (int)size) return -1;
    return len;
}

static int find_record(const char *path, AuthRecord *out_rec) {
    char buffer[MAX_DB_SIZE];

    if (read_db(buffer, sizeof(buffer)) < 0) return 0;

    char *saveptr;
    char *line = strtok_r(buffer, "\n", &saveptr);

    while (line != NULL) {
        AuthRecord rec;

        if (parse_record_line(line, &rec) == 0 &&
            strcmp(rec.path, path) == 0) {
            if (out_rec != NULL) *out_rec = rec;
            return 1;
        }

        line = strtok_r(NULL, "\n", &saveptr);
    }

    return 0;
}

static int add_record(const AuthRecord *rec) {
    if (ensure_data_dir() != 0) return -1;

    int fd = open(PASS_DB, O_WRONLY | O_CREAT | O_APPEND, 0600);

    if (fd < 0) {
        perror("open db");
        return -1;
    }

    char line[MAX_LINE];
    int len = record_to_line(rec, line, sizeof(line));

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

static int update_record(const AuthRecord *updated_rec) {
    char buffer[MAX_DB_SIZE];

    if (read_db(buffer, sizeof(buffer)) < 0) return -1;

    int fd = open(TEMP_DB, O_WRONLY | O_CREAT | O_TRUNC, 0600);

    if (fd < 0) {
        perror("open temp db");
        return -1;
    }

    char *saveptr;
    char *line = strtok_r(buffer, "\n", &saveptr);

    while (line != NULL) {
        AuthRecord rec;
        char out[MAX_LINE];
        int len;

        if (parse_record_line(line, &rec) == 0 &&
            strcmp(rec.path, updated_rec->path) == 0) {
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

        line = strtok_r(NULL, "\n", &saveptr);
    }

    close(fd);

    if (rename(TEMP_DB, PASS_DB) != 0) {
        perror("rename db");
        return -1;
    }

    return 0;
}

static int remove_record(const char *path) {
    char buffer[MAX_DB_SIZE];

    if (read_db(buffer, sizeof(buffer)) < 0) return -1;

    int fd = open(TEMP_DB, O_WRONLY | O_CREAT | O_TRUNC, 0600);

    if (fd < 0) {
        perror("open temp db");
        return -1;
    }

    char *saveptr;
    char *line = strtok_r(buffer, "\n", &saveptr);

    while (line != NULL) {
        AuthRecord rec;

        if (parse_record_line(line, &rec) == 0 &&
            strcmp(rec.path, path) != 0) {
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

        line = strtok_r(NULL, "\n", &saveptr);
    }

    close(fd);

    if (rename(TEMP_DB, PASS_DB) != 0) {
        perror("rename db");
        return -1;
    }

    return 0;
}

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

static const char *get_base_name(const char *path) {
    const char *p = strrchr(path, '/');
    return (p == NULL) ? path : p + 1;
}

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

static int copy_file_content(
    const char *src,
    const char *dst,
    mode_t dst_mode,
    uid_t uid,
    gid_t gid
) {
    int in_fd = open(src, O_RDONLY);

    if (in_fd < 0) {
        perror("open src");
        return -1;
    }

    int out_fd = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0600);

    if (out_fd < 0) {
        perror("open dst");
        close(in_fd);
        return -1;
    }

    if (fchown(out_fd, uid, gid) != 0) {
        perror("fchown dst");
        close(in_fd);
        close(out_fd);
        return -1;
    }

    if (fchmod(out_fd, dst_mode) != 0) {
        perror("fchmod dst");
        close(in_fd);
        close(out_fd);
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

        if (n == 0) break;

        if (write_all(out_fd, buf, (size_t)n) != 0) {
            close(in_fd);
            close(out_fd);
            return -1;
        }
    }

    close(in_fd);
    close(out_fd);

    return 0;
}

static int remove_file_if_exists(const char *path) {
    struct stat st;

    if (lstat(path, &st) != 0) {
        return 0;
    }

    if (S_ISREG(st.st_mode)) {
        return unlink(path);
    }

    fprintf(stderr, "workspace가 일반 파일이 아닙니다: %s\n", path);
    return -1;
}

static int verify_record_password(const AuthRecord *rec, const char *password) {
    if (verify_password_hash(rec->password_hash, password) != 0) {
        write_access_log(rec->path, PASSWORD_ERROR);
        fprintf(stderr, "비밀번호가 틀렸습니다.\n");
        return -1;
    }

    write_access_log(rec->path, SUCCESS);
    return 0;
}

int auth_is_locked(const char *path) {
    return find_record(path, NULL);
}

int auth_lock_file(const char *path, const char *password) {
    struct stat st;

    if (reject_symlink(path) != 0) return -1;

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
        printf("이미 open 상태입니다.\n");
        if (rec.type == 'F') {
            printf("copy path: %s\n", rec.copy_path);
        }
        return -1;
    }

    if (rec.type == 'F') {
        if (make_workspace_path(path, workspace, sizeof(workspace)) != 0) {
            return -1;
        }

        if (remove_file_if_exists(workspace) != 0) {
            return -1;
        }

        if (copy_file_content(path, workspace, 0600, getuid(), getgid()) != 0) {
            return -1;
        }

        strncpy(rec.copy_path, workspace, sizeof(rec.copy_path) - 1);
        rec.copy_path[sizeof(rec.copy_path) - 1] = '\0';

        printf("작업용 copy가 생성되었습니다.\n");
        printf("copy path: %s\n", rec.copy_path);
        printf("copy 파일을 수정한 뒤 close 명령을 실행하세요.\n");
    } else if (rec.type == 'D') {
        if (chmod(rec.path, rec.original_mode) != 0) {
            perror("chmod directory open");
            return -1;
        }

        strncpy(rec.copy_path, COPY_NONE, sizeof(rec.copy_path) - 1);
        rec.copy_path[sizeof(rec.copy_path) - 1] = '\0';

        printf("디렉토리 권한이 임시 복구되었습니다: %s\n", rec.path);
        printf("작업이 끝나면 close 명령을 실행하세요.\n");
    } else {
        fprintf(stderr, "잘못된 record type입니다.\n");
        return -1;
    }

    strncpy(rec.state, "OPEN", sizeof(rec.state) - 1);
    rec.state[sizeof(rec.state) - 1] = '\0';

    if (update_record(&rec) != 0) {
        return -1;
    }

    return 0;
}

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

    if (rec.type == 'F') {
        if (strcmp(rec.copy_path, COPY_NONE) == 0) {
            fprintf(stderr, "copy path가 없습니다.\n");
            return -1;
        }

        if (copy_file_content(
                rec.copy_path,
                rec.path,
                rec.original_mode,
                rec.owner_uid,
                rec.owner_gid
            ) != 0) {
            return -1;
        }

        if (unlink(rec.copy_path) != 0) {
            perror("unlink copy");
            return -1;
        }

        if (chmod(rec.path, 0000) != 0) {
            perror("chmod file close");
            return -1;
        }

        printf("copy 내용을 원본 파일에 반영하고 다시 잠금 처리했습니다: %s\n", rec.path);
    } else if (rec.type == 'D') {
        if (chmod(rec.path, 0000) != 0) {
            perror("chmod directory close");
            return -1;
        }

        printf("디렉토리를 다시 잠금 처리했습니다: %s\n", rec.path);
    } else {
        fprintf(stderr, "잘못된 record type입니다.\n");
        return -1;
    }

    strncpy(rec.state, "LOCKED", sizeof(rec.state) - 1);
    rec.state[sizeof(rec.state) - 1] = '\0';

    strncpy(rec.copy_path, COPY_NONE, sizeof(rec.copy_path) - 1);
    rec.copy_path[sizeof(rec.copy_path) - 1] = '\0';

    if (update_record(&rec) != 0) {
        return -1;
    }

    return 0;
}

int auth_close_all_open_files(void) {
    char buffer[MAX_DB_SIZE];

    if (read_db(buffer, sizeof(buffer)) < 0) {
        return -1;
    }

    char *saveptr;
    char *line = strtok_r(buffer, "\n", &saveptr);

    while (line != NULL) {
        AuthRecord rec;

        if (parse_record_line(line, &rec) == 0 &&
            strcmp(rec.state, "OPEN") == 0) {

            if (rec.type == 'F') {
                if (strcmp(rec.copy_path, COPY_NONE) != 0 &&
                    copy_file_content(
                        rec.copy_path,
                        rec.path,
                        rec.original_mode,
                        rec.owner_uid,
                        rec.owner_gid
                    ) == 0) {
                    unlink(rec.copy_path);
                    chmod(rec.path, 0000);
                }
            } else if (rec.type == 'D') {
                chmod(rec.path, 0000);
            }

            strncpy(rec.state, "LOCKED", sizeof(rec.state) - 1);
            rec.state[sizeof(rec.state) - 1] = '\0';

            strncpy(rec.copy_path, COPY_NONE, sizeof(rec.copy_path) - 1);
            rec.copy_path[sizeof(rec.copy_path) - 1] = '\0';

            update_record(&rec);
            printf("자동 close 완료: %s\n", rec.path);
        }

        line = strtok_r(NULL, "\n", &saveptr);
    }

    return 0;
}

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

    if (rec.owner_uid != getuid()) {
        fprintf(stderr, "파일 소유주만 Factoreal 관리 대상에서 제거할 수 있습니다.\n");
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