#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "auth.h"

// 비밀번호가 저장된 DB 파일 경로
#define PW_DB "data/.pass_db"

/**
 * 새로운 파일/디렉토리에 비밀번호를 설정하고 DB에 저장
 */
void set_password(const char *filename, const char *pw) {
    // 1. DB 파일 열기 (추가 모드)
    FILE *fp = fopen(PW_DB, "a");
    if (fp == NULL) {
        perror("[ERROR] DB 파일을 열 수 없습니다");
        return;
    }

    // 2. 파일명:비밀번호 형식으로 저장
    fprintf(fp, "%s:%s\n", filename, pw);
    fclose(fp);

    // 3. 설정 즉시 파일 권한을 000(접근 불가)으로 변경
    if (chmod(filename, 0) == -1) {
        perror("[WARNING] 초기 권한 설정 실패");
    }

    printf("[SUCCESS] '%s'의 비밀번호가 설정되었으며 접근이 차단되었습니다.\n", filename);
}

/**
 * 입력된 비밀번호를 DB와 대조하고 권한을 부여
 * 반환값: 성공 1, 실패 0
 */
int verify_and_grant_access(const char *filename, const char *input_pw) {
    FILE *fp = fopen(PW_DB, "r");
    if (fp == NULL) {
        printf("[ERROR] 등록된 비밀번호 데이터가 없습니다.\n");
        return 0;
    }

    char line[512];
    char db_file[256];
    char db_pw[256];
    int auth_ok = 0;

    // 1. DB에서 파일명 매칭 및 비밀번호 확인
    while (fgets(line, sizeof(line), fp)) {
        // 줄바꿈 제거 및 파싱
        if (sscanf(line, "%[^:]:%s", db_file, db_pw) == 2) {
            if (strcmp(filename, db_file) == 0) {
                if (strcmp(input_pw, db_pw) == 0) {
                    auth_ok = 1;
                }
                break; // 파일명을 찾았으면 더 이상 읽지 않음
            }
        }
    }
    fclose(fp);

    // 2. 인증 성공 시 권한 부여
    if (auth_ok) {
        struct stat st;
        if (stat(filename, &st) == -1) {
            perror("[ERROR] 파일 상태를 확인할 수 없습니다");
            return 0;
        }

        // 디렉토리면 0700(rwx------), 파일이면 0600(rw-------) 부여
        mode_t mode = S_ISDIR(st.st_mode) ? 0700 : 0600;
        
        if (chmod(filename, mode) == -1) {
            perror("[ERROR] 권한 부여 실패");
            return 0;
        }
        return 1;
    }

    return 0; // 인증 실패
}