#include <stdio.h>
#include <time.h>
#include <unistd.h>     // getuid() 사용
#include <pwd.h>        // getpwuid() 사용
#include "logger.h"



void write_access_log(const char *filename, int result) {
    // 1. 현재 시간 정보 가져오기
    time_t now = time(NULL);
    struct tm *t = localtime(&now);

    // 2. 날짜별 로그 파일 경로 동적 생성 (1024 바이트)
    // 예: data/factoreal_2026-05-22.log
    char log_filepath[MAX_PATH_LEN];
    snprintf(log_filepath, sizeof(log_filepath), "data/factoreal_%04d-%02d-%02d.log",
             t->tm_year + 1900, t->tm_mon + 1, t->tm_mday);

    // 3. 동적으로 생성된 날짜별 파일 오픈
    FILE *fp = fopen(log_filepath, "a");
    if (fp == NULL) {
        perror("로그 파일 오픈 실패 (data/ 폴더를 확인하세요)");
        return;
    }

    // 4. 리눅스 시스템에서 로그인된 유저 이름 자동으로 가져오기
    uid_t uid = getuid();
    struct passwd *pw = getpwuid(uid);
    const char *username = (pw != NULL) ? pw->pw_name : "unknown";

    // 5. 패스워드 결과 메시지 설정 (PASSWORD_ERROR는 -1)
    const char *status_msg;
    if (result == PASSWORD_ERROR) {
        status_msg = "FAIL (PW ERROR)";
    } else {
        status_msg = "SUCCESS";
    }

    // 6. 로그 작성 시간 및 내용 출력
    fprintf(fp, "[%04d-%02d-%02d %02d:%02d:%02d] ",
            t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
            t->tm_hour, t->tm_min, t->tm_sec);
    
    fprintf(fp, "User: %-20s | File: %-30s | Result: %s\n",
            username, filename, status_msg);

    fclose(fp);
}/*패스워드 확인 로직에 이렇게 사용
  


#include "logger.h"

// ... 패스워드 확인 로직 ...

if (is_password_correct) {
    write_access_log("thackmedy", "secret.txt", 1); // 성공 기록
    // 파일 열기 로직
} else {
    write_access_log("thackmedy", "secret.txt", 0); // 실패 기록
    printf("비밀번호가 틀렸습니다.\n");
}



*/