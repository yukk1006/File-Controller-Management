#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include "logger.h"

void write_access_log(const char *user, const char *filename, int success) {
    FILE *fp = fopen("access_log.txt", "a"); // "a" 모드는 파일 끝에 내용을 추가합니다.
    if (fp == NULL) {
        perror("로그 파일을 열 수 없습니다");
        return;
    }

    // 1. 현재 시간 가져오기
    time_t now = time(NULL);
    struct tm *t = localtime(&now);

    // 2. 로그 형식 작성
    // [YYYY-MM-DD HH:MM:SS] User: 이름 | File: 파일명 | Result: SUCCESS/FAIL
    fprintf(fp, "[%04d-%02d-%02d %02d:%02d:%02d] ",
            t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
            t->tm_hour, t->tm_min, t->tm_sec);
    
    fprintf(fp, "User: %-10s | File: %-20s | Result: %s\n",
            user, filename, success ? "SUCCESS" : "FAIL");

    fclose(fp);
}
/*패스워드 확인 로직에 이렇게 사용
  


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
