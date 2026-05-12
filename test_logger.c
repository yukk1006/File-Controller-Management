#include <stdio.h>
#include "logger.h"

int main() {
    printf("--- 로그 시스템 테스트 시작 ---\n");

    // 1. 성공 상황 테스트 (사용자: tester, 파일: data.txt, 성공: 1)
    printf("성공 로그를 기록 중...\n");
    write_access_log("tester01", "data.txt", 1);

    // 2. 실패 상황 테스트 (사용자: hacker, 파일: private.key, 실패: 0)
    printf("실패 로그를 기록 중...\n");
    write_access_log("hacker_top", "private.key", 0);

    // 3. 존재하지 않는 사용자 테스트
    printf("알 수 없는 사용자 로그 기록 중...\n");
    write_access_log("unknown", "config.ini", 0);

    printf("테스트 완료! 'access_log.txt' 파일을 확인해 보세요.\n");

    return 0;
}
