#ifndef LOGGER_H
#define LOGGER_H

// 팀 공통 약속: 패스워드 에러는 -1, 성공은 1
#define PASSWORD_ERROR -1
#define SUCCESS 1

// 팀 공통 약속: 모든 파일명, 디렉토리명, 패스워드 길이는 1024로 통일
#define MAX_PATH_LEN 1024
#define MAX_PW_LEN   1024
#define MAX_USER_LEN 1024

/*
 * 로그를 기록하는 함수
 * user: 사용자 이름 (최대 1024)
 * filename: 접근하려는 파일명 (최대 1024)
 * result: SUCCESS(1) 또는 PASSWORD_ERROR(-1)
 */
void write_access_log(const char *user, const char *filename, int result);

#endif
