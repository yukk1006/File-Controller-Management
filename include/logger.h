#ifndef LOGGER_H
#define LOGGER_H

// 팀 공통 약속
#define PASSWORD_ERROR -1
#define SUCCESS 1

// 팀 공통 약속: 길이 규격 1024
#define MAX_PATH_LEN 1024
#define MAX_PW_LEN   1024
#define MAX_USER_LEN 1024

/*
 * 로그를 기록하는 함수
 * [변경] 매개변수에서 user가 제외되었습니다. 함수 내부에서 자동으로 유저명을 가져옵니다.
 * filename: 접근하려는 파일명 (최대 1024)
 * result: SUCCESS(1) 또는 PASSWORD_ERROR(-1)
 */
void write_access_log(const char *filename, int result);
