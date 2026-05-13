#ifndef LOGGER_H
#define LOGGER_H

// 로그를 기록하는 함수
// user: 사용자 이름, filename: 접근 파일명, success: 성공 여부(1 또는 0)
void write_access_log(const char *user, const char *filename, int success);

#endif
