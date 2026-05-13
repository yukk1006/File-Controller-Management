#ifndef AUTH_H
#define AUTH_H

// 비밀번호 설정 및 초기 잠금
void set_password(const char *filename, const char *pw);

// 비밀번호 검증 및 권한 일시 해제
int verify_and_grant_access(const char *filename, const char *input_pw);

#endif