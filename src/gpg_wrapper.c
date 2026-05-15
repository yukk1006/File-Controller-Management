#include <stdio.h>
#include <stdlib.h>
#include <locale.h>
#include <gpgme.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <termios.h>

#include "gpg_wrapper.h"



void gpg_init()
{
	setlocale(LC_ALL, "");

	gpgme_check_version(NULL);
	gpgme_set_locale(NULL, LC_CTYPE, setlocale(LC_CTYPE, NULL));

#ifdef LC_MESSAGES
	gpgme_set_locale(NULL, LC_MESSAGES, setlocale(LC_MESSAGES, NULL));
#endif

}

// password callback
gpgme_error_t password_cb(void *hook, const char *uid_hint, const char *passphrase_info, int prev_was_bad, int fd)
{
	const char * password = (const char* ) hook;


	if (prev_was_bad)
	{
		fprintf(stderr, "\n[ERROR] Password is not same.\n");
		return GPG_ERR_CANCELED;
	}


	write(fd, password, strlen(password));
	write(fd, "\n", 1);

	return 0;
}


// lock file fn
int lock_file(char fn[], char pwd[])
{







	gpgme_ctx_t ctx;
	gpgme_error_t err;
	gpgme_data_t in_data, out_data;

	FILE* in_file, *out_file;

	const char *input_path = fn;

	char output_path[FN_MAX];
	snprintf(output_path, sizeof(output_path), "%s.gpg", input_path);

	gpg_init();


	err = gpgme_new(&ctx);

	if(err)
	{
		fprintf(stderr, "GPGME context error: %s\n", gpgme_strerror(err));
		return 1;
	}

	gpgme_set_protocol(ctx, GPGME_PROTOCOL_OpenPGP);

	gpgme_set_pinentry_mode(ctx, GPGME_PINENTRY_MODE_LOOPBACK);

	const char * password = pwd;

	gpgme_set_passphrase_cb(ctx, password_cb, (void *) password);


	// open file
	in_file = fopen(input_path, "rb");
	if (!in_file)
	{
		perror("there is no file to lock.\n");
		gpgme_release(ctx);
		return FILE_OPEN_ERROR;
	}

	out_file = fopen(output_path, "wb");
	if(!out_file)
	{
		perror("can't create locked file.\n");
		fclose(in_file);
		gpgme_release(ctx);
		return FILE_OPEN_ERROR;
	}


	// connect file to gpg
	err = gpgme_data_new_from_stream(&in_data, in_file);

	if(err)
	{
		fprintf(stderr, "cannot create in_data : %s\n", gpgme_strerror(err));
		goto cleanup;
	}

	err = gpgme_data_new_from_stream(&out_data, out_file);

	if(err)
	{
		fprintf(stderr, "cannot create out_data : %s\n", gpgme_strerror(err));
		gpgme_data_release(in_data);
		goto cleanup;
	}


	// lock file

	printf("locking file %s...\n", input_path);

	err = gpgme_op_encrypt(ctx, NULL, GPGME_ENCRYPT_SYMMETRIC, in_data, out_data);

	if (err)
	{
		fprintf(stderr, "\nfailed to lock file %s : %s\n", input_path, gpgme_strerror(err));
	}
	else
	{
		printf("\nfile %s locked successfully!\noutput file : %s\n", input_path, output_path);
		if (remove(input_path) == 0) {
            
        } else {
            perror("failed to remove file %s. please remove file self.\n");
        }
	}


	gpgme_data_release(in_data);
	gpgme_data_release(out_data);


cleanup:
	fclose(in_file);
	fclose(out_file);


	gpgme_release(ctx);

	return 0;
}

int open_file(char fn[], char pwd[], char **out_buffer, size_t *out_size)
{
	gpgme_ctx_t ctx;
	gpgme_error_t err;
	gpgme_data_t in_data, out_data;

	FILE* in_file;

	char input_path[FN_MAX];
	snprintf(input_path, sizeof(input_path), "%s.gpg", fn);

	gpg_init();


	err = gpgme_new(&ctx);

	if(err)
	{
		fprintf(stderr, "GPGME context error: %s\n", gpgme_strerror(err));
		return 1;
	}

	gpgme_set_protocol(ctx, GPGME_PROTOCOL_OpenPGP);

	gpgme_set_pinentry_mode(ctx, GPGME_PINENTRY_MODE_LOOPBACK);

	gpgme_set_passphrase_cb(ctx, password_cb, (void *) pwd);


	// open file
	in_file = fopen(input_path, "rb");
	if (!in_file)
	{
		fprintf(stderr, "there is no file name %s.\n", input_path);
		gpgme_release(ctx);
		return FILE_OPEN_ERROR;
	}


	// connect file to gpg
	err = gpgme_data_new_from_stream(&in_data, in_file);

	if(err)
	{
		fprintf(stderr, "cannot create in_data : %s\n", gpgme_strerror(err));
		goto cleanup;
	}

	err = gpgme_data_new(&out_data);

	if(err)
	{
		fprintf(stderr, "cannot create out_data : %s\n", gpgme_strerror(err));
		gpgme_data_release(in_data);
		goto cleanup;
	}


	// lock file

	err = gpgme_op_decrypt(ctx, in_data, out_data);

	if (err)
	{
		fprintf(stderr, "\nfailed to open file %s : %s\n", input_path, gpgme_strerror(err));
		*out_buffer = NULL;
		*out_size = 0;
	}
	else
	{
		off_t size = gpgme_data_seek(out_data, 0, SEEK_END);

		gpgme_data_seek(out_data, 0, SEEK_SET);

		*out_buffer = (char *)malloc(size + 1);

		gpgme_data_read(out_data, *out_buffer, size);
		(*out_buffer)[size] = '\0';
		*out_size = size;


		printf("file %s opened\n", input_path);
	}


	gpgme_data_release(in_data);
	gpgme_data_release(out_data);


cleanup:
	fclose(in_file);


	gpgme_release(ctx);

	return 0;
}

int close_file(char *buffer, size_t size)
{
	if (buffer != NULL)
	{
		memset(buffer, 0, size);

		free(buffer);
		printf("file closed\n");
	}

	return 0;
}

int unlock_file(char fn[], char pwd[])
{
	gpgme_ctx_t ctx;
	gpgme_error_t err;
	gpgme_data_t in_data, out_data;

	FILE* in_file, *out_file;

	char input_path[FN_MAX];
	snprintf(input_path, sizeof(input_path), "%s.gpg", fn);
	const char *output_path = fn;
	

	gpg_init();


	err = gpgme_new(&ctx);

	if(err)
	{
		fprintf(stderr, "GPGME context error: %s\n", gpgme_strerror(err));
		return 1;
	}

	gpgme_set_protocol(ctx, GPGME_PROTOCOL_OpenPGP);

	gpgme_set_pinentry_mode(ctx, GPGME_PINENTRY_MODE_LOOPBACK);

	gpgme_set_passphrase_cb(ctx, password_cb, (void *) pwd);


	// open file
	in_file = fopen(input_path, "rb");
	if (!in_file)
	{
		perror("there is no file locked.\n");
		gpgme_release(ctx);
		return FILE_OPEN_ERROR;
	}

	out_file = fopen(output_path, "wb");
	if(!out_file)
	{
		perror("can't create unlocked file.\n");
		fclose(in_file);
		gpgme_release(ctx);
		return FILE_OPEN_ERROR;
	}


	// connect file to gpg
	err = gpgme_data_new_from_stream(&in_data, in_file);

	if(err)
	{
		fprintf(stderr, "cannot create in_data : %s\n", gpgme_strerror(err));
		goto cleanup;
	}

	err = gpgme_data_new_from_stream(&out_data, out_file);

	if(err)
	{
		fprintf(stderr, "cannot create out_data : %s\n", gpgme_strerror(err));
		gpgme_data_release(in_data);
		goto cleanup;
	}


	// lock file

	printf("unlocking file %s...\n", input_path);

	err = gpgme_op_decrypt(ctx, in_data, out_data);

	if (err)
	{
		fprintf(stderr, "\nfailed to unlock file %s : %s\n", input_path, gpgme_strerror(err));
	}
	else
	{
		printf("\nfile %s unlocked successfully!\noutput file : %s\n", input_path, output_path);
		if (remove(input_path) == 0) {
            
        } else {
            perror("failed to remove file %s. please remove file self.\n");
        }
	}


	gpgme_data_release(in_data);
	gpgme_data_release(out_data);


cleanup:
	fclose(in_file);
	fclose(out_file);


	gpgme_release(ctx);

	return 0;
}



int gpg_lock(char fn[], char pwd[])
{
	char input_fn[FN_MAX] = {0}, input_pwd1[PASSWORD_MAX] = {0}, input_pwd2[PASSWORD_MAX] = {0};


	if (fn == NULL)
	{
		printf("Enter file name :");
		fgets(input_fn, FN_MAX - 1,stdin);

		input_fn[strcspn(input_fn, "\n")] = '\0';

		fn = input_fn;
	}

	if (pwd == NULL)
	{
pwd:
		printf("Enter password\t:");
		fgets(input_pwd1, PASSWORD_MAX - 1,stdin);
		input_pwd1[strcspn(input_pwd1, "\n")] = '\0';

		printf("Confirm password\t:");

		fgets(input_pwd2, PASSWORD_MAX - 1,stdin);
		input_pwd2[strcspn(input_pwd2, "\n")] = '\0';

		if(strcmp(input_pwd1, input_pwd2) != 0)
		{
			printf("password does not match. please try again\n\n");

			goto pwd;
		}

		pwd = input_pwd1;

	}

	lock_file(fn, pwd);


	return 0;
}


int main()
{
	
	char command[FN_MAX * 3];
	char filename[FN_MAX];
	char password[PASSWORD_MAX];

	MemoryFile current_file = {"", NULL, 0};

	printf("system\n");

	// char cmd[FN_MAX*3];

	while (1) {
        printf("\nenter command >> ");
        if (fgets(command, sizeof(command), stdin) == NULL) break;
        command[strcspn(command, "\n")] = '\0';

        // 1. exit (종료)
        if (strcmp(command, "exit") == 0) {
            if (current_file.buffer != NULL) {
                close_file(current_file.buffer, current_file.size);
            }
            printf("exit program.\n");
            break;
        }

        // 2. lock (파일 잠금)
        else if (strcmp(command, "lock") == 0) {
            printf("file name: ");
            fgets(filename, FN_MAX, stdin);
            filename[strcspn(filename, "\n")] = '\0';

            printf("password: ");
            fgets(password, PASSWORD_MAX, stdin);
            password[strcspn(password, "\n")] = '\0';

            lock_file(filename, password);
            memset(password, 0, PASSWORD_MAX); // 보안 파기
        }

        // 3. open (메모리로 로드)
        else if (strcmp(command, "open") == 0) {
            // 구조체의 buffer가 NULL이 아니면 이미 로드된 상태
            if (current_file.buffer != NULL) {
                printf("이미 열려있는 파일(%s)이 있습니다. 먼저 close 하세요.\n", current_file.fn);
                continue;
            }

            printf("열 파일명(확장자 제외): ");
            fgets(filename, FN_MAX, stdin);
            filename[strcspn(filename, "\n")] = '\0';

            printf("비밀번호 입력: ");
            fgets(password, PASSWORD_MAX, stdin);
            password[strcspn(password, "\n")] = '\0';

            // 구조체 내부 변수들의 주소값을 전달하여 데이터 채우기
            if (open_file(filename, password, &current_file.buffer, &current_file.size) == GPG_SUCCESS) {
                strncpy(current_file.fn, filename, FN_MAX); // 파일명 저장
                printf("--- [%s] 내용 ---\n%s\n----------------\n", current_file.fn, current_file.buffer);
            }
            memset(password, 0, PASSWORD_MAX); // 보안 파기
        }

        // 4. unlock (파일 복원)
        else if (strcmp(command, "unlock") == 0) {
            printf("잠금 해제할 파일명(확장자 제외): ");
            fgets(filename, FN_MAX, stdin);
            filename[strcspn(filename, "\n")] = '\0';

            printf("비밀번호 입력: ");
            fgets(password, PASSWORD_MAX, stdin);
            password[strcspn(password, "\n")] = '\0';

            unlock_file(filename, password);
            memset(password, 0, PASSWORD_MAX); // 보안 파기
        }

        // 5. close (메모리 해제)
        else if (strcmp(command, "close") == 0) {
            if (current_file.buffer == NULL) {
                printf("현재 메모리에 열려있는 파일이 없습니다.\n");
            } else {
                // 안전하게 메모리 파기
                close_file(current_file.buffer, current_file.size);
                
                // 구조체 상태를 다시 초기화
                current_file.buffer = NULL;
                current_file.size = 0;
                memset(current_file.fn, 0, FN_MAX);
            }
        }

        else {
            printf("알 수 없는 명령어입니다. (lock, open, unlock, close, exit)\n");
        }
    }

	return 0;
}