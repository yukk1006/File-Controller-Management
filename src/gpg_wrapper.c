#include <stdio.h>
#include <stdlib.h>
#include <locale.h>
#include <gpgme.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <termios.h>

#include "gpg_wrapper.h"
#include "auth.h"

#define NOT_OPENED 0
#define OPENED 1


#define NO_PERMISSION -1
#define IS_DIRECTORY 1


void gpg_init()
{
	setlocale(LC_ALL, "");

	gpgme_check_version(NULL);
	gpgme_set_locale(NULL, LC_CTYPE, setlocale(LC_CTYPE, NULL));

#ifdef LC_MESSAGES
	gpgme_set_locale(NULL, LC_MESSAGES, setlocale(LC_MESSAGES, NULL));
#endif

}

int check_stat(const char *path, mode_t *out_mode)
{
	struct stat st;

	if (stat(path, &st) != 0)
	{
		return NO_PERMISSION;
	}

	if(out_mode != NULL)
	{
		*out_mode = st.st_mode & 0777;
	}

	if (S_ISDIR(st.st_mode))
	{
		return 1;
	}

	return 0;
}

int is_str_end(const char * fn, const char *compair)
{
	size_t len_fn = strlen(fn);
	size_t len_cmp = strlen(compair);
	if(len_fn > len_cmp)
	{
		if (strcmp(fn + len_fn - len_cmp, compair) == 0)
		{
			return 1;
		}
	}
	return 0;
}

void get_fn(char fn[])
{
	printf("파일 이름(경로) :");
	fgets(fn, FN_MAX - 1,stdin);

	fn[strcspn(fn, "\n")] = '\0';
}

void get_password(char pwd[])
{
	char input_pwd1[PASSWORD_MAX] = {0}, input_pwd2[PASSWORD_MAX] = {0};

pwd:
	printf("패스워드 입력\t:");
	fgets(input_pwd1, PASSWORD_MAX - 1,stdin);
	input_pwd1[strcspn(input_pwd1, "\n")] = '\0';

	printf("패스워드 확인\t:");

	fgets(input_pwd2, PASSWORD_MAX - 1,stdin);
	input_pwd2[strcspn(input_pwd2, "\n")] = '\0';

	if(strcmp(input_pwd1, input_pwd2) != 0)
	{
		printf("패스워드가 일치하지 않습니다\n\n");

		goto pwd;
	}

	strncpy(pwd,input_pwd1, PASSWORD_MAX);

}

// password callback
gpgme_error_t password_cb(void *hook, const char *uid_hint, const char *passphrase_info, int prev_was_bad, int fd)
{
	const char * password = (const char* ) hook;


	if (prev_was_bad)
	{
		fprintf(stderr, "\n[ERROR] 패스워드가 일치하지 않습니다\n");
		return GPG_ERR_CANCELED;
	}


	write(fd, password, strlen(password));
	write(fd, "\n", 1);

	return 0;
}



// lock file fn
int lock_file(char fn[], char pwd[], mode_t mode)
{
	gpgme_ctx_t ctx;
	gpgme_error_t err;
	gpgme_data_t in_data, out_data;

	FILE* in_file, *out_file;

	const char *input_path = fn;

	char output_path[FN_MAX];

    if (strcmp(fn, PASS_DB) == 0)
    {
        printf("잠글 수 없는 파일입니다\n");
        return -1;
    }

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
		perror("대상 파일이 존재하지 않거나 접근할 수 없습니다\n");
		gpgme_release(ctx);
		return FILE_OPEN_ERROR;
	}

	out_file = fopen(output_path, "wb");
	if(!out_file)
	{
		perror("파일 잠금에 실패했습니다\n");
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

	printf("파일 %s을(를) 잠그는 중입니다...\n", input_path);

	err = gpgme_op_encrypt(ctx, NULL, GPGME_ENCRYPT_SYMMETRIC, in_data, out_data);

	if (err)
	{
		fprintf(stderr, "\n파일 %s의 잠금에 실패했습니다 : %s\n", input_path, gpgme_strerror(err));
	}
	else
	{
		printf("\n파일 %s을(를) 성공적으로 잠그었습니다!\noutput file : %s\n", input_path, output_path);

		if(chmod(output_path, mode) == 0)
		{
			
		}
		else
		{
			perror("기존 권한 부여에 실패했습니다");
		}


		if (remove(input_path) == 0) {
            
        } else {
            perror("기존 파일 삭제에 실패했습니다\n");
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

int unlock_file(char fn[], char pwd[], mode_t mode)
{
	gpgme_ctx_t ctx;
	gpgme_error_t err;
	gpgme_data_t in_data, out_data;

	FILE* in_file, *out_file;

	const char *input_path = fn;
	char output_path[FN_MAX] = {0};

	strncpy(output_path, fn, FN_MAX);
	char *ext = strstr(output_path, ".gpg");
	if(ext != NULL && *(ext + 4) == '\0')
		*ext = '\0';
	

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
		perror("대상 파일이 존재하지 않거나 접근할 수 없습니다\n");
		gpgme_release(ctx);
		return FILE_OPEN_ERROR;
	}

	out_file = fopen(output_path, "wb");
	if(!out_file)
	{
		perror("잠금 해제 파일 생성에 실패했습니다\n");
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


	// unlock file

	err = gpgme_op_decrypt(ctx, in_data, out_data);

	if (err)
	{
		fprintf(stderr, "\n파일 잠금 해제에 실패했습니다 %s : %s\n", input_path, gpgme_strerror(err));
	}
	else
	{
		printf("\n파일 %s의 잠금을 해제했습니다!\noutput file : %s\n", input_path, output_path);


		if(chmod(output_path, mode) == 0)
		{
			
		}
		else
		{
			perror("권한 부여에 실패했습니다");
		}

		if (remove(input_path) == 0) {
            
        } else {
            perror("기존 파일 삭제에 실패했습니다\n");
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


int lock_directory(char fn[], char pwd[], mode_t mode)
{
	char tar_name[FN_MAX];
	char command[FN_MAX * 2];

	snprintf(tar_name, sizeof(tar_name), "%s.tar", fn);

	printf("변환중 %s >>> %s ...\n",fn, tar_name);
	snprintf(command, sizeof(command), "tar -cf %s %s", tar_name, fn);

	if(system(command) != 0)
	{
		fprintf(stderr, "[ERROR] 디렉토리의 .tar 파일 변환에 실패했습니다\n");
		return FILE_OPEN_ERROR;
	}
	else
	{
		int lock_res = lock_file(tar_name, pwd, mode);
		if (lock_res == 0)
		{
			if (remove(fn) == 0)
			{

	        }
	        else
	        {
	            perror("기존 파일 삭제에 실패했습니다.\n");
	        }

		}

		return lock_res;
	}


	return 0;
}

int unlock_directory(char fn[], char pwd[], mode_t mode)
{
	int unlock_res = unlock_file(fn, pwd, mode);

	if(unlock_res == 0)
	{
		char output_path[FN_MAX] = {0};
		char command[FN_MAX * 2] = {0};

		strncpy(output_path, fn, FN_MAX);
		char *ext = strstr(output_path, ".gpg");
		if(ext != NULL && *(ext+4) == '\0')
			*ext = '\0';

		printf("변환중... %s >>> %s\n", fn, output_path);
		snprintf(command, sizeof(command), "tar -xf %s", output_path);

		if(system(command) == 0)
		{
			remove(output_path);
			printf("잠금이 해제되었습니다\n");
		}
		else
		{
			fprintf(stderr, "[Error] 잠금 해제에 실패했습니다");
		}
	}

	return unlock_res;
}

int open_file(char fn[], char pwd[])
{
	mode_t original_mode;
	check_stat(fn, &original_mode);

	if (is_str_end(fn, ".tar.gpg"))
	{
		return unlock_directory(fn, pwd, original_mode);
	}
	else
	{
		return unlock_file(fn, pwd, original_mode);
	}
	
}

int close_file(char fn[], char pwd[])
{
	mode_t original_mode;
	int stat_check = check_stat(fn, &original_mode);

	if(stat_check == NO_PERMISSION)
	{
		printf("[ERROR] 파일 '%s' 이(가) 존재하지 않거나 접근할 수 없습니다\n", fn);
		return FILE_OPEN_ERROR;
	}

	if(stat_check == IS_DIRECTORY)
	{
		return lock_directory(fn, pwd, original_mode);
	}
	else
	{
		return lock_file(fn, pwd, original_mode);
	}
}




int gpg_lock(char fn[], char pwd[])
{
	char input_fn[FN_MAX] = {0}, input_pwd[PASSWORD_MAX] = {0};
	mode_t original_mode = 0;

	if (fn == NULL)
	{
		get_fn(input_fn);
		fn = input_fn;
	}
	

	int stat_check = check_stat(fn, &original_mode);
	if (stat_check == NO_PERMISSION)
	{
		printf("[ERROR] 파일 '%s'이(가) 존재하지 않거나 접근할 수 없습니다\n", fn);
		return FILE_OPEN_ERROR;
	}


	if (pwd == NULL)
	{
		get_password(input_pwd);
		pwd = input_pwd;
	}
	

	

	if (stat_check == IS_DIRECTORY)
	{
		lock_directory(fn, pwd, original_mode);
	}
	else
	{
	
		lock_file(fn, pwd, original_mode);	
	}

	return 0;
}

int gpg_unlock(char fn[], char pwd[])
{

	char input_fn[FN_MAX] = {0}, input_pwd[PASSWORD_MAX] = {0};
	mode_t original_mode = 0;
	
	if (fn == NULL)
	{
		get_fn(input_fn);
		fn = input_fn;
	}

	if(is_str_end(fn, ".gpg") == 0)
	{
		printf(".gpg 형태의 파일이 아닙니다 (입력 파일 : %s)\n", fn);
		return FILE_OPEN_ERROR;
	
	}
		

	int stat_check = check_stat(fn, &original_mode);
	if (stat_check == NO_PERMISSION)
	{
		printf("[ERROR] 파일 '%s'이(가) 존재하지 않거나 접근할 수 없습니다\n", fn);
		return FILE_OPEN_ERROR;
	}


	if (pwd == NULL)
	{
		get_password(input_pwd);
		pwd = input_pwd;
	}


	if(is_str_end(fn, ".tar.gpg"))
	{
		unlock_directory(fn, pwd, original_mode);
	}
	else
	{
		unlock_file(fn, pwd, original_mode);
	}


	return 0;
}


void show_current_gpg(MemoryFile current_file[])
{
	int cnt = 0;

	printf("========== 열려있는 파일 ==========\n");

	for (int i=0; i<MAX_FILE_GPG; i++)
	{
		if( current_file[i].is_opened == OPENED)
		{
			printf("%2d : %s\n",++cnt,current_file[i].fn);
		}
	}
}
