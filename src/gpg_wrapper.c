#include <stdio.h>
#include <stdlib.h>
#include <locale.h>
#include <gpgme.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <termios.h>

#include "gpg_wrapper.h"

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
	printf("Enter file name :");
	fgets(fn, FN_MAX - 1,stdin);

	fn[strcspn(fn, "\n")] = '\0';
}

void get_password(char pwd[])
{
	char input_pwd1[PASSWORD_MAX] = {0}, input_pwd2[PASSWORD_MAX] = {0};

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

	strncpy(pwd,input_pwd1, PASSWORD_MAX);

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
int lock_file(char fn[], char pwd[], mode_t mode)
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

		if(chmod(output_path, mode) == 0)
		{
			printf("Original file permissions applied to %s.\n", output_path);
		}
		else
		{
			perror("Failed to apply permissions.");
		}


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


	// unlock file

	printf("unlocking file %s...\n", input_path);

	err = gpgme_op_decrypt(ctx, in_data, out_data);

	if (err)
	{
		fprintf(stderr, "\nfailed to unlock file %s : %s\n", input_path, gpgme_strerror(err));
	}
	else
	{
		printf("\nfile %s unlocked successfully!\noutput file : %s\n", input_path, output_path);


		if(chmod(output_path, mode) == 0)
		{
			printf("Original file permissions applied to %s.\n", output_path);
		}
		else
		{
			perror("Failed to apply permissions.");
		}

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


int lock_directory(char fn[], char pwd[], mode_t mode)
{
	char tar_name[FN_MAX];
	char command[FN_MAX * 2];

	snprintf(tar_name, sizeof(tar_name), "%s.tar", fn);

	printf("converting directory %s to %s ...\n",fn, tar_name);
	snprintf(command, sizeof(command), "tar -cf %s %s", tar_name, fn);

	if(system(command) != 0)
	{
		fprintf(stderr, "[ERROR] failed to converting tar.\n");
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
	            perror("failed to remove file %s. please remove file self.\n");
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

		printf("converting %s to %s ...\n", fn, output_path);
		snprintf(command, sizeof(command), "tar -xf %s", output_path);

		if(system(command) == 0)
		{
			remove(output_path);
			printf("unlocking completed\n");
		}
		else
		{
			fprintf(stderr, "[Error] failed to unlocking tar files.");
		}
	}

	return unlock_res;
}

int open_file(char fn[], char pwd[])
{
	mode_t original_mode;
	check_stat(fn, &original_mode);

	if (is_str_end(fn, ".tar.gpg") != 0)
	{
		return unlock_file(fn, pwd, original_mode);
	}
	else
	{
		return unlock_directory(fn, pwd, original_mode);
	}
	
}

int close_file(char fn[], char pwd[])
{
	mode_t original_mode;
	int stat_check = check_stat(fn, &original_mode);

	if(stat_check == NO_PERMISSION)
	{
		printf("[ERROR] File %s does not exist or cannot be accessed.\n", fn);
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
		printf("[ERROR] File '%s' does not exist or cannot be accessed.\n", fn);
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

	if(is_str_end(fn, ".gpg") != 0)
	{
		printf("file %s is not locked file.\n", fn);
		return FILE_OPEN_ERROR;
	
	}
		

	int stat_check = check_stat(fn, &original_mode);
	if (stat_check == NO_PERMISSION)
	{
		printf("[ERROR] File '%s' does not exist or cannot be accessed.\n", fn);
		return FILE_OPEN_ERROR;
	}


	if (pwd == NULL)
	{
		get_password(input_pwd);
		pwd = input_pwd;
	}


	if(is_str_end(fn, ".tar.gpg") != 0)
	{
		unlock_file(fn, pwd, original_mode);
	}
	else
	{
		unlock_directory(fn, pwd, original_mode);
	}


	return 0;
}


void show_current_gpg(MemoryFile current_file[])
{
	int cnt = 0;

	printf("========== current opened file ==========\n");

	for (int i=0; i<MAX_FILE_GPG; i++)
	{
		if( current_file[i].is_opened == OPENED)
		{
			printf("%2d : %s\n",++cnt,current_file[i].fn);
		}
	}
}


int main()
{
	
	char command[FN_MAX * 3];
	char filename[FN_MAX];
	char password[PASSWORD_MAX];

	MemoryFile current_file[MAX_FILE_GPG] = {0};
	int gpg_count = 0;

	printf("====================factoreal=======================\n");

	while (1) {
        printf("\nenter command >> ");
        if (fgets(command, sizeof(command), stdin) == NULL) break;
        command[strcspn(command, "\n")] = '\0';

        // 1. exit (종료)
        if (strcmp(command, "exit") == 0) {
            if (gpg_count != 0) {

            	for (int i=0; i<MAX_FILE_GPG; i++)
            	{
            		if (current_file[i].is_opened == OPENED)
            		{
            			close_file(current_file[i].fn, current_file[i].pwd);
            		}
            	}
                
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

            gpg_lock(filename, password);
        }

        // 3. open (메모리로 로드)
        else if (strcmp(command, "open") == 0) {
        	if (gpg_count == MAX_FILE_GPG)
        	{
        		printf("No space to open file. Current : %2d\n",gpg_count);
        		continue;
        	}
        	else
        	{
        		int i;
        		for (i=0; i<MAX_FILE_GPG; i++)
            	{
            		if(current_file[i].is_opened == NOT_OPENED)
            		{
            			break;
            		}
            	}

            	printf("open file: ");
            	fgets(current_file[i].fn,FN_MAX,stdin);
            	current_file[i].fn[strcspn(current_file[i].fn, "\n")] = '\0';


            	printf("password : ");
	            fgets(current_file[i].pwd, PASSWORD_MAX, stdin);
	            current_file[i].pwd[strcspn(current_file[i].pwd, "\n")] = '\0';

	            gpg_unlock(current_file[i].fn, current_file[i].pwd);

	            gpg_count++;
	            current_file[i].is_opened = OPENED;

	            if (is_str_end(current_file[i].fn, ".tar.gpg") != 0)
	            {
	            	char *ext = strstr(current_file[i].fn, ".gpg");
		            if (ext != NULL && *(ext + 4) == '\0')
		            	*ext = '\0';
	            }
	            else
	            {
	            	char *ext = strstr(current_file[i].fn, ".tar.gpg");
		            if (ext != NULL && *(ext + 8) == '\0')
		            	*ext = '\0';
	            }
	            
        	}
            

        }

        // 4. unlock (파일 복원)
        else if (strcmp(command, "unlock") == 0) {
            printf("filename: ");
            fgets(filename, FN_MAX, stdin);
            filename[strcspn(filename, "\n")] = '\0';

            printf("password: ");
            fgets(password, PASSWORD_MAX, stdin);
            password[strcspn(password, "\n")] = '\0';

            gpg_unlock(filename, password);
        }

        // 5. close (메모리 해제)
        else if (strcmp(command, "close") == 0) {
        	if (gpg_count == 0)
        	{
        		printf("No opened file. Current : %2d\n",gpg_count);
        		continue;
        	}
        	else
        	{
        		int i;

        		printf("close file : ");
            	fgets(filename,FN_MAX,stdin);
            	filename[strcspn(filename, "\n")] = '\0';

        		for (i=0; i<MAX_FILE_GPG; i++)
            	{
            		if((current_file[i].is_opened == OPENED) && (strcmp(filename, current_file[i].fn) == 0))
            		{
            			break;
            		}
            	}

	            close_file(current_file[i].fn, current_file[i].pwd);

	            gpg_count--;
	            current_file[i].is_opened = NOT_OPENED;
        	}
        }
        else if (strcmp(command, "list") == 0) {
            show_current_gpg(current_file);
        }

        else {
            printf("unknown comamnds. (lock, open, unlock, close, exit)\n");
        }
    }

	return 0;
}