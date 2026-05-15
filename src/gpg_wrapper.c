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
	char input_fn[FN_MAX] = {0}, input_pwd[PASSWORD_MAX] = {0};


	if (fn == NULL)
	{
		printf("Enter file name :");
		fgets(input_fn, FN_MAX - 1,stdin);

		fn = input_fn;
	}

	if (pwd == NULL)
	{
pwd:
		printf("Enter password:");
		fgets(input_pwd, PASSWORD_MAX - 1,stdin);

		strncpy(pwd, input_pwd, PASSWORD_MAX);

		fgets(input_pwd, PASSWORD_MAX - 1,stdin);

		if(strcmp(pwd, input_pwd) != 0)
		{
			printf("password does not match. please try again\n");

			goto pwd;
		}

	}

	lock_file(fn, pwd);


	return 0;
}


int main()
{
	
	MemoryFile mem_files[MAX_FILE_GPG];

	while (1)
	{

	}

	return 0;
}