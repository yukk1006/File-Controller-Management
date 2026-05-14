#include <stdio.h>
#include <stdlib.h>
#include <locale.h>
#include <gpgme.h>
#include <string.h>
#include <unistd.h>

#define FN_MAX 1024
#define PASSWORD_MAX 1024
#define PASSWORD_ERROR -1

#define FILE_OPEN_ERROR -1

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

	printf("lockking file %s...\n", input_path);

	err = gpgme_op_encrypt(ctx, NULL, GPGME_ENCRYPT_SYMMETRIC, in_data, out_data);

	if (err)
	{
		fprintf(stderr, "\nfailed to lock file %s : %s\n", input_path, gpgme_strerror(err));
	}
	else
	{
		printf("\nfile %s locked successfully!\noutput file : %s\n", input_path, output_path);
	}


	gpgme_data_release(in_data);
	gpgme_data_release(out_data);


cleanup:
	fclose(in_file);
	fclose(out_file);
	gpgme_release(ctx);

	return 0;
}


int main()
{
	
	lock_file("secret.txt", "1234");

	return 0;
}