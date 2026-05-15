#ifndef GPG_WRAPPER_H
#define GPG_WRAPPER_H

#define PASSWORD_ERROR -1
#define FILE_OPEN_ERROR -1
#define FN_MAX 1024
#define PASSWORD_MAX 1024
#define MAX_FILE_GPG 20

#define GPG_SUCCESS 0

typedef struct
{
	char fn[FN_MAX];
	char *buffer;
	size_t size;
} MemoryFile;

int lock_file(char fn[], char pwd[]);

int unlock_file(char fn[], char pwd[]);

int open_file(char fn[], char pwd[], char **out_buffer, size_t *out_size);

int close_file(char *buffer, size_t size);

#endif