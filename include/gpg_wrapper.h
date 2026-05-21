#ifndef GPG_WRAPPER_H
#define GPG_WRAPPER_H


#include <sys/stat.h>

#define PASSWORD_ERROR -1
#define FILE_OPEN_ERROR -1
#define FN_MAX 1024
#define PASSWORD_MAX 1024
#define MAX_FILE_GPG 20

#define GPG_SUCCESS 0

typedef struct
{
	char fn[FN_MAX];
	char pwd[PASSWORD_MAX];
	int is_opened;
} MemoryFile;

// int lock_file(char fn[], char pwd[], mode_t mode);

// int unlock_file(char fn[], char pwd[], mode_t mode);

// int lock_directory(char fn[], char pwd[], mode_t mode);

// int unlock_directory(char fn[], char pwd[], mode_t mode);

int open_file(char fn[], char pwd[]);

int close_file(char fn[], char pwd[]);

void show_current_gpg(MemoryFile current_file[]);

int gpg_unlock(char fn[], char pwd[]);

int gpg_lock(char fn[], char pwd[]);

#endif