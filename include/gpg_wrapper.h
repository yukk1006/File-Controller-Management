#ifndef GPG_WRAPPER_H
#define GPG_WRAPPER_H

#define PASSWORD_ERROR -1

#define FILE_OPEN_ERROR -1

int lock_file(char fn[], char pwd[]);

int unlock_file(char fn[], char pwd[]);

int open_file(char fn[], char pwd[]);

#endif