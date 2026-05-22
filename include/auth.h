#ifndef AUTH_H
#define AUTH_H

int auth_lock_file(const char *path, const char *password);
int auth_open_file(const char *path, const char *password);
int auth_close_file(const char *path, const char *password);
int auth_remove_lock(const char *path, const char *password);
int auth_is_locked(const char *path);
int auth_close_all_open_files(void);

#endif