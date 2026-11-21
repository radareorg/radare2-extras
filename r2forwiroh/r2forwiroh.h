#ifndef R2FORWIROH_H
#define R2FORWIROH_H
#include <stdbool.h>
#include <stddef.h>
typedef struct Handle R2FwHandle;
R2FwHandle *r2fw_new(const char *path, bool local_only);
char *r2fw_call(R2FwHandle *handle, const char *json);
char *r2fw_command(R2FwHandle *handle, const char *const *args, size_t argc);
void r2fw_string_free(char *text);
void r2fw_free(R2FwHandle *handle);
#endif
