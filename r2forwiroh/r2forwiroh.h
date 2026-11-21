#ifndef R2FORWIROH_H
#define R2FORWIROH_H
#include <stdbool.h>
typedef struct Handle R2FwHandle;
R2FwHandle *r2fw_new(const char *path, bool local_only);
char *r2fw_call(R2FwHandle *handle, const char *json);
void r2fw_string_free(char *text);
void r2fw_free(R2FwHandle *handle);
#endif
