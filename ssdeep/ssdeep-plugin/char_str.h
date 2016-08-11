#ifndef CHAR_ARRAY_H_
#define CHAR_ARRAY_H_

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#define OUT_OF_MEMORY_ERR -1;
#define OVERFLOW_ERR -2;
#define SUCCESS 0;

#ifndef SIZE_T_MAX
#define SIZE_T_MAX UINT_MAX
#endif /* !SIZE_T_MAX */

typedef struct char_str {
	char *array;

	size_t length;
	size_t capacity;
} char_str;

static void char_str_init(char_str *str);
static void char_str_free(char_str *str);
static int char_str_append(char_str *str, const char *value);
static int char_str_append_len(char_str *str, const char *value, size_t len);

static void char_str_init(char_str *str)
{
	str->length = 0;
	str->capacity = 512; //just because

	str->array = (char *) calloc (str->capacity, sizeof(char));
}

static void char_str_free(char_str *str)
{
	free(str->array);
	str->array = NULL;

	str->length = 0;
	str->capacity = 0;
}

static int char_str_append(char_str *str, const char *value)
{
	int str_len = strlen(value);

	if (str->length + str_len + 1 > str->capacity) {
		int new_capacity = str->length + str_len + 1;

		if (new_capacity > str->capacity && new_capacity < SIZE_T_MAX / sizeof (char)) {
			char *new_array = (char *) realloc (str->array, new_capacity * sizeof(char));
			if (new_array != NULL) {
				str->array = new_array;
				str->capacity = new_capacity;
			} else {
				return OUT_OF_MEMORY_ERR;
			}
		} else {
			return OVERFLOW_ERR;
		}
	}

	strcpy (&str->array[str->length], value);
	str->length += str_len;
	str->array[str->length] = '\0';

	return SUCCESS;
}

static int char_str_append_len(char_str *str, const char *value, size_t len)
{
	if (str->length + len + 1 > str->capacity) {
		int new_capacity = str->length + len + 1;

		if (new_capacity > str->capacity && new_capacity < SIZE_T_MAX / sizeof(char)) {
			char *new_array = (char *) realloc (str->array, new_capacity * sizeof(char));
			if (new_array != NULL) {
				str->array = new_array;
				str->capacity = new_capacity;
			} else {
				return OUT_OF_MEMORY_ERR;
			}
		} else {
			return OVERFLOW_ERR;
		}
	}

	strncpy (&str->array[str->length], value, len);
	str->length += len;
	str->array[str->length] = '\0';

	return SUCCESS;
}

#endif /* CHAR_ARRAY_H_ */
