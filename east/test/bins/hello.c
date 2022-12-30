#include <stdio.h>

void fn_hello(void) {
	puts ("Hello World");
}

int fn_ifelse(int argc) {
	if (argc < 3) {
		puts ("one");
		return 1;
	}
	return 0;
}

int main(int argc) {
	fn_hello ();
	int res = fn_ifelse (argc);
	return res;
}
