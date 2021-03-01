#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

int debug_printf(const char *format, ...) {
	char buf[BUFSIZ] = {'\0'};
	va_list ap;
	va_start(ap, format);
	int r = vsnprintf(buf, BUFSIZ, format, ap);
	va_end(ap);
	ocall_print_string(buf);
	return r;
}
