#include<stdio.h>
#include<stdlib.h>
#include<string.h>

#define QUERY_STRING_LEN 150

static char buffer[100];
static void (*function_pointer)();
static char decoded_string[QUERY_STRING_LEN];

void safe_function() {
	printf("%s\n", "This is the normal flow of execution");
}

void unsafe_function() {
	printf("%s\n", "This function should not be called");
}

void decode_query_string(char *query_string) {
	int j = 0, num;
	char num_str[3];
	num_str[2] = '\0';
	for (int i = 0; i < strlen(query_string) && i < QUERY_STRING_LEN;) {
		if (query_string[i] != '%') {
			decoded_string[j] = query_string[i];
			i++;
		} else {
			i++;
			strncpy(num_str, query_string + i, 2);
			num = atoi(num_str);
			num = (num / 10) * 16 + (num % 10);
			decoded_string[j] = (char)num;
			i += 2;
		}
		j++;
	}
}


int main() {
	function_pointer = &safe_function;
	printf("%s\n\n", "Content-type: text/html");
	decode_query_string(getenv("QUERY_STRING"));
	// UNSAGE: `buffer` length is unchecked in this copy
	// The query string can write beyond this buffer into the `function_pointer`
	// which can cause arbitrary functions to be executed.
	strcpy(buffer, decoded_string);
	//printf("%s\n", buffer);
	(void)(*function_pointer)();
	return 0;
}
