#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
//#include <windows.h>

int main(int argc, char * argv[])
{
	sleep(5);
	char * str = (char *) malloc(15);
	printf("%p\n", str);
	sleep(2);
	free(str);
	return 0;
}
