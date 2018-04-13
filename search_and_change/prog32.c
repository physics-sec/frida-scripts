#include <stdio.h>
#include <unistd.h>
#include <stdint.h>

int global = 112233;

int main(int argc, char * argv[])
{
	int num = 12345;
	printf("num = %d\n", num);
	printf("global = %d\n\n", global);
	sleep(5);
	printf("num = %d\n", num);
	printf("global = %d\n", global);
	return 0;
}
