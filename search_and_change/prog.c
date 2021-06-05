#include <stdio.h>
#include <unistd.h>
#include <stdint.h>

int global = 112233;

int main(int argc, char * argv[])
{
	char str[] = "test text";
	int64_t num = 12345;
	int count = 0;
	while(1)
	{
        printf("PID: %d\n", getpid());
		printf("count = %d\n", count++);
		printf("str = %s\n", str);
		printf("num = %ld\n", num);
		printf("global = %d\n\n", global);
		sleep(2);
	}
	return 0;
}
