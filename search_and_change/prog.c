#include <stdio.h>
#include <unistd.h>
#include <stdint.h>

int global = 112233;

int main(int argc, char * argv[])
{
	char str[] = "texto de prueba";
	int64_t num = 12345;
	while(1)
	{
		printf("str = %s\n", str);
		printf("num = %ld\n", num);
		printf("global = %d\n\n", global);
		sleep(1);
	}
	return 0;
}
