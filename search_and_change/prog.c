#include <stdio.h>
#include <unistd.h>

int global = 112233;

int main(int argc, char * argv[])
{
	char str[] = "texto de prueba";
	int num = 12345;
	printf("name = %s\n",  argv[0]);
	printf("num = %d\n", num);
	printf("str = %s\n", str);
	printf("global = %d\n", global);
	if(argc > 1)
	{
		printf("param = %s\n", argv[1]);
	}
	sleep(5);
	printf("\nname = %s\n",  argv[0]);
	printf("num = %d\n", num);
	printf("str = %s\n", str);
	printf("global = %d\n", global);
	if(argc > 1)
	{
		printf("param = %s\n", argv[1]);
	}
	return 0;
}
