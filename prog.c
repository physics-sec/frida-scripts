#include <stdio.h>
#include <unistd.h>


int main(int argc, char * argv[])
{
	int a = 123456879;
	printf("%d\n", a);
	sleep(5);
	printf("%d\n", a);
	return 0;
}
