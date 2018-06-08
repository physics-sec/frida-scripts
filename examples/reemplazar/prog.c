#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
//#include <windows.h>

void f(int* c)
{
	*c = 5;
	return;
}

int main(int argc, char * argv[])
{
	printf("f esta en %p\n", f);
	sleep(3);
	int a = 0;
	f(&a);
	printf("a:%d\n", a);
	return 0;
}
