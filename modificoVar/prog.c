#include <stdio.h>
#include <unistd.h>

void f(int* c)
{
	*c = 1024;
	return;
}

int main(int argc, char * argv[])
{
	int a = 1;
	printf("f está en %p\n", f);
	sleep(5);
	f(&a);
	printf("hola %x\n", a);
	return 0;
}
