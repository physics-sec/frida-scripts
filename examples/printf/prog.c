#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <unistd.h>
//#include <windows.h>

void f(int rand)
{
	printf("\nnum:%d", rand);
	return;
}

int main(int argc, char * argv[])
{
	srand(time(NULL));
	while(1)
	{
		int r = rand() % 100;
		f(r);
		sleep(2);
	}
	return 0;
}
