#include <stdio.h>
#include <unistd.h>


int main(int argc, char * argv[])
{
	char a[] = "texto de prueba";
	printf("%s\n", a);
	sleep(5);
	printf("%s\n", a);
	return 0;
}
