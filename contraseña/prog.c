#include <stdio.h>
#include <stdlib.h>

void exito(void)
{
	printf("El usuario está autenticado!!\n");
	return;
}

int checkSuperComplejo(char* pass)
{
	//bla bla
	return 0;
}

int main(int argc, char * argv[])
{
	char passwd[100];
	printf("Ingrese la contraseña:"):
	scanf("%s", passwd);
	int auth = checkSuperComplejo(passwd);
	if(auth == 1)
	{
		exito();
	}
	else
	{
		printf("Mala suerte..."):
	}
	return 0;
}
