/*PLOVER: NUM.OVERFLOW, BUFF.OVER*/

/*
Description: integer overflow results in a short malloc and an overflow.
Keywords: Size0 Complex0 BufferOverflow Heap AdHoc IntOverflow
ValidArg: "10"
ValidArg: "1073741823"
InvalidArg: "1073741824"
*/

#include <stdio.h>
#include <stdlib.h>

void
test(unsigned int n)
{
	int *buf, i;

	buf = malloc(n * sizeof *buf);		/* BAD */
	if(!buf)
		return;
	for(i = 0; i < n; i++)
		buf[i] = i;			/* BAD */
	while(i-- > 0)
		printf("%x ", buf[i]);		/* BAD */
	printf("\n");
	free(buf);
}

int
main(int argc, char **argv)
{
	int n;

	if(argc != 2)
		return 1;
	n = strtoul(argv[1], 0, 10);
	test(n);
	return 0;
}

