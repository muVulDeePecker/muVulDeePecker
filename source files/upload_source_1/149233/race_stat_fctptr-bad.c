/* This software was developed at the National Institute of Standards and
 * Technology by employees of the Federal Government in the course of their
 * official duties. Pursuant to title 17 Section 105 of the United States
 * Code this software is not subject to copyright protection and is in the
 * public domain. NIST assumes no responsibility whatsoever for its use by
 * other parties, and makes no guarantees, expressed or implied, about its
 * quality, reliability, or any other characteristic.

 * We would appreciate acknowledgement if the software is used.
 * The SAMATE project website is: http://samate.nist.gov
*/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

const char fName[] = "test.file";
const char string1[] = "What I want to write _ fct1";
const char string2[] = "What I want to write _ fct2";

typedef void (*fctPtr)(FILE*, int);
fctPtr myFunctions[2];

unsigned int getRand()
{
	unsigned int r;
	FILE *f;

	f = fopen("/dev/urandom", "rb");
	if(f == NULL)
	{
		fprintf(stderr, "Error opening file\n");
		exit(-1);
	}

	if(fread(&r, sizeof r, 1, f) != 1)
	{
		fprintf(stderr, "Error reading file\n");
		fclose(f);
		exit(-1);
	}

	if(fclose(f) != 0)
		fprintf(stderr, "Error closing file\n");

	return r;
}

void fct1(FILE *f, int curPid) {
	fprintf(stdout, "(%d) Call fct1\n", curPid);
	char output[BUFSIZ];
    sprintf(output, "(%d) %s", curPid, string1);
    if(fwrite(output, sizeof *output, strlen(output), f) < strlen(output))
		fprintf(stderr, "(%d) Couldn't write all characters\n", curPid);
}

void fct2(FILE *f, int curPid) {
	fprintf(stdout, "(%d) Call fct2\n", curPid);
  	char output[BUFSIZ];
    sprintf(output, "(%d) %s", curPid, string2);
    if(fwrite(output, sizeof *output, strlen(output), f) < strlen(output))
		fprintf(stderr, "(%d) Couldn't write all characters\n", curPid);
}

void handler(int curPid)
{
	struct stat fileStat;
  
	// checks for file information, but file can change between now and the file opening
    if(stat(fName, &fileStat))
        return;

    if(fileStat.st_size > 2048)
    {
        fprintf(stderr, "(%d) File is larger than 2k\n", curPid);
      	return;
    }

	FILE *f = fopen(fName, "wb"); /* FLAW */
	if (f != NULL)
	{
		unsigned int i = getRand() % 2;
		fprintf (stdout, "(%d) Start handler...\n", curPid);
		myFunctions[i](f, curPid);
		fclose(f);
		fprintf (stdout, "(%d) Stop handler...\n", curPid);
	}
  	else 
    {
		fprintf(stderr, "(%d) Error opening file\n", curPid);
    }
}

int main(int argc, char *argv[])
{
	unsigned i;

	myFunctions[0] = fct1;
	myFunctions[1] = fct2;
	
	pid_t pid = 0;
	// create fork 1
	if (fork())
		return 0;
	
	for (i=0;i<3;++i) {
		pid = fork();
		if (pid == 0)
		{
			pid = getpid();
			printf ("Run: %d\n",pid);
			handler(pid);
			break;
		}
	}
	return 0;
}
