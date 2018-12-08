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
#include <string.h>
#include <errno.h>

const char fName[] = "test.file";
const char string[] = "What I want to write";

void handler(int curPid)
{
	FILE *fp = NULL;
	struct stat fileStat;
  
	fprintf (stdout, "(%d) Start handler...\n", curPid);

  	// checks for file information, but file can change between now and the file opening
	if(stat(fName, &fileStat))
        return;

    if(fileStat.st_size > 2048)
    {
        fprintf(stderr, "(%d) File is larger than 2k\n", curPid);
      	return;
    }

	if ((fp = fopen(fName, "wb")) != NULL) /* FLAW */
	{
      	char output[BUFSIZ];
      	sprintf(output, "(%d) %s", curPid, string);
        if(fwrite(output, sizeof *output, strlen(output), fp) < strlen(output))
            fprintf (stderr, "(%d) Couldn't write all characters\n", curPid);
		fclose(fp);
	}
  	else 
    {
		fprintf(stderr, "(%d) Error opening file\n", curPid);
    }

	// send the message to the child which should be in fork
	fprintf (stdout, "(%d) Stop handler...\n",curPid);
}

int main(int argc, char *argv[])
{
	unsigned i;
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
